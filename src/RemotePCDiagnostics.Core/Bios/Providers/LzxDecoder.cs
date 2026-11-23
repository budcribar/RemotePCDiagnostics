using System.Buffers.Binary;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Pure-C# Microsoft Cabinet (<c>MSCF</c>) LZX decompressor (<c>TYPE_LZX</c>, method 3, window sizes 15..21).
/// Decompresses CFDATA blocks sequentially within a single CAB folder with zero external process launches.
/// </summary>
internal sealed class LzxDecoder
{
    private const int MinWindowBits = 15;
    private const int MaxWindowBits = 21;
    private const int MaxBlockUncomp = 32768;
    private const int NumChars = 256;
    private const int NumSecondaryLengths = 249;
    private const int PreTreeNumElements = 20;
    private const int AlignedNumElements = 8;
    private const int MaxHuffmanBits = 16;

    private const int BlockTypeVerbatim = 1;
    private const int BlockTypeAligned = 2;
    private const int BlockTypeUncompressed = 3;

    private static readonly int[] ExtraBits = BuildExtraBits();
    private static readonly int[] PositionBase = BuildPositionBase();

    private readonly byte[] _window;
    private readonly int _windowSize;
    private readonly int _windowMask;
    private readonly int _mainTreeElements;

    private readonly byte[] _mainLengths;
    private readonly byte[] _lengthLengths;
    private readonly byte[] _alignedLengths = new byte[AlignedNumElements];

    private readonly HuffmanTable _mainTable;
    private readonly HuffmanTable _lengthTable;
    private readonly HuffmanTable _alignedTable;
    private readonly HuffmanTable _preTreeTable;

    private int _windowPos;
    private int _r0 = 1;
    private int _r1 = 1;
    private int _r2 = 1;

    private bool _headerRead;
    private int _intelFileSize;
    private int _intelCurPos;
    private int _framesRead;

    private int _blockType;
    private int _blockRemaining;
    private bool _uncompressedBlockOdd;

    private LzxDecoder(int windowBits)
    {
        _windowSize = 1 << windowBits;
        _windowMask = _windowSize - 1;
        _window = new byte[_windowSize];

        var numPositionSlots = windowBits switch
        {
            15 => 30,
            16 => 32,
            17 => 34,
            18 => 36,
            19 => 38,
            20 => 42,
            21 => 50,
            _ => throw new ArgumentOutOfRangeException(nameof(windowBits)),
        };

        _mainTreeElements = NumChars + (numPositionSlots * 8);
        _mainLengths = new byte[_mainTreeElements];
        _lengthLengths = new byte[NumSecondaryLengths];

        _mainTable = new HuffmanTable(_mainTreeElements);
        _lengthTable = new HuffmanTable(NumSecondaryLengths);
        _alignedTable = new HuffmanTable(AlignedNumElements);
        _preTreeTable = new HuffmanTable(PreTreeNumElements);
    }

    public static bool IsSupportedWindowBits(int windowBits) =>
        windowBits is >= MinWindowBits and <= MaxWindowBits;

    public static bool TryCreate(int windowBits, out LzxDecoder? decoder)
    {
        if (!IsSupportedWindowBits(windowBits))
        {
            decoder = null;
            return false;
        }

        decoder = new LzxDecoder(windowBits);
        return true;
    }

    /// <summary>
    /// Decompresses a single CFDATA block into <paramref name="output"/> (which must have length &gt;= <paramref name="expectedUncomp"/>).
    /// Returns <c>false</c> cleanly on any malformed or truncated LZX stream.
    /// </summary>
    public bool TryDecompressBlock(byte[] cabBytes, int offset, int length, int expectedUncomp, byte[] output)
    {
        if (expectedUncomp < 0 || expectedUncomp > MaxBlockUncomp || expectedUncomp > output.Length)
            return false;
        if (offset < 0 || length < 0 || offset + length > cabBytes.Length)
            return false;
        if (expectedUncomp == 0)
            return true;

        var bits = new BitReader(cabBytes, offset, length);

        if (!_headerRead)
        {
            if (!bits.TryReadBits(1, out var intelFlag))
                return false;

            if (intelFlag != 0)
            {
                if (!bits.TryReadBits(16, out var hi) || !bits.TryReadBits(16, out var lo))
                    return false;
                _intelFileSize = (int)((hi << 16) | lo);
            }
            else
            {
                _intelFileSize = 0;
            }

            _headerRead = true;
        }

        var outPos = 0;
        var toGo = expectedUncomp;

        while (toGo > 0)
        {
            if (_blockRemaining == 0)
            {
                if (!bits.TryReadBits(3, out var type))
                    return false;
                _blockType = (int)type;

                if (!bits.TryReadBits(16, out var lenHi) || !bits.TryReadBits(8, out var lenLo))
                    return false;
                _blockRemaining = (int)((lenHi << 8) | lenLo);

                if (_blockRemaining <= 0)
                    return false;

                switch (_blockType)
                {
                    case BlockTypeAligned:
                        for (var i = 0; i < AlignedNumElements; i++)
                        {
                            if (!bits.TryReadBits(3, out var len))
                                return false;
                            _alignedLengths[i] = (byte)len;
                        }

                        if (!_alignedTable.Build(_alignedLengths))
                            return false;

                        if (!ReadLengths(ref bits, _mainLengths, 0, NumChars)
                            || !ReadLengths(ref bits, _mainLengths, NumChars, _mainTreeElements)
                            || !_mainTable.Build(_mainLengths)
                            || !ReadLengths(ref bits, _lengthLengths, 0, NumSecondaryLengths)
                            || !_lengthTable.Build(_lengthLengths))
                        {
                            return false;
                        }
                        break;

                    case BlockTypeVerbatim:
                        if (!ReadLengths(ref bits, _mainLengths, 0, NumChars)
                            || !ReadLengths(ref bits, _mainLengths, NumChars, _mainTreeElements)
                            || !_mainTable.Build(_mainLengths)
                            || !ReadLengths(ref bits, _lengthLengths, 0, NumSecondaryLengths)
                            || !_lengthTable.Build(_lengthLengths))
                        {
                            return false;
                        }
                        break;

                    case BlockTypeUncompressed:
                        _uncompressedBlockOdd = (_blockRemaining & 1) != 0;
                        bits.AlignTo16ForUncompressed();
                        if (!bits.TryReadRawInt32LE(out _r0)
                            || !bits.TryReadRawInt32LE(out _r1)
                            || !bits.TryReadRawInt32LE(out _r2))
                        {
                            return false;
                        }
                        break;

                    default:
                        return false;
                }
            }

            var thisRun = Math.Min(_blockRemaining, toGo);

            switch (_blockType)
            {
                case BlockTypeVerbatim:
                case BlockTypeAligned:
                    if (!DecodeCompressedRun(ref bits, _blockType == BlockTypeAligned, thisRun, output, ref outPos))
                        return false;
                    toGo -= thisRun;
                    _blockRemaining -= thisRun;
                    break;

                case BlockTypeUncompressed:
                    for (var i = 0; i < thisRun; i++)
                    {
                        if (!bits.TryReadRawByte(out var b))
                            return false;
                        _window[_windowPos] = b;
                        _windowPos = (_windowPos + 1) & _windowMask;
                        output[outPos++] = b;
                    }

                    toGo -= thisRun;
                    _blockRemaining -= thisRun;

                    if (_blockRemaining == 0 && _uncompressedBlockOdd)
                    {
                        // Pad byte after odd-length uncompressed block.
                        bits.SkipRawByteIfAvailable();
                    }
                    break;

                default:
                    return false;
            }
        }

        if (_intelFileSize != 0 && _framesRead < 32768 && expectedUncomp > 10 && _intelCurPos < 0x40000000)
        {
            ApplyIntelE8Reverse(output, expectedUncomp, _intelCurPos, _intelFileSize);
        }

        _intelCurPos += expectedUncomp;
        _framesRead++;
        return true;
    }

    private bool DecodeCompressedRun(ref BitReader bits, bool aligned, int runLength, byte[] output, ref int outPos)
    {
        var remaining = runLength;
        while (remaining > 0)
        {
            if (!_mainTable.TryDecode(ref bits, out var mainSymbol))
                return false;

            if (mainSymbol < NumChars)
            {
                var b = (byte)mainSymbol;
                _window[_windowPos] = b;
                _windowPos = (_windowPos + 1) & _windowMask;
                output[outPos++] = b;
                remaining--;
                continue;
            }

            var s = mainSymbol - NumChars;
            var matchLength = s & 7;
            var positionSlot = s >> 3;

            if (matchLength == 7)
            {
                if (!_lengthTable.TryDecode(ref bits, out var extraLen))
                    return false;
                matchLength += extraLen;
            }

            matchLength += 2;
            if (matchLength > remaining)
                return false;

            int matchOffset;
            if (positionSlot == 0)
            {
                matchOffset = _r0;
            }
            else if (positionSlot == 1)
            {
                matchOffset = _r1;
                _r1 = _r0;
                _r0 = matchOffset;
            }
            else if (positionSlot == 2)
            {
                matchOffset = _r2;
                _r2 = _r0;
                _r0 = matchOffset;
            }
            else
            {
                if (positionSlot >= ExtraBits.Length)
                    return false;

                var extra = ExtraBits[positionSlot];
                int formattedOffset;
                if (aligned && extra >= 3)
                {
                    if (!bits.TryReadBits(extra - 3, out var verbatim))
                        return false;
                    if (!_alignedTable.TryDecode(ref bits, out var alignedBits))
                        return false;
                    formattedOffset = PositionBase[positionSlot] + ((int)verbatim << 3) + alignedBits;
                }
                else
                {
                    uint verbatim = 0;
                    if (extra > 0 && !bits.TryReadBits(extra, out verbatim))
                        return false;
                    formattedOffset = PositionBase[positionSlot] + (int)verbatim;
                }

                matchOffset = formattedOffset - 2;
                _r2 = _r1;
                _r1 = _r0;
                _r0 = matchOffset;
            }

            if (matchOffset <= 0 || matchOffset > _windowSize)
                return false;

            var srcPos = (_windowPos - matchOffset) & _windowMask;
            for (var i = 0; i < matchLength; i++)
            {
                var b = _window[srcPos];
                srcPos = (srcPos + 1) & _windowMask;
                _window[_windowPos] = b;
                _windowPos = (_windowPos + 1) & _windowMask;
                output[outPos++] = b;
            }

            remaining -= matchLength;
        }

        return true;
    }

    private bool ReadLengths(ref BitReader bits, byte[] lengths, int first, int last)
    {
        Span<byte> preLengths = stackalloc byte[PreTreeNumElements];
        for (var i = 0; i < PreTreeNumElements; i++)
        {
            if (!bits.TryReadBits(4, out var len))
                return false;
            preLengths[i] = (byte)len;
        }

        if (!_preTreeTable.Build(preLengths))
            return false;

        var idx = first;
        while (idx < last)
        {
            if (!_preTreeTable.TryDecode(ref bits, out var sym))
                return false;

            if (sym == 17)
            {
                if (!bits.TryReadBits(4, out var extra))
                    return false;
                var zeros = (int)extra + 4;
                if (idx + zeros > last)
                    return false;
                Array.Clear(lengths, idx, zeros);
                idx += zeros;
            }
            else if (sym == 18)
            {
                if (!bits.TryReadBits(5, out var extra))
                    return false;
                var zeros = (int)extra + 20;
                if (idx + zeros > last)
                    return false;
                Array.Clear(lengths, idx, zeros);
                idx += zeros;
            }
            else if (sym == 19)
            {
                if (!bits.TryReadBits(1, out var extra))
                    return false;
                var count = (int)extra + 4;
                if (!_preTreeTable.TryDecode(ref bits, out var sym2) || sym2 > 16)
                    return false;
                var val = (byte)((lengths[idx] - sym2 + 17) % 17);
                if (idx + count > last)
                    return false;
                for (var k = 0; k < count; k++)
                    lengths[idx++] = val;
            }
            else if (sym <= 16)
            {
                lengths[idx] = (byte)((lengths[idx] - sym + 17) % 17);
                idx++;
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    private static void ApplyIntelE8Reverse(byte[] data, int length, int curPosBase, int fileSize)
    {
        var limit = length - 10;
        for (var i = 0; i <= limit; i++)
        {
            if (data[i] != 0xE8)
                continue;

            var curPos = curPosBase + i;
            var absOff = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(i + 1, 4));
            if (absOff >= -curPos && absOff < fileSize)
            {
                var relOff = absOff >= 0 ? absOff - curPos : absOff + fileSize;
                BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(i + 1, 4), relOff);
            }

            i += 4;
        }
    }

    private static int[] BuildExtraBits()
    {
        var arr = new int[51];
        for (var i = 0; i < arr.Length; i++)
        {
            arr[i] = i < 4 ? 0 : i < 36 ? (i / 2) - 1 : 17;
        }

        return arr;
    }

    private static int[] BuildPositionBase()
    {
        var extra = BuildExtraBits();
        var arr = new int[51];
        var baseVal = 0;
        for (var i = 0; i < arr.Length; i++)
        {
            arr[i] = baseVal;
            baseVal += 1 << extra[i];
        }

        return arr;
    }

    /// <summary>
    /// MSB-first bit reader fed by 16-bit little-endian words per the MS-CAB LZX bitstream specification.
    /// </summary>
    private ref struct BitReader
    {
        private readonly byte[] _data;
        private int _pos;
        private readonly int _end;
        private ulong _bitBuf;
        private int _bitsLeft;

        public BitReader(byte[] data, int offset, int length)
        {
            _data = data;
            _pos = offset;
            _end = offset + length;
            _bitBuf = 0;
            _bitsLeft = 0;
        }

        private void EnsureBits(int count)
        {
            while (_bitsLeft < count && _pos < _end)
            {
                var lo = _data[_pos++];
                var hi = _pos < _end ? _data[_pos++] : (byte)0;
                ulong word = (uint)(lo | (hi << 8));
                _bitBuf |= word << (48 - _bitsLeft);
                _bitsLeft += 16;
            }
        }

        public bool TryReadBits(int count, out uint value)
        {
            if (count == 0)
            {
                value = 0;
                return true;
            }

            EnsureBits(count);
            if (_bitsLeft < count)
            {
                value = 0;
                return false;
            }

            value = (uint)(_bitBuf >> (64 - count));
            _bitBuf <<= count;
            _bitsLeft -= count;
            return true;
        }

        public bool TryPeekBits(int count, out uint value, out int available)
        {
            EnsureBits(count);
            available = _bitsLeft;
            if (_bitsLeft == 0)
            {
                value = 0;
                return false;
            }

            value = (uint)(_bitBuf >> (64 - count));
            return true;
        }

        public void ConsumeBits(int count)
        {
            _bitBuf <<= count;
            _bitsLeft -= count;
        }

        public void AlignTo16ForUncompressed()
        {
            // Rewind any whole 16-bit words buffered ahead in _bitBuf back to _pos.
            var fullWordsBuffered = _bitsLeft / 16;
            var remBits = _bitsLeft % 16;

            if (remBits == 0)
            {
                // Per MS-CAB LZX spec, an uncompressed block on an exact 16-bit boundary is preceded by 16 zero pad bits.
                if (fullWordsBuffered > 0)
                {
                    fullWordsBuffered--;
                }
                else if (_pos + 2 <= _end)
                {
                    _pos += 2;
                }
            }

            _pos -= fullWordsBuffered * 2;
            _bitBuf = 0;
            _bitsLeft = 0;
        }

        public bool TryReadRawInt32LE(out int value)
        {
            if (_pos + 4 > _end)
            {
                value = 0;
                return false;
            }

            value = BinaryPrimitives.ReadInt32LittleEndian(_data.AsSpan(_pos, 4));
            _pos += 4;
            return true;
        }

        public bool TryReadRawByte(out byte value)
        {
            if (_pos >= _end)
            {
                value = 0;
                return false;
            }

            value = _data[_pos++];
            return true;
        }

        public void SkipRawByteIfAvailable()
        {
            if (_pos < _end)
                _pos++;
        }
    }

    /// <summary>Canonical MSB-first Huffman decoder (up to 16-bit codes) with fast 12-bit lookup table.</summary>
    private sealed class HuffmanTable
    {
        private const int FastBits = 12;
        private const int FastSize = 1 << FastBits;

        private readonly int _maxSymbols;
        private readonly ushort[] _fastSym = new ushort[FastSize];
        private readonly byte[] _fastLen = new byte[FastSize];

        private readonly int[] _minCode = new int[MaxHuffmanBits + 2];
        private readonly int[] _maxCode = new int[MaxHuffmanBits + 2];
        private readonly int[] _valPtr = new int[MaxHuffmanBits + 2];
        private readonly ushort[] _sortedSymbols;
        private bool _isEmpty;

        public HuffmanTable(int maxSymbols)
        {
            _maxSymbols = maxSymbols;
            _sortedSymbols = new ushort[maxSymbols];
        }

        public bool Build(ReadOnlySpan<byte> lengths)
        {
            if (lengths.Length > _maxSymbols)
                return false;

            Span<int> blCount = stackalloc int[MaxHuffmanBits + 1];
            var nonZero = 0;
            for (var i = 0; i < lengths.Length; i++)
            {
                var len = lengths[i];
                if (len > MaxHuffmanBits)
                    return false;
                if (len > 0)
                {
                    blCount[len]++;
                    nonZero++;
                }
            }

            Array.Clear(_fastLen);
            if (nonZero == 0)
            {
                _isEmpty = true;
                return true;
            }

            _isEmpty = false;

            // Validate Huffman tree isn't oversubscribed.
            uint left = 1;
            for (var bits = 1; bits <= MaxHuffmanBits; bits++)
            {
                left <<= 1;
                if ((uint)blCount[bits] > left)
                    return false;
                left -= (uint)blCount[bits];
            }

            Span<int> nextCode = stackalloc int[MaxHuffmanBits + 1];
            Span<int> offsets = stackalloc int[MaxHuffmanBits + 1];
            var code = 0;
            var offset = 0;
            for (var bits = 1; bits <= MaxHuffmanBits; bits++)
            {
                nextCode[bits] = code;
                offsets[bits] = offset;
                _minCode[bits] = code;
                _valPtr[bits] = offset;
                if (blCount[bits] > 0)
                {
                    _maxCode[bits] = code + blCount[bits] - 1;
                }
                else
                {
                    _maxCode[bits] = -1;
                }

                code = (code + blCount[bits]) << 1;
                offset += blCount[bits];
            }

            for (var sym = 0; sym < lengths.Length; sym++)
            {
                var len = lengths[sym];
                if (len == 0)
                    continue;

                var c = nextCode[len]++;
                var pos = offsets[len]++;
                _sortedSymbols[pos] = (ushort)sym;

                if (len <= FastBits)
                {
                    var shift = FastBits - len;
                    var fillStart = c << shift;
                    var fillCount = 1 << shift;
                    for (var k = 0; k < fillCount; k++)
                    {
                        _fastSym[fillStart + k] = (ushort)sym;
                        _fastLen[fillStart + k] = len;
                    }
                }
            }

            return true;
        }

        public bool TryDecode(ref BitReader bits, out int symbol)
        {
            if (_isEmpty)
            {
                symbol = 0;
                return false;
            }

            if (!bits.TryPeekBits(FastBits, out var peek, out var avail))
            {
                symbol = 0;
                return false;
            }

            var fastLen = _fastLen[peek];
            if (fastLen > 0)
            {
                if (avail < fastLen)
                {
                    symbol = 0;
                    return false;
                }

                bits.ConsumeBits(fastLen);
                symbol = _fastSym[peek];
                return true;
            }

            // Slow path for 13..16-bit codes.
            if (!bits.TryPeekBits(MaxHuffmanBits, out var peek16, out avail))
            {
                symbol = 0;
                return false;
            }

            for (var len = FastBits + 1; len <= MaxHuffmanBits; len++)
            {
                var max = _maxCode[len];
                if (max < 0)
                    continue;

                var candidate = (int)(peek16 >> (MaxHuffmanBits - len));
                if (candidate <= max && candidate >= _minCode[len])
                {
                    if (avail < len)
                    {
                        symbol = 0;
                        return false;
                    }

                    bits.ConsumeBits(len);
                    symbol = _sortedSymbols[_valPtr[len] + (candidate - _minCode[len])];
                    return true;
                }
            }

            symbol = 0;
            return false;
        }
    }
}
