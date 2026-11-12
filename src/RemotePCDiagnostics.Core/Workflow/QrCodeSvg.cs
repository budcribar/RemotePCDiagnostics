using System.Net;
using System.Text;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>
/// Self-contained ISO/IEC 18004 QR Code encoder (Versions 1–10, Byte mode, Error Correction Level M — 15% recovery, up to 213 UTF-8 bytes)
/// rendering crisp inline vector <c>&lt;svg&gt;</c> markup with zero third-party NuGet dependencies.
/// </summary>
public static class QrCodeSvg
{
    public const int MaxUtf8Bytes = 213;

    // Version 1..10 EC Level M parameters (ISO/IEC 18004 Table 9):
    // (TotalCodewords, EcCodewordsPerBlock, Group1Blocks, Group1DataCw, Group2Blocks, Group2DataCw, AlignmentCenters)
    private sealed record VersionSpec(int Version, int TotalCodewords, int EcPerBlock, int G1Blocks, int G1DataCw, int G2Blocks, int G2DataCw, int[] Align)
    {
        public int Size => 17 + 4 * Version;
        public int DataCodewords => G1Blocks * G1DataCw + G2Blocks * G2DataCw;
        public int CharCountBits => Version <= 9 ? 8 : 16;
        public int MaxByteCapacity => DataCodewords - (4 + CharCountBits) / 8 - ((4 + CharCountBits) % 8 == 0 ? 0 : 1);
    }

    private static readonly VersionSpec[] Specs =
    [
        new(1,  26, 10, 1, 16, 0,  0, []),
        new(2,  44, 16, 1, 28, 0,  0, [6, 18]),
        new(3,  70, 26, 1, 44, 0,  0, [6, 22]),
        new(4, 100, 18, 2, 32, 0,  0, [6, 26]),
        new(5, 134, 24, 2, 43, 0,  0, [6, 30]),
        new(6, 172, 16, 4, 27, 0,  0, [6, 34]),
        new(7, 196, 18, 4, 31, 0,  0, [6, 22, 38]),
        new(8, 242, 22, 2, 38, 2, 39, [6, 24, 42]),
        new(9, 292, 22, 3, 36, 2, 37, [6, 26, 46]),
        new(10, 346, 26, 4, 43, 1, 44, [6, 28, 50]),
    ];

    /// <summary>Renders a standalone crisp vector <c>&lt;svg&gt;</c> QR code for <paramref name="payload"/>.</summary>
    public static string Render(string payload, int quietZoneModules = 2, string? ariaLabel = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var matrix = EncodeMatrix(payload);
        var n = matrix.GetLength(0);
        var q = Math.Clamp(quietZoneModules, 0, 8);
        var total = n + 2 * q;
        var sb = new StringBuilder(total * total / 2 + 256);
        var label = WebUtility.HtmlEncode(ariaLabel ?? "Verification QR code");
        sb.Append("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 ").Append(total).Append(' ').Append(total)
          .Append("\" shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"").Append(label).Append("\">")
          .Append("<rect width=\"").Append(total).Append("\" height=\"").Append(total).Append("\" fill=\"#ffffff\"/>")
          .Append("<path fill=\"#111827\" d=\"");

        for (var r = 0; r < n; r++)
        {
            var c = 0;
            while (c < n)
            {
                if (!matrix[r, c]) { c++; continue; }
                var start = c;
                while (c < n && matrix[r, c]) c++;
                var w = c - start;
                sb.Append('M').Append(start + q).Append(' ').Append(r + q)
                  .Append('h').Append(w).Append("v1h-").Append(w).Append('z');
            }
        }

        sb.Append("\"/></svg>");
        return sb.ToString();
    }

    /// <summary>Encodes <paramref name="payload"/> into a dark/light boolean matrix (<c>true</c> = dark module).</summary>
    public static bool[,] EncodeMatrix(string payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var utf8 = Encoding.UTF8.GetBytes(payload);
        if (utf8.Length > MaxUtf8Bytes)
            throw new ArgumentOutOfRangeException(nameof(payload), $"QR payload length ({utf8.Length} bytes) exceeds maximum {MaxUtf8Bytes} bytes.");

        var spec = SelectSpec(utf8.Length);
        var dataCw = BuildDataCodewords(utf8, spec);
        var allCw = InterleaveWithEcc(dataCw, spec);

        var n = spec.Size;
        var modules = new bool[n, n];
        var isFunction = new bool[n, n];

        DrawFunctionPatterns(modules, isFunction, spec);
        PlaceCodewords(modules, isFunction, allCw);

        // Choose mask 0..7 minimizing ISO/IEC 18004 penalty score.
        var bestMask = 0;
        var bestPenalty = int.MaxValue;
        bool[,]? bestGrid = null;

        for (var mask = 0; mask < 8; mask++)
        {
            var candidate = (bool[,])modules.Clone();
            ApplyMask(candidate, isFunction, mask);
            DrawFormatBits(candidate, mask);
            var penalty = ScorePenalty(candidate);
            if (penalty < bestPenalty)
            {
                bestPenalty = penalty;
                bestMask = mask;
                bestGrid = candidate;
            }
        }

        _ = bestMask;
        return bestGrid!;
    }

    public static int ComputeFormatBits(int ecFormatIndicator, int mask)
    {
        var data = (ecFormatIndicator << 3) | mask;
        var rem = data << 10;
        for (var i = 4; i >= 0; i--)
        {
            if (((rem >> (i + 10)) & 1) != 0)
                rem ^= 0x537 << i;
        }
        return ((data << 10) | rem) ^ 0x5412;
    }

    public static int ComputeVersionBits(int version)
    {
        var rem = version << 12;
        for (var i = 5; i >= 0; i--)
        {
            if (((rem >> (i + 12)) & 1) != 0)
                rem ^= 0x1F25 << i;
        }
        return (version << 12) | rem;
    }

    private static VersionSpec SelectSpec(int byteLen)
    {
        foreach (var s in Specs)
        {
            var neededBits = 4 + s.CharCountBits + byteLen * 8;
            if (neededBits <= s.DataCodewords * 8) return s;
        }
        throw new ArgumentOutOfRangeException(nameof(byteLen), $"No supported QR version for {byteLen} bytes.");
    }

    private static byte[] BuildDataCodewords(byte[] utf8, VersionSpec spec)
    {
        var capacityBits = spec.DataCodewords * 8;
        var bits = new List<bool>(capacityBits);

        AppendBits(bits, 0b0100, 4); // Byte mode indicator
        AppendBits(bits, utf8.Length, spec.CharCountBits);
        foreach (var b in utf8) AppendBits(bits, b, 8);

        // Terminator (up to 4 zero bits) + pad to byte boundary
        var terminator = Math.Min(4, capacityBits - bits.Count);
        AppendBits(bits, 0, terminator);
        while (bits.Count % 8 != 0) bits.Add(false);

        var result = new byte[spec.DataCodewords];
        var cwCount = bits.Count / 8;
        for (var i = 0; i < cwCount; i++)
        {
            var v = 0;
            for (var b = 0; b < 8; b++) v = (v << 1) | (bits[i * 8 + b] ? 1 : 0);
            result[i] = (byte)v;
        }

        byte[] pad = [0xEC, 0x11];
        for (var i = cwCount; i < spec.DataCodewords; i++)
            result[i] = pad[(i - cwCount) & 1];

        return result;
    }

    private static void AppendBits(List<bool> bits, int val, int len)
    {
        for (var i = len - 1; i >= 0; i--)
            bits.Add(((val >> i) & 1) != 0);
    }

    private static byte[] InterleaveWithEcc(byte[] data, VersionSpec spec)
    {
        var totalBlocks = spec.G1Blocks + spec.G2Blocks;
        var dataBlocks = new byte[totalBlocks][];
        var eccBlocks = new byte[totalBlocks][];
        var gen = BuildReedSolomonGenerator(spec.EcPerBlock);

        var offset = 0;
        for (var b = 0; b < totalBlocks; b++)
        {
            var len = b < spec.G1Blocks ? spec.G1DataCw : spec.G2DataCw;
            var block = new byte[len];
            Array.Copy(data, offset, block, 0, len);
            offset += len;
            dataBlocks[b] = block;
            eccBlocks[b] = ComputeReedSolomonRemainder(block, gen);
        }

        var output = new byte[spec.TotalCodewords];
        var pos = 0;
        var maxDataLen = Math.Max(spec.G1DataCw, spec.G2DataCw);
        for (var i = 0; i < maxDataLen; i++)
        {
            for (var b = 0; b < totalBlocks; b++)
                if (i < dataBlocks[b].Length) output[pos++] = dataBlocks[b][i];
        }
        for (var i = 0; i < spec.EcPerBlock; i++)
        {
            for (var b = 0; b < totalBlocks; b++)
                output[pos++] = eccBlocks[b][i];
        }
        return output;
    }

    private static byte[] BuildReedSolomonGenerator(int degree)
    {
        var poly = new byte[degree];
        poly[degree - 1] = 1;
        byte root = 1;
        for (var i = 0; i < degree; i++)
        {
            for (var j = 0; j < degree; j++)
            {
                poly[j] = GfMultiply(poly[j], root);
                if (j + 1 < degree) poly[j] ^= poly[j + 1];
            }
            root = GfMultiply(root, 0x02);
        }
        return poly;
    }

    private static byte[] ComputeReedSolomonRemainder(byte[] data, byte[] generator)
    {
        var rem = new byte[generator.Length];
        foreach (var b in data)
        {
            var factor = (byte)(b ^ rem[0]);
            Array.Copy(rem, 1, rem, 0, rem.Length - 1);
            rem[^1] = 0;
            if (factor == 0) continue;
            for (var j = 0; j < generator.Length; j++)
                rem[j] ^= GfMultiply(generator[j], factor);
        }
        return rem;
    }

    private static byte GfMultiply(byte x, byte y)
    {
        var z = 0;
        for (var i = 7; i >= 0; i--)
        {
            z = (z << 1) ^ ((z >> 7) * 0x11D);
            z ^= ((y >> i) & 1) * x;
        }
        return (byte)z;
    }

    private static void DrawFunctionPatterns(bool[,] modules, bool[,] isFunction, VersionSpec spec)
    {
        var n = spec.Size;

        // Timing patterns
        for (var i = 0; i < n; i++)
        {
            SetFunction(modules, isFunction, 6, i, i % 2 == 0);
            SetFunction(modules, isFunction, i, 6, i % 2 == 0);
        }

        // Three 7x7 finder patterns + white separators (centered at (3,3), (3,n-4), (n-4,3))
        DrawFinderPattern(modules, isFunction, 3, 3, n);
        DrawFinderPattern(modules, isFunction, 3, n - 4, n);
        DrawFinderPattern(modules, isFunction, n - 4, 3, n);

        // Alignment patterns
        var align = spec.Align;
        for (var i = 0; i < align.Length; i++)
        {
            for (var j = 0; j < align.Length; j++)
            {
                if ((i == 0 && j == 0) || (i == 0 && j == align.Length - 1) || (i == align.Length - 1 && j == 0))
                    continue;
                DrawAlignmentPattern(modules, isFunction, align[i], align[j]);
            }
        }

        // Reserve format info modules & set dark module (4*V + 9, 8) = (n - 8, 8)
        DrawFormatBits(modules, 0, isFunction);

        // Version info (V7..V10)
        if (spec.Version >= 7)
        {
            var bits = ComputeVersionBits(spec.Version);
            for (var i = 0; i < 18; i++)
            {
                var bit = ((bits >> i) & 1) != 0;
                var a = n - 11 + i % 3;
                var b = i / 3;
                SetFunction(modules, isFunction, b, a, bit);
                SetFunction(modules, isFunction, a, b, bit);
            }
        }
    }

    private static void DrawFinderPattern(bool[,] modules, bool[,] isFunction, int centerR, int centerC, int n)
    {
        for (var dy = -4; dy <= 4; dy++)
        {
            for (var dx = -4; dx <= 4; dx++)
            {
                var r = centerR + dy;
                var c = centerC + dx;
                if (r < 0 || r >= n || c < 0 || c >= n) continue;
                var dist = Math.Max(Math.Abs(dx), Math.Abs(dy));
                SetFunction(modules, isFunction, r, c, dist != 2 && dist != 4);
            }
        }
    }

    private static void DrawAlignmentPattern(bool[,] modules, bool[,] isFunction, int centerR, int centerC)
    {
        for (var dy = -2; dy <= 2; dy++)
        {
            for (var dx = -2; dx <= 2; dx++)
            {
                var dist = Math.Max(Math.Abs(dx), Math.Abs(dy));
                SetFunction(modules, isFunction, centerR + dy, centerC + dx, dist != 1);
            }
        }
    }

    private static void DrawFormatBits(bool[,] modules, int mask, bool[,]? isFunction = null)
    {
        var n = modules.GetLength(0);
        // EC Level M format indicator is 00 (0).
        var bits = ComputeFormatBits(0, mask);

        // Top-left copy: bit 0..5 up col 8 (rows 0..5), bit 6 at (7,8), bit 7 at (8,8), bit 8 at (8,7), bits 9..14 at (8, 5..0)
        for (var i = 0; i <= 5; i++) SetFmt(i, 8, GetBit(bits, i));
        SetFmt(7, 8, GetBit(bits, 6));
        SetFmt(8, 8, GetBit(bits, 7));
        SetFmt(8, 7, GetBit(bits, 8));
        for (var i = 9; i < 15; i++) SetFmt(8, 14 - i, GetBit(bits, i));

        // Top-right & bottom-left copy: bits 0..7 along row 8 cols (n-1 .. n-8), bits 8..14 along col 8 rows (n-7 .. n-1)
        for (var i = 0; i < 8; i++) SetFmt(8, n - 1 - i, GetBit(bits, i));
        for (var i = 8; i < 15; i++) SetFmt(n - 15 + i, 8, GetBit(bits, i));

        // Always-dark module at (n - 8, 8)
        SetFmt(n - 8, 8, true);

        void SetFmt(int r, int c, bool dark)
        {
            modules[r, c] = dark;
            if (isFunction is not null) isFunction[r, c] = true;
        }
    }

    private static void SetFunction(bool[,] modules, bool[,] isFunction, int r, int c, bool dark)
    {
        modules[r, c] = dark;
        isFunction[r, c] = true;
    }

    private static void PlaceCodewords(bool[,] modules, bool[,] isFunction, byte[] allCw)
    {
        var n = modules.GetLength(0);
        var bitIdx = 0;
        var totalBits = allCw.Length * 8;

        for (var right = n - 1; right >= 1; right -= 2)
        {
            if (right == 6) right = 5; // Skip vertical timing column
            for (var vert = 0; vert < n; vert++)
            {
                var upward = ((right + 1) & 2) == 0;
                var r = upward ? n - 1 - vert : vert;
                for (var j = 0; j < 2; j++)
                {
                    var c = right - j;
                    if (isFunction[r, c]) continue;
                    var dark = bitIdx < totalBits && GetBit(allCw[bitIdx >> 3], 7 - (bitIdx & 7));
                    modules[r, c] = dark;
                    bitIdx++;
                }
            }
        }
    }

    private static void ApplyMask(bool[,] modules, bool[,] isFunction, int mask)
    {
        var n = modules.GetLength(0);
        for (var r = 0; r < n; r++)
        {
            for (var c = 0; c < n; c++)
            {
                if (isFunction[r, c]) continue;
                var invert = mask switch
                {
                    0 => (r + c) % 2 == 0,
                    1 => r % 2 == 0,
                    2 => c % 3 == 0,
                    3 => (r + c) % 3 == 0,
                    4 => (r / 2 + c / 3) % 2 == 0,
                    5 => r * c % 2 + r * c % 3 == 0,
                    6 => (r * c % 2 + r * c % 3) % 2 == 0,
                    7 => ((r + c) % 2 + r * c % 3) % 2 == 0,
                    _ => false,
                };
                if (invert) modules[r, c] = !modules[r, c];
            }
        }
    }

    private static int ScorePenalty(bool[,] m)
    {
        var n = m.GetLength(0);
        var penalty = 0;

        // N1: 5+ consecutive same-color modules in rows and columns
        for (var i = 0; i < n; i++)
        {
            int rowRun = 1, colRun = 1;
            for (var j = 1; j < n; j++)
            {
                if (m[i, j] == m[i, j - 1]) { rowRun++; if (rowRun == 5) penalty += 3; else if (rowRun > 5) penalty++; }
                else rowRun = 1;

                if (m[j, i] == m[j - 1, i]) { colRun++; if (colRun == 5) penalty += 3; else if (colRun > 5) penalty++; }
                else colRun = 1;
            }
        }

        // N2: 2x2 same-color blocks
        for (var r = 0; r < n - 1; r++)
        {
            for (var c = 0; c < n - 1; c++)
            {
                var v = m[r, c];
                if (v == m[r, c + 1] && v == m[r + 1, c] && v == m[r + 1, c + 1])
                    penalty += 3;
            }
        }

        // N3: 1:1:3:1:1 finder-like patterns preceded or followed by 4 light modules
        for (var i = 0; i < n; i++)
        {
            for (var j = 0; j <= n - 11; j++)
            {
                if (IsFinderLike(r => m[i, j + r])) penalty += 40;
                if (IsFinderLike(r => m[j + r, i])) penalty += 40;
            }
        }

        // N4: dark module balance
        var dark = 0;
        for (var r = 0; r < n; r++)
            for (var c = 0; c < n; c++)
                if (m[r, c]) dark++;
        var total = n * n;
        var k = Math.Abs(dark * 20 - total * 10) / total;
        penalty += k * 10;

        return penalty;
    }

    private static bool IsFinderLike(Func<int, bool> at)
    {
        // 10111010000 or 00001011101
        var p1 = at(0) && !at(1) && at(2) && at(3) && at(4) && !at(5) && at(6) && !at(7) && !at(8) && !at(9) && !at(10);
        if (p1) return true;
        return !at(0) && !at(1) && !at(2) && !at(3) && at(4) && !at(5) && at(6) && at(7) && at(8) && !at(9) && at(10);
    }

    private static bool GetBit(int val, int bit) => ((val >> bit) & 1) != 0;
}
