using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>Structured outcome of pure-C# MS-CAB (<c>MSCF</c>) inspection and extraction.</summary>
public enum CabExtractionStatus
{
    /// <summary>CAB archive passed all safety checks and was extracted in pure C#.</summary>
    Succeeded = 0,

    /// <summary>
    /// CAB archive passed all header, folder, path-traversal, and size-cap validations,
    /// but uses a compression method (e.g., LZX or Quantum) or cross-block MSZIP stream not handled in pure C#.
    /// </summary>
    UnsupportedCompression = 1,

    /// <summary>
    /// CAB archive is malformed, truncated, contains unsafe/traversal entry paths, or exceeds
    /// the maximum decompressed size cap. Callers MUST NOT fall back to native <c>expand.exe</c>.
    /// </summary>
    UnsafeOrInvalid = 2,
}

/// <summary>
/// Shared XXE-prohibited XML parser, size-capped GZip decompressor, Zip-Slip-safe ZIP extractor,
/// and pure-C# MS-CAB (<c>MSCF</c>) reader with optional native <c>expand.exe</c> fallback for LZX CABs.
/// </summary>
public static class BiosArchiveAndXml
{
    public const long DefaultMaxXmlCharacters = 64L * 1024 * 1024;
    public const long DefaultMaxDecompressedBytes = 128L * 1024 * 1024;

    private const int CopyBufferSize = 81920;
    private const int MaxCabFolders = 4096;
    private const int MaxCabHeaderReserve = 60000;
    private const ushort CabFlagPrevCabinet = 0x0001;
    private const ushort CabFlagNextCabinet = 0x0002;
    private const ushort CabFlagReservePresent = 0x0004;
    private const ushort CabAttribNameIsUtf = 0x0080;

    /// <summary>Parses an XML string with DTD processing prohibited, no XML resolver, and bounded document size.</summary>
    public static XDocument ParseXmlSafe(string xml, long maxCharactersInDocument = DefaultMaxXmlCharacters)
    {
        ArgumentNullException.ThrowIfNull(xml);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxCharactersInDocument);

        var clean = xml.Length > 0 && xml[0] == '\uFEFF' ? xml[1..] : xml;
        using var sr = new StringReader(clean);
        using var reader = XmlReader.Create(sr, CreateSafeXmlSettings(maxCharactersInDocument));
        return XDocument.Load(reader, LoadOptions.None);
    }

    /// <summary>Parses an XML stream with DTD processing prohibited, no XML resolver, and bounded document size.</summary>
    public static XDocument ParseXmlSafe(Stream stream, long maxCharactersInDocument = DefaultMaxXmlCharacters)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxCharactersInDocument);

        using var reader = XmlReader.Create(stream, CreateSafeXmlSettings(maxCharactersInDocument));
        return XDocument.Load(reader, LoadOptions.None);
    }

    /// <summary>
    /// Decompresses a GZip stream while enforcing a strict maximum output byte cap (<paramref name="maxBytes"/>).
    /// Throws <see cref="InvalidDataException"/> immediately upon exceeding the cap.
    /// </summary>
    public static async Task<byte[]> DecompressGzipBoundedAsync(
        Stream stream,
        long maxBytes = DefaultMaxDecompressedBytes,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);

        await using var gzip = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: true);
        using var ms = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        long total = 0;

        try
        {
            while (true)
            {
                var remaining = maxBytes - total;
                var toRead = remaining >= buffer.Length ? buffer.Length : (int)remaining + 1;
                var read = await gzip.ReadAsync(buffer.AsMemory(0, toRead), ct).ConfigureAwait(false);
                if (read == 0)
                    break;

                if (total + read > maxBytes || total + read > Array.MaxLength)
                    throw new InvalidDataException($"GZip stream exceeded maximum allowed size of {maxBytes} bytes.");

                ms.Write(buffer, 0, read);
                total += read;
            }

            return ms.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Safely extracts a ZIP archive into <paramref name="destinationDir"/>, preventing Zip-Slip traversal,
    /// absolute/drive paths, NTFS alternate data streams, Windows reserved device names, forbidden/control
    /// characters, Unix symlinks, and decompression bombs.
    /// </summary>
    public static IReadOnlyList<string> ExtractZipSafe(
        string zipPath,
        string destinationDir,
        long maxTotalBytes = DefaultMaxDecompressedBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(zipPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationDir);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxTotalBytes);

        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(destinationDir));
        EnsureNoSymlinkOrReparseAncestors(fullRoot);
        Directory.CreateDirectory(fullRoot);
        EnsureNoSymlinkOrReparseAncestors(fullRoot);
        var rootWithSep = fullRoot.EndsWith(Path.DirectorySeparatorChar)
            ? fullRoot
            : fullRoot + Path.DirectorySeparatorChar;
        var pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        var extracted = new List<string>();
        long totalBytes = 0;
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);

        try
        {
            using var archive = ZipFile.OpenRead(zipPath);
            var filesToExtract = new List<(ZipArchiveEntry Entry, string[] Segments, string DestPath)>(archive.Entries.Count);

            foreach (var entry in archive.Entries)
            {
                var unixMode = (entry.ExternalAttributes >> 16) & 0xF000;
                if (unixMode == 0xA000)
                    throw new InvalidDataException($"ZIP entry '{entry.FullName}' is a symbolic link and is not allowed.");

                if (!TryValidateArchiveEntryPath(
                    entry.FullName,
                    allowTrailingDirectorySeparator: true,
                    out var segments,
                    out var isDirectoryEntry,
                    out var failureReason))
                {
                    throw new InvalidDataException($"ZIP entry '{entry.FullName}' is invalid: {failureReason}.");
                }

                if (isDirectoryEntry)
                    continue;

                var relative = Path.Combine(segments);
                var destPath = Path.GetFullPath(Path.Combine(fullRoot, relative));
                if (!destPath.StartsWith(rootWithSep, pathComparison))
                    throw new InvalidDataException($"ZIP entry '{entry.FullName}' escapes the destination directory.");

                filesToExtract.Add((entry, segments, destPath));
            }

            foreach (var (entry, segments, destPath) in filesToExtract)
            {
                if (entry.Length < 0 || entry.Length > maxTotalBytes - totalBytes)
                    throw new InvalidDataException($"ZIP archive exceeds maximum allowed extracted size of {maxTotalBytes} bytes.");

                // Walk every directory component from fullRoot down through segments[..^1],
                // rejecting any pre-existing or intermediate directory symlink / reparse point before writing.
                EnsureNotSymlinkOrReparseDirectory(fullRoot, entry.FullName);
                var currentDir = fullRoot;
                for (var s = 0; s < segments.Length - 1; s++)
                {
                    currentDir = Path.Combine(currentDir, segments[s]);
                    EnsureNotSymlinkOrReparseDirectory(currentDir, entry.FullName);
                    if (!Directory.Exists(currentDir))
                        Directory.CreateDirectory(currentDir);
                    EnsureNotSymlinkOrReparseDirectory(currentDir, entry.FullName);
                }

                EnsureNotSymlinkOrReparseFile(destPath, entry.FullName);

                var fileCreated = false;
                var entrySucceeded = false;
                try
                {
                    using var entryStream = entry.Open();
                    using var destStream = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None, CopyBufferSize);
                    fileCreated = true;
                    while (true)
                    {
                        var remaining = maxTotalBytes - totalBytes;
                        var toRead = remaining >= buffer.Length ? buffer.Length : (int)remaining + 1;
                        var read = entryStream.Read(buffer, 0, toRead);
                        if (read == 0)
                            break;

                        if (totalBytes + read > maxTotalBytes)
                            throw new InvalidDataException($"ZIP archive exceeded maximum allowed extracted size of {maxTotalBytes} bytes.");

                        destStream.Write(buffer, 0, read);
                        totalBytes += read;
                    }

                    entrySucceeded = true;
                }
                finally
                {
                    if (fileCreated && !entrySucceeded)
                        TryDeleteFile(destPath);
                }

                extracted.Add(destPath);
            }

            return extracted;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Pure-C# Microsoft Cabinet (<c>MSCF</c>) reader supporting <c>TYPE_NONE</c> (0), <c>TYPE_MSZIP</c> (1),
    /// and <c>TYPE_LZX</c> (3, window sizes 15..21).
    /// Returns <c>false</c> cleanly (never throws) on unsupported compression (e.g., Quantum), corrupt/truncated archives,
    /// path traversal entries, or archives exceeding <paramref name="maxTotalBytes"/>.
    /// </summary>
    public static bool TryExtractCabEntries(
        byte[] cabBytes,
        out IReadOnlyDictionary<string, byte[]> entries,
        long maxTotalBytes = DefaultMaxDecompressedBytes) =>
        TryExtractCabEntriesWithStatus(cabBytes, out entries, maxTotalBytes) == CabExtractionStatus.Succeeded;

    /// <summary>
    /// Pure-C# Microsoft Cabinet (<c>MSCF</c>) inspector and extractor returning a structured
    /// <see cref="CabExtractionStatus"/> so callers can distinguish safe unsupported-compression CABs (LZX/Quantum)
    /// from malformed, path-traversal, or oversized CAB bombs that MUST NOT be handed to native <c>expand.exe</c>.
    /// </summary>
    public static CabExtractionStatus TryExtractCabEntriesWithStatus(
        byte[] cabBytes,
        out IReadOnlyDictionary<string, byte[]> entries,
        long maxTotalBytes = DefaultMaxDecompressedBytes)
    {
        var empty = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        entries = empty;

        if (cabBytes is null || cabBytes.Length < 36 || maxTotalBytes <= 0)
            return CabExtractionStatus.UnsafeOrInvalid;

        try
        {
            var span = cabBytes.AsSpan();
            if (span[0] != (byte)'M' || span[1] != (byte)'S' || span[2] != (byte)'C' || span[3] != (byte)'F')
                return CabExtractionStatus.UnsafeOrInvalid;

            var cbCabinet = BinaryPrimitives.ReadUInt32LittleEndian(span[8..]);
            if (cbCabinet < 36 || cbCabinet > (uint)cabBytes.Length)
                return CabExtractionStatus.UnsafeOrInvalid;

            var coffFiles = BinaryPrimitives.ReadUInt32LittleEndian(span[16..]);
            if (coffFiles < 36 || coffFiles > cbCabinet)
                return CabExtractionStatus.UnsafeOrInvalid;

            var versionMinor = span[24];
            var versionMajor = span[25];
            if (versionMajor != 1 || versionMinor != 3)
                return CabExtractionStatus.UnsafeOrInvalid;

            var cFolders = BinaryPrimitives.ReadUInt16LittleEndian(span[26..]);
            var cFiles = BinaryPrimitives.ReadUInt16LittleEndian(span[28..]);
            var flags = BinaryPrimitives.ReadUInt16LittleEndian(span[30..]);

            if (cFolders > MaxCabFolders)
                return CabExtractionStatus.UnsafeOrInvalid;

            var pos = 36;
            ushort cbCFHeader = 0;
            byte cbCFFolder = 0;
            byte cbCFData = 0;

            if ((flags & CabFlagReservePresent) != 0)
            {
                if (pos + 4 > cbCabinet)
                    return CabExtractionStatus.UnsafeOrInvalid;

                cbCFHeader = BinaryPrimitives.ReadUInt16LittleEndian(span[pos..]);
                cbCFFolder = span[pos + 2];
                cbCFData = span[pos + 3];
                pos += 4;

                if (cbCFHeader > MaxCabHeaderReserve || (long)pos + cbCFHeader > cbCabinet)
                    return CabExtractionStatus.UnsafeOrInvalid;

                pos += cbCFHeader;
            }

            if ((flags & CabFlagPrevCabinet) != 0)
            {
                if (!SkipNullTerminatedString(span, (int)cbCabinet, ref pos)
                    || !SkipNullTerminatedString(span, (int)cbCabinet, ref pos))
                    return CabExtractionStatus.UnsafeOrInvalid;
            }

            if ((flags & CabFlagNextCabinet) != 0)
            {
                if (!SkipNullTerminatedString(span, (int)cbCabinet, ref pos)
                    || !SkipNullTerminatedString(span, (int)cbCabinet, ref pos))
                    return CabExtractionStatus.UnsafeOrInvalid;
            }

            var folderRecordSize = 8 + cbCFFolder;
            if ((long)pos + (long)cFolders * folderRecordSize > cbCabinet)
                return CabExtractionStatus.UnsafeOrInvalid;

            if (cFiles == 0)
                return CabExtractionStatus.Succeeded;

            if (cFolders == 0)
                return CabExtractionStatus.UnsafeOrInvalid;

            var folders = new CabFolder[cFolders];
            for (var i = 0; i < cFolders; i++)
            {
                var coffCabStart = BinaryPrimitives.ReadUInt32LittleEndian(span[pos..]);
                var cCFData = BinaryPrimitives.ReadUInt16LittleEndian(span[(pos + 4)..]);
                var typeCompress = BinaryPrimitives.ReadUInt16LittleEndian(span[(pos + 6)..]);
                folders[i] = new CabFolder(coffCabStart, cCFData, typeCompress & 0x000F, (typeCompress >> 8) & 0x001F);
                pos += folderRecordSize;
            }

            var folderFiles = new List<CabFileEntry>[cFolders];
            for (var i = 0; i < cFolders; i++)
                folderFiles[i] = [];

            var filePos = (int)coffFiles;
            long declaredTotal = 0;
            for (var i = 0; i < cFiles; i++)
            {
                if ((long)filePos + 16 >= cbCabinet)
                    return CabExtractionStatus.UnsafeOrInvalid;

                var cbFile = BinaryPrimitives.ReadUInt32LittleEndian(span[filePos..]);
                var uoffFolderStart = BinaryPrimitives.ReadUInt32LittleEndian(span[(filePos + 4)..]);
                var iFolder = BinaryPrimitives.ReadUInt16LittleEndian(span[(filePos + 8)..]);
                var attribs = BinaryPrimitives.ReadUInt16LittleEndian(span[(filePos + 14)..]);
                filePos += 16;

                if (iFolder >= 0xFFFD || iFolder >= cFolders)
                    return CabExtractionStatus.UnsafeOrInvalid;

                var searchLimit = Math.Min((int)cbCabinet, filePos + 1024);
                var nulIdx = -1;
                for (var k = filePos; k < searchLimit; k++)
                {
                    if (span[k] == 0)
                    {
                        nulIdx = k;
                        break;
                    }
                }

                if (nulIdx < 0)
                    return CabExtractionStatus.UnsafeOrInvalid;

                var nameBytes = span[filePos..nulIdx];
                var rawName = (attribs & CabAttribNameIsUtf) != 0
                    ? Encoding.UTF8.GetString(nameBytes)
                    : Encoding.Latin1.GetString(nameBytes);
                filePos = nulIdx + 1;

                if (!TrySanitizeCabEntryName(rawName, out var sanitizedName))
                    return CabExtractionStatus.UnsafeOrInvalid;

                declaredTotal += cbFile;
                if (declaredTotal > maxTotalBytes || (long)uoffFolderStart + cbFile > maxTotalBytes)
                    return CabExtractionStatus.UnsafeOrInvalid;

                folderFiles[iFolder].Add(new CabFileEntry(sanitizedName, cbFile, uoffFolderStart));
            }

            // Pass 1: Validate all used folder compression methods, CFDATA header bounds, and cumulative
            // uncompressed block sizes BEFORE deciding whether unsupported compression fallback is allowed.
            var hasUnsupportedCompression = false;
            long totalDeclaredBlockUncomp = 0;

            for (var f = 0; f < cFolders; f++)
            {
                if (folderFiles[f].Count == 0)
                    continue;

                var folder = folders[f];
                if (folder.CompressionMethod is not (0 or 1 or 2 or 3))
                    return CabExtractionStatus.UnsafeOrInvalid;

                if (folder.CompressionMethod == 2
                    || (folder.CompressionMethod == 3 && !LzxDecoder.IsSupportedWindowBits(folder.WindowBits)))
                {
                    hasUnsupportedCompression = true;
                }

                long dataPos = folder.CoffCabStart;
                long folderUncomp = 0;
                for (var b = 0; b < folder.CCFData; b++)
                {
                    if (dataPos < 0 || dataPos + 8 + cbCFData > cbCabinet)
                        return CabExtractionStatus.UnsafeOrInvalid;

                    var cbData = BinaryPrimitives.ReadUInt16LittleEndian(span[(int)(dataPos + 4)..]);
                    var cbUncomp = BinaryPrimitives.ReadUInt16LittleEndian(span[(int)(dataPos + 6)..]);
                    var payloadOffset = dataPos + 8 + cbCFData;

                    if (payloadOffset + cbData > cbCabinet)
                        return CabExtractionStatus.UnsafeOrInvalid;

                    if (totalDeclaredBlockUncomp > maxTotalBytes - cbUncomp)
                        return CabExtractionStatus.UnsafeOrInvalid;

                    if (folder.CompressionMethod == 0 && cbData != cbUncomp)
                        return CabExtractionStatus.UnsafeOrInvalid;

                    if (folder.CompressionMethod == 1
                        && (cbData < 2 || cabBytes[payloadOffset] != (byte)'C' || cabBytes[payloadOffset + 1] != (byte)'K'))
                    {
                        return CabExtractionStatus.UnsafeOrInvalid;
                    }

                    totalDeclaredBlockUncomp += cbUncomp;
                    folderUncomp += cbUncomp;
                    dataPos = payloadOffset + cbData;
                }

                foreach (var file in folderFiles[f])
                {
                    if ((long)file.UoffFolderStart + file.CbFile > folderUncomp)
                        return CabExtractionStatus.UnsafeOrInvalid;
                }
            }

            if (hasUnsupportedCompression)
                return CabExtractionStatus.UnsupportedCompression;

            // Pass 2: Pure-C# extraction for TYPE_NONE (0), TYPE_MSZIP (1), and TYPE_LZX (3, window 15..21).
            var result = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            long cumulativeUncomp = 0;

            for (var f = 0; f < cFolders; f++)
            {
                if (folderFiles[f].Count == 0)
                    continue;

                var folder = folders[f];
                long dataPos = folder.CoffCabStart;
                using var folderStream = new MemoryStream();
                LzxDecoder? lzx = null;
                byte[]? lzxBlockBuf = null;
                if (folder.CompressionMethod == 3)
                {
                    if (!LzxDecoder.TryCreate(folder.WindowBits, out lzx))
                        return CabExtractionStatus.UnsupportedCompression;
                    lzxBlockBuf = new byte[32768];
                }

                for (var b = 0; b < folder.CCFData; b++)
                {
                    var cbData = BinaryPrimitives.ReadUInt16LittleEndian(span[(int)(dataPos + 4)..]);
                    var cbUncomp = BinaryPrimitives.ReadUInt16LittleEndian(span[(int)(dataPos + 6)..]);
                    var payloadOffset = dataPos + 8 + cbCFData;

                    if (cumulativeUncomp > maxTotalBytes - cbUncomp)
                        return CabExtractionStatus.UnsafeOrInvalid;

                    if (folder.CompressionMethod == 0)
                    {
                        folderStream.Write(cabBytes, (int)payloadOffset, cbData);
                        cumulativeUncomp += cbUncomp;
                    }
                    else if (folder.CompressionMethod == 1)
                    {
                        if (!TryDecompressMsZipBlock(cabBytes, (int)(payloadOffset + 2), cbData - 2, cbUncomp, out var blockBuf))
                        {
                            // Subsequent MSZIP blocks (b > 0) may legitimately reference prior 32 KB block
                            // history which standalone DeflateStream cannot reconstruct.
                            return b > 0
                                ? CabExtractionStatus.UnsupportedCompression
                                : CabExtractionStatus.UnsafeOrInvalid;
                        }

                        folderStream.Write(blockBuf, 0, cbUncomp);
                        cumulativeUncomp += cbUncomp;
                    }
                    else
                    {
                        if (!lzx!.TryDecompressBlock(cabBytes, (int)payloadOffset, cbData, cbUncomp, lzxBlockBuf!))
                            return CabExtractionStatus.UnsupportedCompression;

                        folderStream.Write(lzxBlockBuf!, 0, cbUncomp);
                        cumulativeUncomp += cbUncomp;
                    }

                    dataPos = payloadOffset + cbData;
                }

                var folderData = folderStream.ToArray();
                foreach (var file in folderFiles[f])
                {
                    if ((long)file.UoffFolderStart + file.CbFile > folderData.Length)
                        return CabExtractionStatus.UnsafeOrInvalid;

                    var content = new byte[file.CbFile];
                    Buffer.BlockCopy(folderData, (int)file.UoffFolderStart, content, 0, (int)file.CbFile);
                    result[file.SanitizedName] = content;
                }
            }

            entries = result;
            return CabExtractionStatus.Succeeded;
        }
        catch
        {
            entries = empty;
            return CabExtractionStatus.UnsafeOrInvalid;
        }
    }

    /// <summary>
    /// Extracts XML text from either a plain XML payload (UTF-8/UTF-16 with optional BOM) or a CAB archive
    /// (pure C# <see cref="TryExtractCabEntries"/> first, with optional native <c>expand.exe</c> fallback via
    /// <c>ArgumentList</c> for LZX CABs on Windows or scripted test runners).
    /// </summary>
    public static async Task<string?> ExtractXmlFromCabOrPlainAsync(
        byte[] payload,
        string stagingHint,
        SystemCommandRunner? commands = null,
        CancellationToken ct = default,
        long maxDecompressedBytes = DefaultMaxDecompressedBytes)
    {
        if (payload is null || payload.Length == 0 || maxDecompressedBytes <= 0)
            return null;

        ct.ThrowIfCancellationRequested();

        if (payload.Length <= maxDecompressedBytes && TryDecodePlainXml(payload, out var plainXml))
            return plainXml;

        if (payload.Length < 4
            || payload[0] != (byte)'M'
            || payload[1] != (byte)'S'
            || payload[2] != (byte)'C'
            || payload[3] != (byte)'F')
            return null;

        var cabStatus = TryExtractCabEntriesWithStatus(payload, out var entries, maxDecompressedBytes);
        if (cabStatus == CabExtractionStatus.Succeeded)
        {
            var xmlKey = entries.Keys
                .Where(static k => k.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                .OrderBy(static k => k, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();

            return xmlKey is null ? null : DecodeXmlBytes(entries[xmlKey]);
        }

        // Only fall back to native expand.exe when the CAB passed all structural, traversal,
        // and size-cap checks and simply uses unsupported compression (e.g., LZX/Quantum).
        if (cabStatus != CabExtractionStatus.UnsupportedCompression)
            return null;

        if (commands is null || (!OperatingSystem.IsWindows() && !commands.IsScripted))
            return null;

        var prefix = SanitizeTempPrefix(stagingHint);
        var tempDir = Path.Combine(Path.GetTempPath(), $"rpd-bios-cab-{prefix}-{Guid.NewGuid():N}");
        var outDir = Path.Combine(tempDir, "out");
        var cabPath = Path.Combine(tempDir, "catalog.cab");

        try
        {
            Directory.CreateDirectory(outDir);
            await File.WriteAllBytesAsync(cabPath, payload, ct).ConfigureAwait(false);

            var pr = await commands.RunAsync(
                SystemCommandRunner.SystemTool("expand.exe"),
                ["-F:*.xml", cabPath, outDir],
                TimeSpan.FromSeconds(60),
                ct).ConfigureAwait(false);

            if (pr is not { ExitCode: 0 })
                return null;

            var xmlFile = Directory.EnumerateFiles(outDir, "*.xml", SearchOption.AllDirectories)
                .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();

            if (xmlFile is null)
                return null;

            var fullTempDir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(tempDir));
            var fullOutDir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(outDir));
            var outDirWithSep = fullOutDir.EndsWith(Path.DirectorySeparatorChar)
                ? fullOutDir
                : fullOutDir + Path.DirectorySeparatorChar;
            var pathComparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;
            var fullXmlPath = Path.GetFullPath(xmlFile);
            if (!fullXmlPath.StartsWith(outDirWithSep, pathComparison))
                return null;

            var fi = new FileInfo(fullXmlPath);
            if (!fi.Exists
                || fi.LinkTarget is not null
                || (fi.Attributes & FileAttributes.ReparsePoint) != 0
                || fi.Length <= 0
                || fi.Length > maxDecompressedBytes)
            {
                return null;
            }

            if (!AreAllAncestorsSafeWithinRoot(fi.Directory, fullTempDir, pathComparison))
                return null;

            var bytes = await File.ReadAllBytesAsync(fullXmlPath, ct).ConfigureAwait(false);
            return DecodeXmlBytes(bytes);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
        finally
        {
            TryDeleteDirectory(tempDir);
        }
    }

    private static XmlReaderSettings CreateSafeXmlSettings(long maxCharactersInDocument) => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersFromEntities = 0,
        MaxCharactersInDocument = maxCharactersInDocument,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
    };

    private static bool TryDecodePlainXml(byte[] payload, out string xml)
    {
        xml = "";

        if (payload.Length >= 2 && payload[0] == 0xFF && payload[1] == 0xFE)
        {
            var decoded = Encoding.Unicode.GetString(payload, 2, payload.Length - 2);
            if (decoded.TrimStart().StartsWith('<'))
            {
                xml = decoded;
                return true;
            }

            return false;
        }

        if (payload.Length >= 2 && payload[0] == 0xFE && payload[1] == 0xFF)
        {
            var decoded = Encoding.BigEndianUnicode.GetString(payload, 2, payload.Length - 2);
            if (decoded.TrimStart().StartsWith('<'))
            {
                xml = decoded;
                return true;
            }

            return false;
        }

        if (payload.Length >= 2 && payload[0] == (byte)'<' && payload[1] == 0x00)
        {
            var decoded = Encoding.Unicode.GetString(payload);
            if (decoded.TrimStart().StartsWith('<'))
            {
                xml = decoded;
                return true;
            }

            return false;
        }

        var offset = 0;
        if (payload.Length >= 3 && payload[0] == 0xEF && payload[1] == 0xBB && payload[2] == 0xBF)
            offset = 3;

        var scan = offset;
        while (scan < payload.Length && payload[scan] is 0x20 or 0x09 or 0x0D or 0x0A)
            scan++;

        if (scan < payload.Length && payload[scan] == (byte)'<')
        {
            xml = Encoding.UTF8.GetString(payload, offset, payload.Length - offset);
            return true;
        }

        return false;
    }

    private static string DecodeXmlBytes(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);

        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);

        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);

        if (bytes.Length >= 2 && bytes[0] == (byte)'<' && bytes[1] == 0x00)
            return Encoding.Unicode.GetString(bytes);

        return Encoding.UTF8.GetString(bytes);
    }

    private static bool TryDecompressMsZipBlock(
        byte[] cabBytes,
        int deflateOffset,
        int deflateLength,
        int expectedUncompressedLength,
        out byte[] blockBuf)
    {
        blockBuf = new byte[expectedUncompressedLength + 1];
        try
        {
            using var input = new MemoryStream(cabBytes, deflateOffset, deflateLength, writable: false);
            using var deflate = new DeflateStream(input, CompressionMode.Decompress);

            var totalRead = 0;
            while (totalRead < blockBuf.Length)
            {
                var read = deflate.Read(blockBuf, totalRead, blockBuf.Length - totalRead);
                if (read == 0)
                    break;
                totalRead += read;
            }

            return totalRead == expectedUncompressedLength;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static bool SkipNullTerminatedString(ReadOnlySpan<byte> span, int limit, ref int pos)
    {
        var max = Math.Min(limit, pos + 1024);
        for (var i = pos; i < max; i++)
        {
            if (span[i] == 0)
            {
                pos = i + 1;
                return true;
            }
        }

        return false;
    }

    private static readonly char[] ForbiddenArchivePathChars = ['<', '>', '"', '|', '?', '*'];

    private static bool TryValidateArchiveEntryPath(
        string rawName,
        bool allowTrailingDirectorySeparator,
        out string[] segments,
        out bool isDirectoryEntry,
        out string? failureReason)
    {
        segments = [];
        isDirectoryEntry = false;
        failureReason = null;

        if (string.IsNullOrWhiteSpace(rawName))
        {
            failureReason = "entry path is empty or whitespace";
            return false;
        }

        foreach (var c in rawName)
        {
            if (char.IsControl(c))
            {
                failureReason = "entry path contains a control character";
                return false;
            }

            if (c == ':')
            {
                failureReason = "entry path contains a colon";
                return false;
            }

            if (Array.IndexOf(ForbiddenArchivePathChars, c) >= 0)
            {
                failureReason = "entry path contains a forbidden path or wildcard character";
                return false;
            }
        }

        var normalized = rawName.Replace('\\', '/');
        if (normalized.StartsWith('/'))
        {
            failureReason = "entry path uses an absolute path";
            return false;
        }

        if (normalized.EndsWith('/'))
        {
            if (!allowTrailingDirectorySeparator)
            {
                failureReason = "entry path ends with a directory separator";
                return false;
            }

            isDirectoryEntry = true;
            normalized = normalized[..^1];
            if (normalized.Length == 0)
            {
                failureReason = "directory entry path is empty";
                return false;
            }
        }

        var parts = normalized.Split('/', StringSplitOptions.None);
        if (parts.Length == 0)
        {
            failureReason = "entry path contains no segments";
            return false;
        }

        foreach (var seg in parts)
        {
            if (seg.Length == 0)
            {
                failureReason = "entry path contains an empty segment";
                return false;
            }

            if (char.IsWhiteSpace(seg[0]) || char.IsWhiteSpace(seg[^1]) || seg[^1] == '.')
            {
                failureReason = "entry path segment has leading/trailing whitespace or a trailing dot";
                return false;
            }

            var trimmed = seg.Trim();
            if (trimmed.Length == 0 || trimmed is "." or "..")
            {
                failureReason = "entry path contains path traversal";
                return false;
            }

            var dotIndex = trimmed.IndexOf('.');
            var stem = (dotIndex >= 0 ? trimmed[..dotIndex] : trimmed).TrimEnd();
            if (stem.Length == 0 || BiosVendorIdentity.IsWindowsReservedDeviceName(stem))
            {
                failureReason = "entry path segment uses an invalid dot-only stem or Windows reserved device name";
                return false;
            }
        }

        segments = parts;
        return true;
    }

    private static bool TrySanitizeCabEntryName(string rawName, out string sanitized)
    {
        sanitized = "";
        if (!TryValidateArchiveEntryPath(
            rawName,
            allowTrailingDirectorySeparator: false,
            out var segments,
            out _,
            out _))
        {
            return false;
        }

        sanitized = string.Join('/', segments);
        return true;
    }

    private static void EnsureNoSymlinkOrReparseAncestors(string fullPath, string? entryName = null)
    {
        var current = Path.TrimEndingDirectorySeparator(Path.GetFullPath(fullPath));
        var visited = 0;
        while (!string.IsNullOrEmpty(current) && visited++ < 256)
        {
            EnsureNotSymlinkOrReparseDirectory(current, entryName);

            var parent = Path.GetDirectoryName(current);
            if (string.IsNullOrEmpty(parent) || string.Equals(parent, current, StringComparison.Ordinal))
                break;

            current = Path.TrimEndingDirectorySeparator(parent);
        }
    }

    private static bool AreAllAncestorsSafeWithinRoot(DirectoryInfo? dir, string fullRoot, StringComparison pathComparison)
    {
        var current = dir;
        var visited = 0;
        while (current is not null && visited++ < 256)
        {
            if (current.LinkTarget is not null
                || (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0))
            {
                return false;
            }

            var fullCurrent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(current.FullName));
            if (string.Equals(fullCurrent, fullRoot, pathComparison))
                return true;

            current = current.Parent;
        }

        return false;
    }

    private static void EnsureNotSymlinkOrReparseDirectory(string dirPath, string? entryName = null)
    {
        var di = new DirectoryInfo(dirPath);
        if (di.LinkTarget is not null || (di.Exists && (di.Attributes & FileAttributes.ReparsePoint) != 0))
        {
            var detail = entryName is null ? $"'{dirPath}'" : $"'{dirPath}' for ZIP entry '{entryName}'";
            throw new InvalidDataException($"Destination directory {detail} is a symbolic link or reparse point.");
        }
    }

    private static void EnsureNotSymlinkOrReparseFile(string filePath, string entryName)
    {
        var fi = new FileInfo(filePath);
        if (fi.LinkTarget is not null || (fi.Exists && (fi.Attributes & FileAttributes.ReparsePoint) != 0))
            throw new InvalidDataException($"Destination path '{filePath}' for ZIP entry '{entryName}' is a symbolic link or reparse point.");
    }

    private static string SanitizeTempPrefix(string? stagingHint)
    {
        if (string.IsNullOrWhiteSpace(stagingHint))
            return "cab";

        var sb = new StringBuilder(Math.Min(stagingHint.Length, 24));
        foreach (var c in stagingHint)
        {
            if (sb.Length >= 24)
                break;
            if (char.IsAsciiLetterOrDigit(c) || c == '-')
                sb.Append(c);
        }

        return sb.Length > 0 ? sb.ToString() : "cab";
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    /// <summary>
    /// Scans an executable (such as an HP SoftPaq self-extracting cabinet) for an embedded Microsoft Cabinet (<c>MSCF</c>)
    /// archive and extracts its entries into <paramref name="destinationDirectory"/> without launching the SFX executable.
    /// Uses native <c>expand.exe</c> on Windows (after validating CAB entry paths) and pure-C# extraction on non-Windows.
    /// </summary>
    public static bool TryExtractEmbeddedCabToDirectory(
        string exePath,
        string destinationDirectory,
        long maxExeBytes = 128L * 1024 * 1024,
        long maxDecompressedBytes = 256L * 1024 * 1024)
    {
        if (string.IsNullOrWhiteSpace(exePath) || string.IsNullOrWhiteSpace(destinationDirectory) || !File.Exists(exePath))
            return false;

        try
        {
            var info = new FileInfo(exePath);
            if (info.Length < 36 || info.Length > maxExeBytes)
                return false;

            var data = File.ReadAllBytes(exePath);
            var destRoot = Path.GetFullPath(destinationDirectory);
            var destRootWithSep = destRoot.EndsWith(Path.DirectorySeparatorChar)
                ? destRoot
                : destRoot + Path.DirectorySeparatorChar;

            for (var i = 0; i <= data.Length - 36; i++)
            {
                if (data[i] != (byte)'M' || data[i + 1] != (byte)'S' || data[i + 2] != (byte)'C' || data[i + 3] != (byte)'F')
                    continue;

                var span = data.AsSpan(i);
                var reserved1 = BinaryPrimitives.ReadUInt32LittleEndian(span[4..]);
                var cbCabinet = BinaryPrimitives.ReadUInt32LittleEndian(span[8..]);
                var reserved2 = BinaryPrimitives.ReadUInt32LittleEndian(span[12..]);
                var coffFiles = BinaryPrimitives.ReadUInt32LittleEndian(span[16..]);
                var versionMinor = span[24];
                var versionMajor = span[25];
                var cFolders = BinaryPrimitives.ReadUInt16LittleEndian(span[26..]);
                var cFiles = BinaryPrimitives.ReadUInt16LittleEndian(span[28..]);

                if (reserved1 != 0 || reserved2 != 0 || versionMajor != 1 || versionMinor != 3)
                    continue;
                if (cbCabinet < 36 || cbCabinet > (uint)(data.Length - i))
                    continue;
                if (coffFiles < 36 || coffFiles > cbCabinet)
                    continue;
                if (cFolders == 0 || cFolders > MaxCabFolders || cFiles == 0)
                    continue;

                var cabSlice = new byte[cbCabinet];
                Buffer.BlockCopy(data, i, cabSlice, 0, (int)cbCabinet);

                if (OperatingSystem.IsWindows()
                    && TryExtractCabWithWindowsExpand(cabSlice, coffFiles, cFiles, destRoot, destRootWithSep, maxDecompressedBytes))
                {
                    return true;
                }

                if (!TryExtractCabEntries(cabSlice, out var entries, maxDecompressedBytes) || entries.Count == 0)
                    continue;

                Directory.CreateDirectory(destRoot);
                var written = 0;
                foreach (var (relName, fileBytes) in entries)
                {
                    var normalizedRel = relName.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar).TrimStart(Path.DirectorySeparatorChar);
                    if (string.IsNullOrWhiteSpace(normalizedRel))
                        continue;

                    var fullPath = Path.GetFullPath(Path.Combine(destRoot, normalizedRel));
                    if (!fullPath.StartsWith(destRootWithSep, StringComparison.OrdinalIgnoreCase))
                        continue;

                    var parent = Path.GetDirectoryName(fullPath);
                    if (!string.IsNullOrEmpty(parent))
                        Directory.CreateDirectory(parent);

                    File.WriteAllBytes(fullPath, fileBytes);
                    written++;
                }

                if (written > 0)
                    return true;
            }
        }
        catch
        {
            // Fall back to SFX CLI extraction.
        }

        return false;
    }

    private static bool TryExtractCabWithWindowsExpand(
        byte[] cabSlice,
        uint coffFiles,
        ushort cFiles,
        string destRoot,
        string destRootWithSep,
        long maxDecompressedBytes)
    {
        string? tempCabPath = null;
        try
        {
            // Validate all CAB entry names (no traversal / ADS / reserved names) and pre-create any
            // subdirectories inside destRoot so Windows expand.exe can write nested paths cleanly.
            var span = cabSlice.AsSpan();
            var filePos = (int)coffFiles;
            long declaredTotal = 0;
            var subDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (var f = 0; f < cFiles; f++)
            {
                if ((long)filePos + 16 >= cabSlice.Length)
                    return false;

                var cbFile = BinaryPrimitives.ReadUInt32LittleEndian(span[filePos..]);
                var attribs = BinaryPrimitives.ReadUInt16LittleEndian(span[(filePos + 14)..]);
                filePos += 16;

                var searchLimit = Math.Min(cabSlice.Length, filePos + 1024);
                var nulIdx = -1;
                for (var k = filePos; k < searchLimit; k++)
                {
                    if (span[k] == 0)
                    {
                        nulIdx = k;
                        break;
                    }
                }
                if (nulIdx < 0)
                    return false;

                var nameBytes = span[filePos..nulIdx];
                var rawName = (attribs & CabAttribNameIsUtf) != 0
                    ? Encoding.UTF8.GetString(nameBytes)
                    : Encoding.Latin1.GetString(nameBytes);
                filePos = nulIdx + 1;

                if (!TrySanitizeCabEntryName(rawName, out var sanitizedName))
                    return false;

                declaredTotal += cbFile;
                if (declaredTotal > maxDecompressedBytes)
                    return false;

                var normalizedRel = sanitizedName.Replace('\\', Path.DirectorySeparatorChar).Replace('/', Path.DirectorySeparatorChar).TrimStart(Path.DirectorySeparatorChar);
                var fullPath = Path.GetFullPath(Path.Combine(destRoot, normalizedRel));
                if (!fullPath.StartsWith(destRootWithSep, StringComparison.OrdinalIgnoreCase))
                    return false;

                var parent = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(parent) && !string.Equals(parent, destRoot, StringComparison.OrdinalIgnoreCase))
                    subDirs.Add(parent);
            }

            Directory.CreateDirectory(destRoot);
            foreach (var dir in subDirs)
                Directory.CreateDirectory(dir);

            var parentDir = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(destRoot)) ?? Path.GetTempPath();
            tempCabPath = Path.Combine(parentDir, $"embedded-{Guid.NewGuid():N}.cab");
            File.WriteAllBytes(tempCabPath, cabSlice);

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = SystemCommandRunner.SystemTool("expand.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("-F:*");
            psi.ArgumentList.Add(tempCabPath);
            psi.ArgumentList.Add(destRoot);

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc is null)
                return false;

            // Drain stdout/stderr asynchronously to avoid pipe buffer deadlocks on large cabinets.
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(60_000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return false;
            }

            _ = stdoutTask.Wait(2_000);
            _ = stderrTask.Wait(2_000);
            return proc.ExitCode == 0 && Directory.EnumerateFiles(destRoot, "*", SearchOption.AllDirectories).Any();
        }
        catch
        {
            return false;
        }
        finally
        {
            if (tempCabPath is not null)
                TryDeleteFile(tempCabPath);
        }
    }

    private readonly record struct CabFolder(uint CoffCabStart, ushort CCFData, int CompressionMethod, int WindowBits);
    private readonly record struct CabFileEntry(string SanitizedName, uint CbFile, uint UoffFolderStart);
}
