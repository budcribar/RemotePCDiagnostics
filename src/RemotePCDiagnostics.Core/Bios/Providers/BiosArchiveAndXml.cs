using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Bios;

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
    /// absolute/drive paths, Unix symlinks, and decompression bombs.
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
        EnsureNotSymlinkOrReparseDirectory(fullRoot);
        Directory.CreateDirectory(fullRoot);
        EnsureNotSymlinkOrReparseDirectory(fullRoot);
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
            foreach (var entry in archive.Entries)
            {
                var unixMode = (entry.ExternalAttributes >> 16) & 0xF000;
                if (unixMode == 0xA000)
                    throw new InvalidDataException($"ZIP entry '{entry.FullName}' is a symbolic link and is not allowed.");

                var normalized = entry.FullName.Replace('\\', '/');
                if (normalized.Contains('\0', StringComparison.Ordinal))
                    throw new InvalidDataException($"ZIP entry '{entry.FullName}' contains a NUL character.");

                if (normalized.StartsWith('/'))
                    throw new InvalidDataException($"ZIP entry '{entry.FullName}' uses an absolute path.");

                if (normalized.Length >= 2 && char.IsAsciiLetter(normalized[0]) && normalized[1] == ':')
                    throw new InvalidDataException($"ZIP entry '{entry.FullName}' uses a drive-qualified path.");

                var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
                if (segments.Any(static s => s is ".."))
                    throw new InvalidDataException($"ZIP entry '{entry.FullName}' contains path traversal.");

                if (normalized.EndsWith('/') || string.IsNullOrEmpty(entry.Name) || segments.Length == 0)
                    continue;

                var relative = Path.Combine(segments);
                var destPath = Path.GetFullPath(Path.Combine(fullRoot, relative));
                if (!destPath.StartsWith(rootWithSep, pathComparison))
                    throw new InvalidDataException($"ZIP entry '{entry.FullName}' escapes the destination directory.");

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
    /// Pure-C# Microsoft Cabinet (<c>MSCF</c>) reader supporting <c>TYPE_NONE</c> (0) and <c>TYPE_MSZIP</c> (1).
    /// Returns <c>false</c> cleanly (never throws) on unsupported compression (e.g., LZX), corrupt/truncated archives,
    /// path traversal entries, or archives exceeding <paramref name="maxTotalBytes"/>.
    /// </summary>
    public static bool TryExtractCabEntries(
        byte[] cabBytes,
        out IReadOnlyDictionary<string, byte[]> entries,
        long maxTotalBytes = DefaultMaxDecompressedBytes)
    {
        var empty = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        entries = empty;

        if (cabBytes is null || cabBytes.Length < 36 || maxTotalBytes <= 0)
            return false;

        try
        {
            var span = cabBytes.AsSpan();
            if (span[0] != (byte)'M' || span[1] != (byte)'S' || span[2] != (byte)'C' || span[3] != (byte)'F')
                return false;

            var cbCabinet = BinaryPrimitives.ReadUInt32LittleEndian(span[8..]);
            if (cbCabinet < 36 || cbCabinet > (uint)cabBytes.Length)
                return false;

            var coffFiles = BinaryPrimitives.ReadUInt32LittleEndian(span[16..]);
            if (coffFiles < 36 || coffFiles > cbCabinet)
                return false;

            var versionMinor = span[24];
            var versionMajor = span[25];
            if (versionMajor != 1 || versionMinor != 3)
                return false;

            var cFolders = BinaryPrimitives.ReadUInt16LittleEndian(span[26..]);
            var cFiles = BinaryPrimitives.ReadUInt16LittleEndian(span[28..]);
            var flags = BinaryPrimitives.ReadUInt16LittleEndian(span[30..]);

            if (cFolders > MaxCabFolders)
                return false;

            var pos = 36;
            ushort cbCFHeader = 0;
            byte cbCFFolder = 0;
            byte cbCFData = 0;

            if ((flags & CabFlagReservePresent) != 0)
            {
                if (pos + 4 > cbCabinet)
                    return false;

                cbCFHeader = BinaryPrimitives.ReadUInt16LittleEndian(span[pos..]);
                cbCFFolder = span[pos + 2];
                cbCFData = span[pos + 3];
                pos += 4;

                if (cbCFHeader > MaxCabHeaderReserve || (long)pos + cbCFHeader > cbCabinet)
                    return false;

                pos += cbCFHeader;
            }

            if ((flags & CabFlagPrevCabinet) != 0)
            {
                if (!SkipNullTerminatedString(span, (int)cbCabinet, ref pos)
                    || !SkipNullTerminatedString(span, (int)cbCabinet, ref pos))
                    return false;
            }

            if ((flags & CabFlagNextCabinet) != 0)
            {
                if (!SkipNullTerminatedString(span, (int)cbCabinet, ref pos)
                    || !SkipNullTerminatedString(span, (int)cbCabinet, ref pos))
                    return false;
            }

            var folderRecordSize = 8 + cbCFFolder;
            if ((long)pos + (long)cFolders * folderRecordSize > cbCabinet)
                return false;

            if (cFiles == 0)
                return true;

            if (cFolders == 0)
                return false;

            var folders = new CabFolder[cFolders];
            for (var i = 0; i < cFolders; i++)
            {
                var coffCabStart = BinaryPrimitives.ReadUInt32LittleEndian(span[pos..]);
                var cCFData = BinaryPrimitives.ReadUInt16LittleEndian(span[(pos + 4)..]);
                var typeCompress = BinaryPrimitives.ReadUInt16LittleEndian(span[(pos + 6)..]);
                folders[i] = new CabFolder(coffCabStart, cCFData, typeCompress & 0x000F);
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
                    return false;

                var cbFile = BinaryPrimitives.ReadUInt32LittleEndian(span[filePos..]);
                var uoffFolderStart = BinaryPrimitives.ReadUInt32LittleEndian(span[(filePos + 4)..]);
                var iFolder = BinaryPrimitives.ReadUInt16LittleEndian(span[(filePos + 8)..]);
                var attribs = BinaryPrimitives.ReadUInt16LittleEndian(span[(filePos + 14)..]);
                filePos += 16;

                if (iFolder >= 0xFFFD || iFolder >= cFolders)
                    return false;

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
                    return false;

                var nameBytes = span[filePos..nulIdx];
                var rawName = (attribs & CabAttribNameIsUtf) != 0
                    ? Encoding.UTF8.GetString(nameBytes)
                    : Encoding.Latin1.GetString(nameBytes);
                filePos = nulIdx + 1;

                if (!TrySanitizeCabEntryName(rawName, out var sanitizedName))
                    return false;

                declaredTotal += cbFile;
                if (declaredTotal > maxTotalBytes || (long)uoffFolderStart + cbFile > maxTotalBytes)
                    return false;

                folderFiles[iFolder].Add(new CabFileEntry(sanitizedName, cbFile, uoffFolderStart));
            }

            var result = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            long cumulativeUncomp = 0;

            for (var f = 0; f < cFolders; f++)
            {
                if (folderFiles[f].Count == 0)
                    continue;

                var folder = folders[f];
                if (folder.CompressionMethod is not (0 or 1))
                    return false;

                long dataPos = folder.CoffCabStart;
                using var folderStream = new MemoryStream();

                for (var b = 0; b < folder.CCFData; b++)
                {
                    if (dataPos < 0 || dataPos + 8 + cbCFData > cbCabinet)
                        return false;

                    var cbData = BinaryPrimitives.ReadUInt16LittleEndian(span[(int)(dataPos + 4)..]);
                    var cbUncomp = BinaryPrimitives.ReadUInt16LittleEndian(span[(int)(dataPos + 6)..]);
                    var payloadOffset = dataPos + 8 + cbCFData;

                    if (payloadOffset + cbData > cbCabinet)
                        return false;

                    if (cumulativeUncomp + cbUncomp > maxTotalBytes)
                        return false;

                    if (folder.CompressionMethod == 0)
                    {
                        if (cbData != cbUncomp)
                            return false;

                        folderStream.Write(cabBytes, (int)payloadOffset, cbData);
                        cumulativeUncomp += cbUncomp;
                    }
                    else
                    {
                        if (cbData < 2 || cabBytes[payloadOffset] != (byte)'C' || cabBytes[payloadOffset + 1] != (byte)'K')
                            return false;

                        if (!TryDecompressMsZipBlock(cabBytes, (int)(payloadOffset + 2), cbData - 2, cbUncomp, out var blockBuf))
                            return false;

                        folderStream.Write(blockBuf, 0, cbUncomp);
                        cumulativeUncomp += cbUncomp;
                    }

                    dataPos = payloadOffset + cbData;
                }

                var folderData = folderStream.ToArray();
                foreach (var file in folderFiles[f])
                {
                    if ((long)file.UoffFolderStart + file.CbFile > folderData.Length)
                        return false;

                    var content = new byte[file.CbFile];
                    Buffer.BlockCopy(folderData, (int)file.UoffFolderStart, content, 0, (int)file.CbFile);
                    result[file.SanitizedName] = content;
                }
            }

            entries = result;
            return true;
        }
        catch
        {
            entries = empty;
            return false;
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

        if (TryExtractCabEntries(payload, out var entries, maxDecompressedBytes))
        {
            var xmlKey = entries.Keys
                .Where(static k => k.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                .OrderBy(static k => k, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();

            return xmlKey is null ? null : DecodeXmlBytes(entries[xmlKey]);
        }

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

            var fi = new FileInfo(xmlFile);
            if (fi.LinkTarget is not null || fi.Length <= 0 || fi.Length > maxDecompressedBytes)
                return null;

            var bytes = await File.ReadAllBytesAsync(xmlFile, ct).ConfigureAwait(false);
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

    private static bool TrySanitizeCabEntryName(string rawName, out string sanitized)
    {
        sanitized = "";
        if (string.IsNullOrWhiteSpace(rawName) || rawName.Contains('\0', StringComparison.Ordinal))
            return false;

        var normalized = rawName.Replace('\\', '/');
        if (normalized.StartsWith('/'))
            return false;

        if (normalized.Length >= 2 && char.IsAsciiLetter(normalized[0]) && normalized[1] == ':')
            return false;

        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || segments.Any(static s => s is "." or ".."))
            return false;

        sanitized = string.Join('/', segments);
        return true;
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

    private readonly record struct CabFolder(uint CoffCabStart, ushort CCFData, int CompressionMethod);
    private readonly record struct CabFileEntry(string SanitizedName, uint CbFile, uint UoffFolderStart);
}
