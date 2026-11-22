using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Where Crashes &amp; unexpected restarts finds the crash dump files: blue screen dumps (<c>C:\Windows\Minidump</c>, <c>C:\Windows\MEMORY.DMP</c>)
/// and graphics hang dumps (<c>C:\Windows\LiveKernelReports</c>). Both folders are for administrators only, so the app reads them through
/// the Agent (<see cref="WmiCrashDumpSource"/>); the Store edition, which may have no Agent, also has the legacy reader that lists them
/// itself (RemotePCDiagnostics.Legacy), which only works when the app has administrator rights.
/// </summary>
public interface ICrashDumpSource
{
    /// <summary>Blue screen dumps, newest first; empty when there are none or they couldn't be listed.</summary>
    Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct);

    /// <summary>Graphics hang dumps: WATCHDOG dumps and the display drivers' own folders, newest first.</summary>
    Task<IReadOnlyList<MinidumpFile>> ReadLiveKernelReportsAsync(CancellationToken ct);
}

/// <summary>Lists the dump files with WMI (<c>CIM_DataFile</c>, <c>Win32_Directory</c>), through the Agent.</summary>
/// <param name="windowsDirectory">The Windows folder; the PC's own when null (C:\Windows off Windows, for replay tests).</param>
public sealed class WmiCrashDumpSource(IWmiSource wmi, string? windowsDirectory = null) : ICrashDumpSource
{
    public const string Cimv2 = @"root\cimv2";
    public const int MaxFiles = 50;

    private string WindowsDirectory => windowsDirectory
        ?? (Environment.GetFolderPath(Environment.SpecialFolder.Windows) is { Length: > 0 } w ? w : @"C:\Windows");

    /// <summary>The <c>*.<paramref name="extension"/></c> files directly in <paramref name="folder"/> (a full path, such as C:\Windows\Minidump).</summary>
    public static string FilesSql(string folder, string extension)
    {
        var (drive, path) = Split(folder);
        return $"SELECT Name, FileSize, LastModified FROM CIM_DataFile WHERE Drive = '{drive}' AND Path = '{Escape(path)}' AND Extension = '{Escape(extension)}'";
    }

    /// <summary>One file by its full path.</summary>
    public static string FileSql(string file) => $"SELECT Name, FileSize, LastModified FROM CIM_DataFile WHERE Name = '{Escape(file)}'";

    /// <summary>The folders directly in <paramref name="folder"/>.</summary>
    public static string FoldersSql(string folder)
    {
        var (drive, path) = Split(folder);
        return $"SELECT Name FROM Win32_Directory WHERE Drive = '{drive}' AND Path = '{Escape(path)}'";
    }

    public string MinidumpFolder => Join(WindowsDirectory, "Minidump");
    public string MemoryDump => Join(WindowsDirectory, "MEMORY.DMP");
    public string LiveKernelReportsFolder => Join(WindowsDirectory, "LiveKernelReports");

    public async Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct)
    {
        var dumps = (await FilesAsync(FilesSql(MinidumpFolder, "dmp"), ct).ConfigureAwait(false)).OrderByDescending(f => f.Created).Take(MaxFiles);
        var memory = await FilesAsync(FileSql(MemoryDump), ct).ConfigureAwait(false);
        return dumps.Concat(memory).OrderByDescending(f => f.Created).ToList();
    }

    public async Task<IReadOnlyList<MinidumpFile>> ReadLiveKernelReportsAsync(CancellationToken ct)
    {
        var root = LiveKernelReportsFolder;
        var files = (await FilesAsync(FilesSql(root, "dmp"), ct).ConfigureAwait(false))
            .Where(f => f.FileName.StartsWith("WATCHDOG", StringComparison.OrdinalIgnoreCase)).ToList();
        var folders = await wmi.QueryAsync(Cimv2, FoldersSql(root), ct).ConfigureAwait(false);
        foreach (var name in (folders.Rows ?? []).Select(r => LastPart(r.Str("Name"))))
            if (name.Equals("WATCHDOG", StringComparison.OrdinalIgnoreCase) || GraphicsDriverCrashes.DriverService(name) is not null)
                files.AddRange(await FilesAsync(FilesSql(Join(root, name), "dmp"), ct).ConfigureAwait(false));
        return files.OrderByDescending(f => f.Created).ToList();
    }

    private async Task<IEnumerable<MinidumpFile>> FilesAsync(string sql, CancellationToken ct)
    {
        var q = await wmi.QueryAsync(Cimv2, sql, ct).ConfigureAwait(false);
        return (q.Rows ?? []).Select(File).OfType<MinidumpFile>();
    }

    /// <summary>A CIM_DataFile row as a dump file; null without a name or a time.</summary>
    public static MinidumpFile? File(WmiRow r)
    {
        var path = r.Str("Name");
        if (path.Length == 0 || CimDateTime.Parse(r.Str("LastModified")) is not { } modified) return null;
        return new(LastPart(path), modified.ToUniversalTime(), r.Long("FileSize") ?? 0, path);
    }

    /// <summary>"C:\Windows\Minidump" as WMI's drive ("C:") and path ("\Windows\Minidump\").</summary>
    private static (string Drive, string Path) Split(string folder)
    {
        var f = folder.TrimEnd('\\');
        return f.Length >= 2 && f[1] == ':' ? (f[..2], f[2..] + "\\") : ("C:", "\\" + f.TrimStart('\\') + "\\");
    }

    /// <summary>A WQL string literal's contents: backslashes and quotes escaped.</summary>
    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("'", "\\'");

    private static string Join(string folder, string name) => folder.TrimEnd('\\') + "\\" + name;

    private static string LastPart(string path) => path.TrimEnd('\\')[(path.TrimEnd('\\').LastIndexOf('\\') + 1)..];
}

/// <inheritdoc cref="AgentOrFallbackBatteryPowerSource"/>
public sealed class AgentOrFallbackCrashDumpSource(Session.IElevatedCommandBridge agent, ICrashDumpSource withAgent, ICrashDumpSource fallback) : ICrashDumpSource
{
    private ICrashDumpSource Current => agent.IsConnected ? withAgent : fallback;
    public Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct) => Current.ReadMinidumpsAsync(ct);
    public Task<IReadOnlyList<MinidumpFile>> ReadLiveKernelReportsAsync(CancellationToken ct) => Current.ReadLiveKernelReportsAsync(ct);
}
