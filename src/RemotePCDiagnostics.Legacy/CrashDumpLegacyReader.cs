using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Legacy;

/// <summary>
/// Lists the crash dump folders itself (<see cref="BsodHistoryModule.ReadSystemMinidumps"/>, <see cref="GraphicsDriverCrashes.ReadLiveKernelReports"/>).
/// The folders are for administrators only, so without the Agent the Store edition finds no dumps unless it runs with administrator rights.
/// </summary>
public sealed class FileCrashDumpSource : ICrashDumpSource
{
    public Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct) => Task.Run(Read(BsodHistoryModule.ReadSystemMinidumps), ct);

    public Task<IReadOnlyList<MinidumpFile>> ReadLiveKernelReportsAsync(CancellationToken ct) => Task.Run(Read(GraphicsDriverCrashes.ReadLiveKernelReports), ct);

    /// <summary>A folder this user can't open counts as no dumps.</summary>
    private static Func<IReadOnlyList<MinidumpFile>> Read(Func<IReadOnlyList<MinidumpFile>> list) => () =>
    {
        try { return list(); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException) { return []; }
    };
}
