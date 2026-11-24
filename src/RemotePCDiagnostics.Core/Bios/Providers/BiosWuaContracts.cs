namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Metadata for a pending firmware/BIOS update discovered through the Windows Update Agent (WUA) COM API.
/// </summary>
public sealed record BiosWuaFirmwareUpdate(
    string UpdateId,
    string Title,
    string? Version,
    DateOnly? ReleaseDate,
    long? SizeBytes,
    BiosUpdateSeverity Severity,
    bool RebootRequired,
    string? DriverClass = null,
    string? DriverModel = null,
    IReadOnlyList<string>? Categories = null);

/// <summary>
/// Outcome of installing a specific Windows Update firmware capsule by its <see cref="Guid"/> update identifier.
/// </summary>
public sealed record BiosWuaInstallOutcome(
    bool Succeeded,
    int ResultCode,
    bool RebootRequired,
    string Message);

/// <summary>
/// Abstraction over pure-C# Windows Update Agent COM (<c>Microsoft.Update.Session</c>) for offline unit testing.
/// </summary>
public interface IBiosWindowsUpdateClient
{
    Task<IReadOnlyList<BiosWuaFirmwareUpdate>> SearchPendingFirmwareUpdatesAsync(CancellationToken ct = default);
    Task<BiosWuaInstallOutcome> InstallUpdateAsync(Guid updateId, CancellationToken ct = default);

    /// <summary>
    /// Searches Windows Update's local cache (<paramref name="online"/> false, quick) or the update service itself (true, can take minutes).
    /// The default searches the way <see cref="SearchPendingFirmwareUpdatesAsync(CancellationToken)"/> does.
    /// </summary>
    Task<IReadOnlyList<BiosWuaFirmwareUpdate>> SearchPendingFirmwareUpdatesAsync(bool online, CancellationToken ct) =>
        SearchPendingFirmwareUpdatesAsync(ct);

    /// <summary>When Windows Update last finished a scan (UTC), or null when Windows doesn't say. The local cache is only as new as this.</summary>
    Task<DateTimeOffset?> GetLastSuccessfulScanUtcAsync(CancellationToken ct = default) => Task.FromResult<DateTimeOffset?>(null);
}
