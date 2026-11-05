namespace RemotePCDiagnostics.Core;

/// <summary>
/// A module that only exists on PCs with the right hardware (e.g. the NPU test). Until <see cref="DetectPresenceAsync"/> has found the
/// hardware it is hidden: <see cref="DiagnosticsService.Modules"/> leaves it out, so no list, card, link or run can reach it. It stays in
/// <see cref="DiagnosticsService.Catalog"/> as <see cref="ModuleState.NotPresent"/>, so History can still name its old results.
/// </summary>
public interface IHardwareGatedModule : IDiagnosticModule
{
    /// <summary>True once detection found the hardware. False before detection, when absent, or when detection failed.</summary>
    bool IsPresent { get; }
    /// <summary>Detects once (cached); must never throw (failure = not present).</summary>
    Task<bool> DetectPresenceAsync(CancellationToken ct = default);
}
