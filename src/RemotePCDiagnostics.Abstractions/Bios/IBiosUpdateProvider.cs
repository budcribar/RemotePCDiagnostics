namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Pluggable vendor-specific BIOS/UEFI firmware provider (for example HP, Dell, Lenovo, ASUS, Acer, MSI, Microsoft Surface, or Windows Update).
/// Register implementations in DI as <see cref="IBiosUpdateProvider"/> so <see cref="IBiosUpdateService"/> can discover and select the best match automatically.
/// </summary>
public interface IBiosUpdateProvider
{
    /// <summary>Stable lowercase identifier for this provider (for example <c>"hp"</c>, <c>"dell"</c>, <c>"lenovo"</c>, <c>"windows-update"</c>).</summary>
    string VendorId { get; }

    /// <summary>Human-readable vendor/provider name shown in diagnostics output (for example <c>"HP"</c>, <c>"Dell"</c>, <c>"Lenovo"</c>).</summary>
    string DisplayName { get; }

    /// <summary>
    /// Selection priority when multiple providers match the same PC. Higher wins.
    /// OEM-specific providers should use <c>100</c> (default); generic fallbacks such as Windows Update UEFI capsules should use a lower value (e.g. <c>10</c>).
    /// </summary>
    int Priority => 100;

    /// <summary>Capabilities supported by this provider (version check, install, elevation, reboot, internet).</summary>
    BiosProviderCapabilities Capabilities { get; }

    /// <summary>
    /// Fast, offline check returning <c>true</c> when this provider can service the PC described by <paramref name="system"/>.
    /// Must not make network calls or throw.
    /// </summary>
    bool CanHandle(BiosSystemIdentity system);

    /// <summary>
    /// Returns the currently installed BIOS version normalized for this vendor's catalog.
    /// Default implementation returns <see cref="BiosSystemIdentity.CurrentBios"/> tagged with <see cref="VendorId"/>;
    /// override when the vendor exposes a richer version/family identifier (e.g. HP BIOS family or Lenovo version prefix).
    /// </summary>
    Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default) =>
        Task.FromResult(system.CurrentBios with { ProviderId = VendorId });

    /// <summary>
    /// Queries the vendor's catalog/tool to determine the latest BIOS release for <paramref name="system"/>
    /// and compares it against <paramref name="current"/>.
    /// </summary>
    Task<BiosLatestInfo> GetLatestVersionAsync(BiosSystemIdentity system, BiosCurrentInfo current, CancellationToken ct = default);

    /// <summary>
    /// Downloads, verifies, and stages/installs the BIOS update described by <paramref name="request"/>.
    /// Callers should invoke this through <see cref="IBiosUpdateService.InstallUpdateAsync"/>, which enforces approval and pre-flash safety gates.
    /// </summary>
    Task<BiosInstallResult> InstallAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress = null,
        CancellationToken ct = default) =>
        Task.FromResult(BiosInstallResult.Unsupported(
            $"{DisplayName} BIOS provider does not support automated installation.",
            request.Current.Version,
            request.Target.LatestVersion));
}

/// <summary>Probes the local PC's vendor-independent hardware and SMBIOS identity.</summary>
public interface IBiosSystemProbe
{
    Task<BiosSystemIdentity> ProbeAsync(CancellationToken ct = default);
}

/// <summary>Probes pre-flash safety prerequisites (AC power, battery reserve, BitLocker, elevation, pending reboot).</summary>
public interface IBiosInstallSafetyProbe
{
    Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default);
}

/// <summary>
/// Vendor-independent facade that discovers registered <see cref="IBiosUpdateProvider"/> implementations,
/// resolves the best match for the current PC, and enforces pre-flash safety gates on install.
/// </summary>
public interface IBiosUpdateService
{
    /// <summary>All registered providers, ordered by descending <see cref="IBiosUpdateProvider.Priority"/>.</summary>
    IReadOnlyList<IBiosUpdateProvider> Providers { get; }

    /// <summary>Selects the highest-priority provider that handles <paramref name="system"/>, or <c>null</c> when none matches.</summary>
    IBiosUpdateProvider? ResolveProvider(BiosSystemIdentity system);

    /// <summary>Reads the current BIOS version using the matching provider (or SMBIOS fallback when no vendor provider matches).</summary>
    Task<BiosCurrentInfo> GetCurrentVersionAsync(CancellationToken ct = default);

    /// <summary>Probes the system, reads the current BIOS version, and checks the matching provider for updates.</summary>
    Task<BiosUpdateCheckOutcome> CheckForUpdateAsync(CancellationToken ct = default);

    /// <summary>Evaluates pre-flash safety prerequisites without modifying the PC.</summary>
    Task<BiosSafetyCheckResult> EvaluateInstallSafetyAsync(BiosInstallRequest request, CancellationToken ct = default);

    /// <summary>Validates approval and pre-flash safety prerequisites, then delegates installation to the matching provider.</summary>
    Task<BiosInstallResult> InstallUpdateAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress = null,
        CancellationToken ct = default);
}
