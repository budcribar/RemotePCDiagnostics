namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Vendor-independent BIOS update orchestrator. Discovers all registered <see cref="IBiosUpdateProvider"/> implementations,
/// resolves the highest-priority matching provider for the local PC, and enforces approval and safety gates before installation.
/// </summary>
public sealed class BiosUpdateService : IBiosUpdateService
{
    private readonly IBiosSystemProbe _systemProbe;
    private readonly IBiosInstallSafetyProbe _safetyProbe;
    private readonly ILogger? _log;

    public BiosUpdateService(
        IBiosSystemProbe systemProbe,
        IBiosInstallSafetyProbe safetyProbe,
        IEnumerable<IBiosUpdateProvider> providers,
        ILogger? log = null)
    {
        _systemProbe = systemProbe ?? throw new ArgumentNullException(nameof(systemProbe));
        _safetyProbe = safetyProbe ?? throw new ArgumentNullException(nameof(safetyProbe));
        _log = log;
        Providers = (providers ?? [])
            .OrderByDescending(p => p.Priority)
            .ThenBy(p => p.VendorId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public IReadOnlyList<IBiosUpdateProvider> Providers { get; }

    public IBiosUpdateProvider? ResolveProvider(BiosSystemIdentity system)
    {
        ArgumentNullException.ThrowIfNull(system);
        foreach (var provider in Providers)
        {
            if (SafeCanHandle(provider, system))
                return provider;
        }
        return null;
    }

    private bool SafeCanHandle(IBiosUpdateProvider provider, BiosSystemIdentity system)
    {
        try
        {
            return provider.CanHandle(system);
        }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS provider '{provider.VendorId}' threw in CanHandle: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// The provider that installs <paramref name="request"/>: the one that found the target (<see cref="BiosLatestInfo.ProviderId"/>)
    /// when it handles this PC, else this PC's own provider (which then checks the target against its own URL allowlist).
    /// The safety check and the install both use this, so they always agree on the provider's capabilities.
    /// </summary>
    private IBiosUpdateProvider? SelectInstallProvider(BiosInstallRequest request)
    {
        var resolved = ResolveProvider(request.System);
        var wanted = request.Target.ProviderId;
        if (resolved is null || string.IsNullOrWhiteSpace(wanted) || string.Equals(wanted, resolved.VendorId, StringComparison.OrdinalIgnoreCase))
            return resolved;

        return Providers.FirstOrDefault(p =>
            string.Equals(p.VendorId, wanted, StringComparison.OrdinalIgnoreCase) && SafeCanHandle(p, request.System)) ?? resolved;
    }

    public async Task<BiosCurrentInfo> GetCurrentVersionAsync(CancellationToken ct = default)
    {
        var system = await _systemProbe.ProbeAsync(ct).ConfigureAwait(false);
        var provider = ResolveProvider(system);
        if (provider is null)
            return system.CurrentBios;

        try
        {
            return await provider.GetCurrentVersionAsync(system, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS provider '{provider.VendorId}' failed to read current version; falling back to SMBIOS: {ex.Message}");
            return system.CurrentBios with { ProviderId = provider.VendorId };
        }
    }

    public async Task<BiosUpdateCheckOutcome> CheckForUpdateAsync(CancellationToken ct = default)
    {
        var system = await _systemProbe.ProbeAsync(ct).ConfigureAwait(false);
        var provider = ResolveProvider(system);
        if (provider is null)
        {
            var maker = string.IsNullOrWhiteSpace(system.Manufacturer) ? "this manufacturer" : system.Manufacturer;
            return new BiosUpdateCheckOutcome(
                system,
                system.CurrentBios,
                BiosLatestInfo.Unsupported("none", $"No BIOS update provider is registered for {maker}."),
                ProviderId: null,
                ProviderDisplayName: null);
        }

        BiosCurrentInfo current;
        try
        {
            current = await provider.GetCurrentVersionAsync(system, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS provider '{provider.VendorId}' failed to read current version; using SMBIOS: {ex.Message}");
            current = system.CurrentBios with { ProviderId = provider.VendorId };
        }

        if (!provider.Capabilities.CanCheckLatest)
        {
            return new BiosUpdateCheckOutcome(
                system,
                current,
                BiosLatestInfo.Unsupported(provider.VendorId, $"{provider.DisplayName} BIOS provider does not support checking for latest versions."),
                provider.VendorId,
                provider.DisplayName);
        }

        try
        {
            var latest = await provider.GetLatestVersionAsync(system, current, ct).ConfigureAwait(false);
            return new BiosUpdateCheckOutcome(system, current, latest, provider.VendorId, provider.DisplayName);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS provider '{provider.VendorId}' failed during update check: {ex.Message}");
            return new BiosUpdateCheckOutcome(
                system,
                current,
                BiosLatestInfo.Failed(provider.VendorId, $"{provider.DisplayName} BIOS update check failed: {ex.Message}"),
                provider.VendorId,
                provider.DisplayName);
        }
    }

    public async Task<BiosSafetyCheckResult> EvaluateInstallSafetyAsync(BiosInstallRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var provider = SelectInstallProvider(request);
        var capabilities = provider?.Capabilities ?? new BiosProviderCapabilities();
        var snapshot = await _safetyProbe.ProbeAsync(ct).ConfigureAwait(false);
        return BiosInstallSafetyEvaluator.Evaluate(snapshot, request, capabilities);
    }

    public async Task<BiosInstallResult> InstallUpdateAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var prev = request.Current.Version;
        var target = request.Target.LatestVersion;

        if (!request.Approved)
            return BiosInstallResult.Refused("Explicit operator approval is required before installing a BIOS update.", prev, target);

        if (request.Target.Status == BiosCheckStatus.UpToDate)
            return new BiosInstallResult(true, BiosInstallStatus.AlreadyUpToDate, PreviousVersion: prev, TargetVersion: target, Message: "BIOS is already up to date.");

        if (request.Target.Status != BiosCheckStatus.UpdateAvailable)
            return BiosInstallResult.Refused(request.Target.Message ?? "No installable BIOS update is available.", prev, target);

        var provider = SelectInstallProvider(request);
        if (provider is null)
            return BiosInstallResult.Unsupported("No BIOS update provider is registered for this hardware.", prev, target);

        if (!provider.Capabilities.CanInstall)
            return BiosInstallResult.Unsupported($"{provider.DisplayName} BIOS provider does not support automated installation.", prev, target);

        progress?.Report(new BiosInstallProgress(BiosInstallStage.CheckingPrerequisites, 0, "Checking power, BitLocker, and elevation prerequisites…"));
        var snapshot = await _safetyProbe.ProbeAsync(ct).ConfigureAwait(false);
        var safety = BiosInstallSafetyEvaluator.Evaluate(snapshot, request, provider.Capabilities);
        if (!safety.Passed)
        {
            var reason = string.Join(" ", safety.BlockingReasons);
            _log?.Warn($"BIOS update blocked by prerequisites ({provider.VendorId}, {prev} -> {target}): {reason}");
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, reason));
            return BiosInstallResult.Blocked(reason, prev, target);
        }

        // Lets the provider continue when BitLocker suspension doesn't apply only if BitLocker is known to be off.
        request = request with { BitLockerKnownOff = snapshot.BitLockerActive == false || snapshot.BitLockerSuspended == true };

        var approver = string.IsNullOrWhiteSpace(request.ApprovedBy) ? "operator" : request.ApprovedBy.Trim();
        _log?.Info($"Starting BIOS update via '{provider.VendorId}' ({prev} -> {target}, approvedBy={approver}, allowReboot={request.AllowReboot}, suspendBitLocker={request.SuspendBitLocker}).");

        try
        {
            var result = await provider.InstallAsync(request, progress, ct).ConfigureAwait(false);
            _log?.Info($"BIOS update finished via '{provider.VendorId}': status={result.Status}, succeeded={result.Succeeded}, requiresReboot={result.RequiresReboot}, exitCode={result.ExitCode}.");
            return result;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Error($"BIOS update failed via '{provider.VendorId}': {ex.Message}");
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, ex.Message));
            return BiosInstallResult.Failed($"{provider.DisplayName} BIOS installation failed: {ex.Message}", prev, target);
        }
    }
}
