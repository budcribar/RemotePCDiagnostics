namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Vendor-independent pre-flash safety evaluator applied by <see cref="BiosUpdateService"/> before any
/// <see cref="IBiosUpdateProvider.InstallAsync"/> implementation is invoked.
/// </summary>
public static class BiosInstallSafetyEvaluator
{
    /// <summary>Minimum battery charge required on battery-equipped PCs even while AC power is connected.</summary>
    public const int MinBatteryPercent = 30;

    public static BiosSafetyCheckResult Evaluate(
        BiosSafetySnapshot snapshot,
        BiosInstallRequest request,
        BiosProviderCapabilities capabilities)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(capabilities);

        var blockers = new List<string>();
        var warnings = new List<string>();

        if (!request.Approved)
            blockers.Add("Explicit operator approval is required before installing a BIOS update.");

        if (capabilities.RequiresElevation && !snapshot.HasElevation)
            blockers.Add("Administrator rights (or the elevated Agent service) are required to install a BIOS update.");

        if (snapshot.HasBattery == true)
        {
            if (snapshot.OnAcPower == false)
                blockers.Add("AC power must be connected before installing a BIOS update.");
            else if (snapshot.OnAcPower is null)
                warnings.Add("Could not confirm AC power state; ensure the power adapter is plugged in before restarting.");

            if (snapshot.BatteryPercent is int pct && pct < MinBatteryPercent)
                blockers.Add($"Battery charge is {pct}%; at least {MinBatteryPercent}% is required before installing a BIOS update.");
        }

        if (snapshot.BitLockerActive == true && snapshot.BitLockerSuspended != true && !request.SuspendBitLocker)
            blockers.Add("BitLocker is active on the system drive and suspension is disabled. Suspend BitLocker (or enable SuspendBitLocker) to avoid a recovery key prompt after flashing.");
        else if (snapshot.BitLockerActive is null && !request.SuspendBitLocker)
            warnings.Add("Could not read the BitLocker state of the system drive, and suspension is disabled. If BitLocker is on, the PC will ask for the recovery key after flashing.");

        if (snapshot.PendingReboot == true)
            blockers.Add("A Windows or firmware restart is already pending. Restart the PC first before staging a BIOS update.");

        if (!string.IsNullOrWhiteSpace(request.Target.DownloadUrl) && !BiosPackageVerifier.IsSafeDownloadUrl(request.Target.DownloadUrl))
            blockers.Add("BIOS update download URL must use HTTPS.");

        if (!string.IsNullOrWhiteSpace(request.Target.DownloadUrl))
        {
            if (!request.VerifyHash)
                warnings.Add("SHA-256 hash verification is disabled; pinned Authenticode signature verification will still be enforced before executing.");
            else if (string.IsNullOrWhiteSpace(request.Target.Sha256))
                warnings.Add("Vendor catalog did not publish a SHA-256 checksum; verify the package's Authenticode signature before executing.");
        }

        return new BiosSafetyCheckResult(blockers.Count == 0, blockers, warnings);
    }
}
