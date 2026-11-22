using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>Structured outcome of attempting to suspend BitLocker for 1 reboot locally or via the elevated Agent.</summary>
public sealed record BiosBitLockerSuspendOutcome(
    bool Suspended,
    bool ElevationRequired = false,
    bool LegacyAgentUnsupported = false,
    string? Message = null,
    bool SuspendFailed = false)
{
    /// <summary>
    /// True when the flash must not go ahead: elevation is missing, or suspension failed on a drive that may be encrypted
    /// (flashing then would ask for the BitLocker recovery key on the next boot).
    /// </summary>
    public bool BlocksInstall => ElevationRequired || SuspendFailed;
}

/// <summary>
/// Suspends BitLocker protection for 1 reboot via native <c>manage-bde.exe</c> using <c>ArgumentList</c> only
/// (pure C#, zero command shells or script interpreters), routing through <see cref="IElevatedCommandBridge"/>
/// whenever the current process is not elevated.
/// </summary>
public static partial class BiosBitLockerSuspender
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    [GeneratedRegex("^[A-Za-z]:$", RegexOptions.CultureInvariant)]
    private static partial Regex DriveLetterRegex();

    /// <summary>Returns <c>true</c> only for strict two-character Windows drive specifiers like <c>"C:"</c>.</summary>
    public static bool IsValidSystemDrive(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        return DriveLetterRegex().IsMatch(value.Trim());
    }

    /// <summary>
    /// Resolves and validates the target system drive (<paramref name="systemDriveOverride"/> or <c>%SystemDrive%</c>),
    /// returning an uppercased drive letter such as <c>"C:"</c> and falling back safely to <c>"C:"</c>.
    /// </summary>
    public static string ResolveSystemDrive(string? systemDriveOverride = null)
    {
        var raw = systemDriveOverride ?? Environment.GetEnvironmentVariable("SystemDrive");
        var candidate = raw?.Trim();
        return !string.IsNullOrEmpty(candidate) && DriveLetterRegex().IsMatch(candidate)
            ? candidate.ToUpperInvariant()
            : "C:";
    }

    /// <summary>
    /// Suspends BitLocker protectors on the system drive for 1 reboot when <see cref="BiosInstallRequest.SuspendBitLocker"/> is <c>true</c>.
    /// Returns <c>true</c> if BitLocker was suspended, or <c>false</c> if skipped, unavailable, elevation is required, or volume is not encrypted.
    /// Never throws except on caller cancellation.
    /// </summary>
    public static async Task<bool> SuspendForOneRebootIfRequestedAsync(
        BiosInstallRequest request,
        SystemCommandRunner? commands,
        IProgress<BiosInstallProgress>? progress,
        ILogger? log,
        CancellationToken ct,
        string? systemDriveOverride = null,
        IElevatedCommandBridge? bridge = null,
        Func<bool>? isProcessElevated = null)
    {
        var outcome = await SuspendForOneRebootWithResultAsync(
            request,
            commands,
            progress,
            log,
            ct,
            systemDriveOverride,
            bridge,
            isProcessElevated).ConfigureAwait(false);
        return outcome.Suspended;
    }

    /// <summary>
    /// Suspends BitLocker protectors on the system drive for 1 reboot when <see cref="BiosInstallRequest.SuspendBitLocker"/> is <c>true</c>,
    /// returning a structured <see cref="BiosBitLockerSuspendOutcome"/> that distinguishes elevation/legacy-Agent failures from non-encrypted volumes.
    /// Never throws except on caller cancellation.
    /// </summary>
    public static async Task<BiosBitLockerSuspendOutcome> SuspendForOneRebootWithResultAsync(
        BiosInstallRequest request,
        SystemCommandRunner? commands,
        IProgress<BiosInstallProgress>? progress,
        ILogger? log,
        CancellationToken ct,
        string? systemDriveOverride = null,
        IElevatedCommandBridge? bridge = null,
        Func<bool>? isProcessElevated = null)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!request.SuspendBitLocker)
            return new BiosBitLockerSuspendOutcome(Suspended: false);

        var drive = ResolveSystemDrive(systemDriveOverride);
        var serialNumber = request.System.SerialNumber;
        var effectiveBridge = bridge ?? commands?.ElevatedBridge;
        var elevated = isProcessElevated is not null
            ? isProcessElevated()
            : (commands is not null ? commands.IsProcessElevated : ElevationService.DetectProcessElevated());

        if (!elevated)
        {
            if (effectiveBridge is not { IsConnected: true })
            {
                var elevationMsg = $"BitLocker suspension on {drive} requires Administrator rights or a connected Agent. {ElevationService.AdminRepairHint}";
                log?.Warn(elevationMsg);
                return new BiosBitLockerSuspendOutcome(
                    Suspended: false,
                    ElevationRequired: true,
                    LegacyAgentUnsupported: false,
                    Message: elevationMsg);
            }

            progress?.Report(new BiosInstallProgress(
                BiosInstallStage.SuspendingBitLocker,
                0,
                $"Suspending BitLocker on {drive} for 1 reboot..."));

            try
            {
                var agentResult = await effectiveBridge.SuspendBitLockerAsync(drive, ct).ConfigureAwait(false);
                if (agentResult.Suspended && agentResult.Allowed)
                {
                    progress?.Report(new BiosInstallProgress(
                        BiosInstallStage.SuspendingBitLocker,
                        100,
                        $"BitLocker suspended on {drive} for 1 reboot."));
                    log?.Info($"BitLocker suspended on {drive} for 1 reboot via elevated Agent.");
                    return new BiosBitLockerSuspendOutcome(Suspended: true);
                }

                if (!agentResult.Allowed)
                {
                    var rawRefused = agentResult.Error ?? "The Agent refused or does not support elevated BitLocker suspension. Update Remote PC Diagnostics, then try again.";
                    var refusedMsg = BiosInstallerRunner.RedactSerialNumber(rawRefused, serialNumber);
                    log?.Warn($"BitLocker suspension on {drive} was refused by Agent: {refusedMsg}");
                    return new BiosBitLockerSuspendOutcome(
                        Suspended: false,
                        ElevationRequired: true,
                        LegacyAgentUnsupported: true,
                        Message: refusedMsg);
                }

                var sanitizedError = agentResult.Error is null
                    ? null
                    : BiosInstallerRunner.RedactSerialNumber(agentResult.Error, serialNumber);
                return NotApplied(request, drive, $"exit={agentResult.ExitCode}", sanitizedError, log);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is AdminRequiredException or NotSupportedException)
            {
                var sanitized = BiosInstallerRunner.RedactSerialNumber(ex.Message, serialNumber);
                log?.Warn($"BitLocker suspension on {drive} is not supported by the connected Agent: {sanitized}");
                return new BiosBitLockerSuspendOutcome(
                    Suspended: false,
                    ElevationRequired: true,
                    LegacyAgentUnsupported: true,
                    Message: sanitized);
            }
            catch (Exception ex)
            {
                var sanitized = BiosInstallerRunner.RedactSerialNumber(ex.Message, serialNumber);
                var failedMsg = $"BitLocker suspension on {drive} via Agent failed: {sanitized} {ElevationService.AdminRepairHint}";
                log?.Warn(failedMsg);
                return new BiosBitLockerSuspendOutcome(
                    Suspended: false,
                    ElevationRequired: true,
                    LegacyAgentUnsupported: false,
                    Message: failedMsg);
            }
        }

        if (commands is null)
            return NotApplied(request, drive, "command runner is unavailable", "Command runner is unavailable.", log);

        progress?.Report(new BiosInstallProgress(
            BiosInstallStage.SuspendingBitLocker,
            0,
            $"Suspending BitLocker on {drive} for 1 reboot..."));

        try
        {
            var result = await RunSuspendCommandAsync(commands, drive, ct).ConfigureAwait(false);
            if (result is { ExitCode: 0 })
            {
                progress?.Report(new BiosInstallProgress(
                    BiosInstallStage.SuspendingBitLocker,
                    100,
                    $"BitLocker suspended on {drive} for 1 reboot."));
                log?.Info($"BitLocker suspended on {drive} for 1 reboot.");
                return new BiosBitLockerSuspendOutcome(Suspended: true);
            }

            if (SystemCommandRunner.AgentFailure(result) is { } agentError)
            {
                var sanitizedAgentError = BiosInstallerRunner.RedactSerialNumber(agentError, serialNumber);
                log?.Warn($"BitLocker suspension on {drive} could not be executed by Agent: {sanitizedAgentError}");
                return new BiosBitLockerSuspendOutcome(Suspended: false, ElevationRequired: true, Message: sanitizedAgentError);
            }

            var exitCodeText = result is null ? "timeout/unavailable" : $"exit={result.ExitCode}";
            return NotApplied(request, drive, exitCodeText, exitCodeText, log);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            var sanitized = BiosInstallerRunner.RedactSerialNumber(ex.Message, serialNumber);
            return NotApplied(request, drive, sanitized, sanitized, log);
        }
    }

    /// <summary>
    /// Suspension didn't happen. That's fine only when the safety probe saw BitLocker off (or already suspended)
    /// on this drive; otherwise the install is blocked rather than risking a recovery-key prompt after the flash.
    /// </summary>
    private static BiosBitLockerSuspendOutcome NotApplied(BiosInstallRequest request, string drive, string why, string? detail, ILogger? log)
    {
        if (request.BitLockerKnownOff)
        {
            log?.Info($"BitLocker suspension on {drive} did not apply ({why}); BitLocker is off, continuing.");
            return new BiosBitLockerSuspendOutcome(Suspended: false, Message: detail);
        }

        var msg = $"Couldn't suspend BitLocker on {drive} ({detail ?? why}), and BitLocker may be on. The BIOS update was not started, so the PC won't ask for the BitLocker recovery key. Suspend BitLocker on {drive}, then try again.";
        log?.Warn(msg);
        return new BiosBitLockerSuspendOutcome(Suspended: false, Message: msg, SuspendFailed: true);
    }

    // Invokes commands.Launcher.RunAsync directly (never SystemCommandRunner.RunAsync) so raw tool output
    // or launch errors containing BiosSystemIdentity.SerialNumber cannot bypass redaction and leak into commands.Log.
    private static async Task<ProcessResult?> RunSuspendCommandAsync(
        SystemCommandRunner commands,
        string drive,
        CancellationToken ct)
    {
        var tool = SystemCommandRunner.SystemTool("manage-bde.exe");
        string[] args = ["-protectors", "-disable", drive, "-RebootCount", "1"];
        var pr = await commands.Launcher.RunAsync(tool, args, DefaultTimeout, ct).ConfigureAwait(false);
        return pr.TimedOut ? null : pr;
    }
}
