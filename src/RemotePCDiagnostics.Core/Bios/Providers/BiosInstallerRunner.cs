using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Shared safe installer executor for BIOS update packages. Invokes native executables directly via
/// <c>ArgumentList</c> (zero command shells or script interpreters), routes through
/// <see cref="IElevatedCommandBridge"/> when the current process is not elevated, redacts
/// <see cref="BiosSystemIdentity.SerialNumber"/> from captured output, and maps vendor exit codes
/// to <see cref="BiosInstallResult"/>.
/// </summary>
public static class BiosInstallerRunner
{
    public const int DefaultMaxLogTailChars = 2000;

    /// <summary>
    /// Executes a verified BIOS installer binary (locally when elevated, or through the elevated Agent bridge
    /// when un-elevated) and maps its exit code into a structured <see cref="BiosInstallResult"/>,
    /// preserving <paramref name="bitLockerSuspended"/> and redacting <see cref="BiosSystemIdentity.SerialNumber"/>.
    /// </summary>
    public static async Task<BiosInstallResult> RunInstallerAsync(
        SystemCommandRunner? commands,
        string executablePath,
        IReadOnlyList<string> arguments,
        BiosInstallRequest request,
        bool bitLockerSuspended,
        IReadOnlySet<int> rebootSuccessExitCodes,
        IReadOnlySet<int>? completedSuccessExitCodes,
        TimeSpan timeout,
        ILogger? log,
        CancellationToken ct,
        string? workingDirectory = null,
        BiosAgentInstallRequest? agentRequest = null,
        IElevatedCommandBridge? bridge = null,
        Func<bool>? isProcessElevated = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(rebootSuccessExitCodes);

        var previousVersion = request.Current.Version;
        var targetVersion = request.Target.LatestVersion;
        var serialNumber = request.System.SerialNumber;
        var toolName = Path.GetFileName(executablePath);

        var effectiveBridge = bridge ?? commands?.ElevatedBridge;
        var elevated = isProcessElevated is not null
            ? isProcessElevated()
            : (commands is not null ? commands.IsProcessElevated : ElevationService.DetectProcessElevated());

        if (!elevated)
        {
            return await RunViaElevatedBridgeAsync(
                effectiveBridge,
                agentRequest,
                toolName,
                previousVersion,
                targetVersion,
                serialNumber,
                bitLockerSuspended,
                rebootSuccessExitCodes,
                completedSuccessExitCodes,
                timeout,
                log,
                ct).ConfigureAwait(false);
        }

        if (commands is null)
        {
            var noRunnerMsg = $"BIOS installer '{toolName}' cannot run locally because no command runner is configured.";
            log?.Warn(noRunnerMsg);
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: noRunnerMsg,
                ExitCode: null,
                LogTail: null);
        }

        log?.Info($"Launching BIOS installer '{toolName}' (target={targetVersion ?? "unknown"}, timeout={timeout.TotalSeconds:F0}s).");

        var effectiveExe = executablePath;
        var effectiveArgs = arguments;
        var effectiveWorkingDir = workingDirectory;
        string? sfxExtractDir = null;

        ProcessResult? result;
        try
        {
            var mode = agentRequest?.InstallMode?.Trim().ToLowerInvariant();
            if ((mode == BiosAgentInstallModes.HpSoftPaq || mode == BiosAgentInstallModes.HpBiosUpdRec)
                && AgentBiosOperations.IsHpSoftPaqExecutable(executablePath))
            {
                sfxExtractDir = Path.Combine(Path.GetTempPath(), $"rpcd-bios-extract-{Guid.NewGuid():N}");
                Directory.CreateDirectory(sfxExtractDir);

                string? inner = null;
                if (BiosArchiveAndXml.TryExtractEmbeddedCabToDirectory(executablePath, sfxExtractDir))
                    inner = AgentBiosOperations.FindExtractedHpFlasher(sfxExtractDir);

                if (inner is null)
                {
                    var extractRes = await ExecuteProcessAsync(
                        commands,
                        executablePath,
                        AgentBiosOperations.BuildHpSoftPaqExtractArguments(sfxExtractDir),
                        timeout,
                        workingDirectory,
                        serialNumber,
                        log,
                        ct).ConfigureAwait(false);

                    if (extractRes is { ExitCode: 0 })
                        inner = AgentBiosOperations.FindExtractedHpFlasher(sfxExtractDir);
                }

                if (inner is not null)
                {
                    effectiveExe = inner;
                    effectiveArgs = BiosAgentInstallModes.BuildArguments(BiosAgentInstallModes.HpBiosUpdRec, request.AllowReboot);
                    effectiveWorkingDir = Path.GetDirectoryName(inner) ?? sfxExtractDir;
                    toolName = Path.GetFileName(inner);
                }
                else
                {
                    effectiveArgs = BiosAgentInstallModes.BuildArguments(BiosAgentInstallModes.HpSoftPaq, request.AllowReboot);
                }
            }
            else if ((mode == BiosAgentInstallModes.LenovoWinUptp || mode == BiosAgentInstallModes.LenovoPackageSilent)
                && AgentBiosOperations.IsLenovoSfxExecutable(executablePath))
            {
                sfxExtractDir = Path.Combine(Path.GetTempPath(), $"rpcd-bios-extract-{Guid.NewGuid():N}");
                Directory.CreateDirectory(sfxExtractDir);
                var extractRes = await ExecuteProcessAsync(
                    commands,
                    executablePath,
                    AgentBiosOperations.BuildLenovoSfxExtractArguments(sfxExtractDir),
                    timeout,
                    workingDirectory,
                    serialNumber,
                    log,
                    ct).ConfigureAwait(false);

                var inner = extractRes is { ExitCode: 0 } ? AgentBiosOperations.FindExtractedLenovoFlasher(sfxExtractDir) : null;
                if (inner is not null)
                {
                    effectiveExe = inner;
                    effectiveArgs = BiosAgentInstallModes.BuildArguments(BiosAgentInstallModes.LenovoWinUptp, request.AllowReboot);
                    effectiveWorkingDir = Path.GetDirectoryName(inner) ?? sfxExtractDir;
                    toolName = Path.GetFileName(inner);
                }
                else
                {
                    effectiveArgs = BiosAgentInstallModes.BuildArguments(BiosAgentInstallModes.LenovoPackageSilent, request.AllowReboot);
                }
            }

            result = await ExecuteProcessAsync(commands, effectiveExe, effectiveArgs, timeout, effectiveWorkingDir, serialNumber, log, ct)
                .ConfigureAwait(false);
        }
        finally
        {
            if (sfxExtractDir is not null)
            {
                try { Directory.Delete(sfxExtractDir, recursive: true); } catch { }
            }
        }

        if (result is null)
        {
            var msg = $"BIOS installer '{toolName}' failed to start or timed out after {timeout.TotalSeconds:F0}s.";
            log?.Warn(msg);
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: msg,
                ExitCode: null,
                LogTail: null);
        }

        var logTail = BuildSanitizedLogTail(result.StdOut, result.StdErr, serialNumber);

        if (SystemCommandRunner.AgentFailure(result) is { } agentError)
        {
            var sanitizedAgentError = RedactSerialNumber(agentError, serialNumber);
            log?.Warn($"BIOS installer '{toolName}' could not be executed by Agent: {sanitizedAgentError}");
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: sanitizedAgentError,
                ExitCode: result.ExitCode,
                LogTail: logTail);
        }

        return MapExitCodeResult(
            toolName,
            result.ExitCode,
            previousVersion,
            targetVersion,
            bitLockerSuspended,
            logTail,
            rebootSuccessExitCodes,
            completedSuccessExitCodes,
            log);
    }

    /// <summary>
    /// Combines stdout/stderr, redacts <paramref name="serialNumber"/> (case-insensitive, length &gt;= 3),
    /// and returns a bounded tail of at most <paramref name="maxChars"/> characters.
    /// </summary>
    public static string? BuildSanitizedLogTail(
        string? stdOut,
        string? stdErr,
        string? serialNumber,
        int maxChars = DefaultMaxLogTailChars)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxChars);

        var trimmedOut = stdOut?.Trim() ?? "";
        var trimmedErr = stdErr?.Trim() ?? "";

        string combined;
        if (trimmedOut.Length > 0 && trimmedErr.Length > 0)
            combined = trimmedOut + "\n" + trimmedErr;
        else if (trimmedOut.Length > 0)
            combined = trimmedOut;
        else if (trimmedErr.Length > 0)
            combined = trimmedErr;
        else
            return null;

        combined = combined.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        combined = RedactSerialNumber(combined, serialNumber);

        if (combined.Length <= maxChars)
            return combined;

        if (maxChars <= 3)
            return combined[^maxChars..];

        var keep = maxChars - 3;
        return "..." + combined[^keep..];
    }

    /// <summary>Redacts <paramref name="serialNumber"/> (case-insensitive, length &gt;= 3) from <paramref name="text"/>.</summary>
    public static string RedactSerialNumber(string text, string? serialNumber)
    {
        var secret = serialNumber?.Trim();
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(secret) || secret.Length < 3)
            return text;

        return text.Replace(secret, "[REDACTED]", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<BiosInstallResult> RunViaElevatedBridgeAsync(
        IElevatedCommandBridge? bridge,
        BiosAgentInstallRequest? agentRequest,
        string toolName,
        string? previousVersion,
        string? targetVersion,
        string? serialNumber,
        bool bitLockerSuspended,
        IReadOnlySet<int> rebootSuccessExitCodes,
        IReadOnlySet<int>? completedSuccessExitCodes,
        TimeSpan timeout,
        ILogger? log,
        CancellationToken ct)
    {
        if (bridge is not { IsConnected: true })
        {
            var msg = $"Administrator rights (or the elevated Agent service) are required to run BIOS installer '{toolName}'. {ElevationService.AdminRepairHint}";
            log?.Warn(msg);
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: msg,
                ExitCode: SystemCommandRunner.AgentFailedExitCode,
                LogTail: null);
        }

        if (agentRequest is null)
        {
            var msg = $"A typed BIOS installer request is required to run '{toolName}' through the elevated Agent.";
            log?.Warn(msg);
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: msg,
                ExitCode: SystemCommandRunner.AgentFailedExitCode,
                LogTail: null);
        }

        var rawTimeoutMs = agentRequest.TimeoutMs > 0
            ? (double)agentRequest.TimeoutMs
            : timeout.TotalMilliseconds;
        var clampedTimeoutMs = (int)Math.Clamp(rawTimeoutMs, 1_000, 1_800_000);
        var effectiveAgentRequest = agentRequest with { TimeoutMs = clampedTimeoutMs };

        log?.Info($"Routing BIOS installer '{toolName}' through elevated Agent (mode={effectiveAgentRequest.InstallMode}, target={targetVersion ?? "unknown"}, timeout={clampedTimeoutMs / 1000.0:F0}s).");

        BiosAgentInstallResult agentResult;
        try
        {
            agentResult = await bridge.RunBiosInstallerAsync(effectiveAgentRequest, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is AdminRequiredException or NotSupportedException)
        {
            var sanitized = RedactSerialNumber(ex.Message, serialNumber);
            log?.Warn($"BIOS installer '{toolName}' is not supported by the elevated Agent: {sanitized}");
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: sanitized,
                ExitCode: SystemCommandRunner.AgentFailedExitCode,
                LogTail: null);
        }
        catch (Exception ex)
        {
            var sanitized = RedactSerialNumber(ex.Message, serialNumber);
            var msg = $"The elevated Agent could not run BIOS installer '{toolName}': {sanitized} {ElevationService.AdminRepairHint}";
            log?.Warn(msg);
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: msg,
                ExitCode: SystemCommandRunner.AgentFailedExitCode,
                LogTail: null);
        }

        var logTail = string.IsNullOrEmpty(agentResult.LogTail)
            ? null
            : BuildSanitizedLogTail(agentResult.LogTail, null, serialNumber);
        var sanitizedError = string.IsNullOrWhiteSpace(agentResult.Error)
            ? null
            : RedactSerialNumber(agentResult.Error, serialNumber);

        if (!agentResult.Allowed)
        {
            var msg = sanitizedError ?? "The elevated Agent refused or does not support BIOS installation. Update Remote PC Diagnostics, then try again.";
            log?.Warn($"BIOS installer '{toolName}' was refused by elevated Agent: {msg}");
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: msg,
                ExitCode: SystemCommandRunner.AgentFailedExitCode,
                LogTail: logTail);
        }

        if (agentResult.TimedOut)
        {
            var msg = sanitizedError ?? $"BIOS installer '{toolName}' timed out in elevated Agent after {clampedTimeoutMs / 1000.0:F0}s.";
            log?.Warn(msg);
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: msg,
                ExitCode: null,
                LogTail: logTail);
        }

        if (!agentResult.Executed)
        {
            var msg = sanitizedError ?? $"BIOS installer '{toolName}' could not be executed by the elevated Agent.";
            log?.Warn(msg);
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: msg,
                ExitCode: agentResult.ExitCode,
                LogTail: logTail);
        }

        return MapExitCodeResult(
            toolName,
            agentResult.ExitCode,
            previousVersion,
            targetVersion,
            bitLockerSuspended,
            logTail,
            rebootSuccessExitCodes,
            completedSuccessExitCodes,
            log);
    }

    private static BiosInstallResult MapExitCodeResult(
        string toolName,
        int exitCode,
        string? previousVersion,
        string? targetVersion,
        bool bitLockerSuspended,
        string? logTail,
        IReadOnlySet<int> rebootSuccessExitCodes,
        IReadOnlySet<int>? completedSuccessExitCodes,
        ILogger? log)
    {
        if (rebootSuccessExitCodes.Contains(exitCode))
        {
            log?.Info($"BIOS installer '{toolName}' staged update for reboot (exit={exitCode}).");
            return BiosInstallResult.StagedForReboot(
                previousVersion: previousVersion,
                targetVersion: targetVersion,
                bitLockerSuspended: bitLockerSuspended,
                exitCode: exitCode,
                logTail: logTail);
        }

        if (completedSuccessExitCodes is not null && completedSuccessExitCodes.Contains(exitCode))
        {
            var versionLabel = string.IsNullOrWhiteSpace(targetVersion) ? "update" : targetVersion;
            var msg = $"BIOS {versionLabel} installation completed (exit={exitCode}).";
            log?.Info($"BIOS installer '{toolName}' completed without reboot (exit={exitCode}).");
            return new BiosInstallResult(
                Succeeded: true,
                Status: BiosInstallStatus.Completed,
                RequiresReboot: false,
                BitLockerSuspended: bitLockerSuspended,
                PreviousVersion: previousVersion,
                TargetVersion: targetVersion,
                Message: msg,
                ExitCode: exitCode,
                LogTail: logTail);
        }

        var failMessage = $"BIOS installer '{toolName}' failed with exit code {exitCode}.";
        log?.Warn(failMessage);
        return new BiosInstallResult(
            Succeeded: false,
            Status: BiosInstallStatus.Failed,
            RequiresReboot: false,
            BitLockerSuspended: bitLockerSuspended,
            PreviousVersion: previousVersion,
            TargetVersion: targetVersion,
            Message: failMessage,
            ExitCode: exitCode,
            LogTail: logTail);
    }

    // Invokes commands.Launcher.RunAsync directly (never SystemCommandRunner.RunAsync) so raw installer stdout/stderr
    // containing BiosSystemIdentity.SerialNumber cannot bypass redaction and leak into commands.Log.
    private static async Task<ProcessResult?> ExecuteProcessAsync(
        SystemCommandRunner commands,
        string executablePath,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        string? workingDirectory,
        string? serialNumber,
        ILogger? log,
        CancellationToken ct)
    {
        try
        {
            var effectiveWorkingDirectory = string.IsNullOrWhiteSpace(workingDirectory) ? null : workingDirectory;
            var pr = await commands.Launcher.RunAsync(executablePath, arguments, timeout, ct, effectiveWorkingDirectory)
                .ConfigureAwait(false);
            return pr.TimedOut ? null : pr;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            var sanitizedError = RedactSerialNumber(ex.Message, serialNumber);
            log?.Warn($"BIOS installer '{Path.GetFileName(executablePath)}' failed to start: {sanitizedError}");
            return null;
        }
    }
}
