using System.ComponentModel;
using System.Globalization;
using System.Management;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Strict wire-safe install mode allowlist for elevated BIOS installer operations executed inside the Agent.
/// No free-form command lines or arbitrary argument lists are ever accepted over the admin pipe.
/// </summary>
public static class BiosAgentInstallModes
{
    /// <summary>HP SoftPaq executable (verified <c>.exe</c>; <c>-r</c> suppresses reboot).</summary>
    public const string HpSoftPaq = "hp_softpaq";

    /// <summary>HP firmware updater executable (verified <c>.exe</c>; <c>-r</c> suppresses reboot).</summary>
    public const string HpBiosUpdRec = "hp_biosupdrec";

    /// <summary>Dell BIOS updater executable (verified <c>.exe</c>; <c>/r</c> enables reboot).</summary>
    public const string DellBiosExe = "dell_bios_exe";

    /// <summary>Allowlisted installed Dell Command | Update CLI (<c>Dell\CommandUpdate\dcu-cli.exe</c>).</summary>
    public const string DellDcuCli = "dell_dcu_cli";

    /// <summary>Lenovo winuptp BIOS updater executable (verified <c>.exe</c>; <c>-r</c> enables reboot).</summary>
    public const string LenovoWinUptp = "lenovo_winuptp";

    /// <summary>Lenovo silent package executable (verified <c>.exe</c>; <c>/NORESTART</c> suppresses reboot).</summary>
    public const string LenovoPackageSilent = "lenovo_package_silent";

    /// <summary>Microsoft Surface firmware MSI via <c>msiexec.exe</c> (verified <c>.msi</c>).</summary>
    public const string MicrosoftSurfaceMsi = "microsoft_surface_msi";

    /// <summary>Framework Windows BIOS updater executable (verified <c>.exe</c>; <c>/norestart</c> suppresses reboot).</summary>
    public const string FrameworkBiosExe = "framework_bios_exe";

    /// <summary>Framework UEFI capsule cabinet extracted in admin staging and installed via <c>pnputil.exe</c>.</summary>
    public const string FrameworkCabCapsule = "framework_cab_capsule";

    /// <summary>
    /// Validates that <paramref name="vendorId"/> and <paramref name="installMode"/> match an exact allowlisted pair.
    /// </summary>
    public static bool TryValidateVendorAndMode(
        string? vendorId,
        string? installMode,
        out string normalizedVendor,
        out string normalizedMode)
    {
        normalizedVendor = "";
        normalizedMode = "";

        if (string.IsNullOrWhiteSpace(vendorId) || string.IsNullOrWhiteSpace(installMode))
            return false;

        var v = vendorId.Trim().ToLowerInvariant();
        var m = installMode.Trim().ToLowerInvariant();

        var expectedVendor = m switch
        {
            HpSoftPaq => "hp",
            HpBiosUpdRec => "hp",
            DellBiosExe => "dell",
            DellDcuCli => "dell",
            LenovoWinUptp => "lenovo",
            LenovoPackageSilent => "lenovo",
            MicrosoftSurfaceMsi => "microsoft",
            FrameworkBiosExe => "framework",
            FrameworkCabCapsule => "framework",
            _ => null,
        };

        if (expectedVendor is null || !string.Equals(v, expectedVendor, StringComparison.Ordinal))
            return false;

        normalizedVendor = v;
        normalizedMode = m;
        return true;
    }

    private static readonly string[] HpSigners = ["HP Inc.", "HP Inc", "Hewlett-Packard Company"];
    private static readonly string[] DellSigners = ["Dell Inc", "Dell Inc.", "Dell Technologies Inc."];
    private static readonly string[] LenovoSigners = ["Lenovo", "Lenovo (Beijing) Limited"];
    private static readonly string[] MicrosoftSigners = ["Microsoft Corporation"];
    // Framework's Windows BIOS updaters wrap Insyde's flash tool, which Insyde signs.
    private static readonly string[] FrameworkSigners = ["Framework Computer Inc", "Framework Computer Inc.", "Framework Computer, Inc.", "Insyde Software Corp."];

    /// <summary>
    /// The certificate organizations (O=) the Agent accepts as the signer of a package for <paramref name="normalizedMode"/>.
    /// A valid signature from anyone else is refused, so the Agent never runs an arbitrary signed program elevated.
    /// </summary>
    public static IReadOnlyCollection<string> AllowedSignerOrganizations(string normalizedMode) => normalizedMode switch
    {
        HpSoftPaq or HpBiosUpdRec => HpSigners,
        DellBiosExe or DellDcuCli => DellSigners,
        LenovoWinUptp or LenovoPackageSilent => LenovoSigners,
        MicrosoftSurfaceMsi => MicrosoftSigners,
        FrameworkBiosExe or FrameworkCabCapsule => FrameworkSigners,
        _ => [],
    };

    /// <summary>
    /// The certificate organizations (O=) accepted as the signer of a package for <paramref name="vendorId"/>.
    /// Unknown vendors return an empty collection (fail-closed).
    /// </summary>
    public static IReadOnlyCollection<string> AllowedSignerOrganizationsForVendor(string? vendorId) =>
        (vendorId?.Trim().ToLowerInvariant() ?? "") switch
        {
            "hp" => HpSigners,
            "dell" => DellSigners,
            "lenovo" => LenovoSigners,
            "microsoft" => MicrosoftSigners,
            "framework" => FrameworkSigners,
            _ => [],
        };

    /// <summary>Signers accepted for the driver catalog (.cat) of a capsule cabinet: Windows Hardware Compatibility Publisher.</summary>
    public static IReadOnlyCollection<string> AllowedCatalogSignerOrganizations { get; } = MicrosoftSigners;

    /// <summary>
    /// Signers accepted for an inner BIOS flasher (e.g., <c>HpFirmwareUpdRec64.exe</c>, <c>WINUPTP64.EXE</c>)
    /// after it has been extracted inside the Agent's admin-only staging directory from an outer package
    /// that already passed <see cref="AllowedSignerOrganizations"/> for the vendor.
    /// Modern HP/OEM firmware updaters are frequently attestation/WHQL-signed by
    /// <c>Microsoft Windows Hardware Compatibility Publisher</c> (<c>O=Microsoft Corporation</c>).
    /// </summary>
    public static IReadOnlyCollection<string> AllowedExtractedFlasherSignerOrganizations(string normalizedMode)
    {
        var vendorSigners = AllowedSignerOrganizations(normalizedMode);
        if (vendorSigners.Count == 0)
            return [];

        return [.. vendorSigners, .. MicrosoftSigners];
    }

    /// <summary>
    /// Builds the canonical <c>ArgumentList</c> for an allowlisted <paramref name="installMode"/> and reboot preference.
    /// </summary>
    public static IReadOnlyList<string> BuildArguments(
        string installMode,
        bool allowReboot,
        string? stagedTargetPath = null)
    {
        var normalized = installMode?.Trim().ToLowerInvariant() ?? "";
        return normalized switch
        {
            // HP SoftPaq SFX wrappers (sp*.exe) reject -r with exit code 87 (ERROR_INVALID_PARAMETER).
            // The inner flasher (HpFirmwareUpdRec64.exe / HPBIOSUPDREC64.exe) uses -r to suppress reboot.
            HpSoftPaq => ["-s"],
            HpBiosUpdRec => !allowReboot ? ["-s", "-r"] : ["-s"],
            DellBiosExe => allowReboot ? ["/s", "/r"] : ["/s"],
            DellDcuCli => ["/applyUpdates", "-updateType=bios", "-silent", allowReboot ? "-reboot=enable" : "-reboot=disable"],
            LenovoWinUptp => allowReboot ? ["-s", "-r"] : ["-s"],
            LenovoPackageSilent => allowReboot
                ? ["/VERYSILENT", "/SUPPRESSMSGBOXES"]
                : ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"],
            MicrosoftSurfaceMsi => BuildMsiArguments(stagedTargetPath, allowReboot),
            FrameworkBiosExe => allowReboot ? ["/silent"] : ["/silent", "/norestart"],
            FrameworkCabCapsule => BuildPnpUtilArguments(stagedTargetPath),
            _ => throw new ArgumentOutOfRangeException(nameof(installMode), installMode, "Unsupported BIOS install mode."),
        };
    }

    internal static bool TryGetRequiredExtension(string normalizedMode, out string? extension)
    {
        switch (normalizedMode)
        {
            case HpSoftPaq:
            case HpBiosUpdRec:
            case DellBiosExe:
            case LenovoWinUptp:
            case LenovoPackageSilent:
            case FrameworkBiosExe:
                extension = ".exe";
                return true;
            case MicrosoftSurfaceMsi:
                extension = ".msi";
                return true;
            case FrameworkCabCapsule:
                extension = ".cab";
                return true;
            case DellDcuCli:
                extension = null;
                return true;
            default:
                extension = null;
                return false;
        }
    }

    private static IReadOnlyList<string> BuildMsiArguments(string? stagedMsiPath, bool allowReboot)
    {
        if (string.IsNullOrWhiteSpace(stagedMsiPath))
            throw new ArgumentException("A staged MSI path is required for Microsoft Surface MSI installs.", nameof(stagedMsiPath));

        return allowReboot
            ? ["/i", stagedMsiPath, "/qn"]
            : ["/i", stagedMsiPath, "/qn", "/norestart"];
    }

    private static IReadOnlyList<string> BuildPnpUtilArguments(string? stagedInfPath)
    {
        if (string.IsNullOrWhiteSpace(stagedInfPath))
            throw new ArgumentException("A staged INF path is required for cabinet capsule installs.", nameof(stagedInfPath));

        return ["/add-driver", stagedInfPath, "/install"];
    }
}

/// <summary>
/// Typed request sent over the admin pipe for elevated BIOS installer execution.
/// Intentionally omits any serial number or free-form command-line fields.
/// </summary>
public sealed record BiosAgentInstallRequest(
    [property: JsonPropertyName("vendorId")] string VendorId,
    [property: JsonPropertyName("installMode")] string InstallMode,
    [property: JsonPropertyName("packagePath")] string? PackagePath = null,
    [property: JsonPropertyName("expectedSha256")] string? ExpectedSha256 = null,
    [property: JsonPropertyName("allowReboot")] bool AllowReboot = false,
    [property: JsonPropertyName("infRelativePath")] string? InfRelativePath = null,
    [property: JsonPropertyName("timeoutMs")] int TimeoutMs = 600_000);

/// <summary>Typed outcome of an elevated BitLocker 1-reboot suspension request.</summary>
public sealed record BiosAgentBitLockerResult(
    [property: JsonPropertyName("suspended")] bool Suspended,
    [property: JsonPropertyName("allowed")] bool Allowed = true,
    [property: JsonPropertyName("exitCode")] int ExitCode = -1,
    [property: JsonPropertyName("error")] string? Error = null);

/// <summary>Typed outcome of an elevated BIOS installer execution request.</summary>
public sealed record BiosAgentInstallResult(
    [property: JsonPropertyName("executed")] bool Executed,
    [property: JsonPropertyName("allowed")] bool Allowed = true,
    [property: JsonPropertyName("exitCode")] int ExitCode = -1,
    [property: JsonPropertyName("timedOut")] bool TimedOut = false,
    [property: JsonPropertyName("logTail")] string? LogTail = null,
    [property: JsonPropertyName("error")] string? Error = null);

/// <summary>Agent-side handler for privileged BIOS update operations received over <see cref="AdminPipeServer"/>.</summary>
public interface IAgentBiosOperations
{
    Task<BiosAgentBitLockerResult> SuspendBitLockerAsync(string systemDrive, CancellationToken ct = default);
    Task<BiosAgentInstallResult> RunBiosInstallerAsync(BiosAgentInstallRequest request, CancellationToken ct = default);
    Task<BiosWuaInstallOutcome> InstallWindowsUpdateAsync(Guid updateId, TimeSpan timeout, CancellationToken ct = default);
}

/// <summary>
/// Pure-C# Agent-side implementation of privileged BIOS operations.
/// Enforces strict input validation, admin-owned staging copies (eliminating TOCTOU races),
/// SHA-256 and Authenticode verification, allowlisted tool resolution, and canonical argument construction
/// without ever invoking command shells or script interpreters.
/// </summary>
public sealed partial class AgentBiosOperations : IAgentBiosOperations
{
    private const int MaxPathLength = 512;
    private const int CopyBufferSize = 64 * 1024;
    private const int MinTimeoutMs = 1_000;
    private const int MaxTimeoutMs = 1_800_000;
    private static readonly TimeSpan BitLockerTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ExpandTimeout = TimeSpan.FromSeconds(60);

    private static readonly char[] ForbiddenPathChars =
    [
        '&', '|', ';', '>', '<', '`', '$', '%', '"', '\'', '^', '!', '*', '?',
    ];

    private readonly IProcessLauncher _launcher;
    private readonly IBiosSignatureVerifier _signatureVerifier;
    private readonly Func<IWindowsUpdateApi>? _wuaApiFactory;
    private readonly string _stagingRoot;
    private readonly bool _isCustomStagingRoot;
    private readonly IReadOnlyList<string> _allowedToolRoots;
    private readonly long _maxPackageBytes;
    private readonly ILogger? _log;
    private readonly Dictionary<Guid, Task<SingleUpdateInstallResult>> _wuaInstalls = [];
    private readonly Lock _wuaInstallsLock = new();

    [GeneratedRegex(@"\A[0-9A-Fa-f]{64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256HexRegex();

    public AgentBiosOperations(
        IProcessLauncher? launcher = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        Func<IWindowsUpdateApi>? wuaApiFactory = null,
        string? stagingRoot = null,
        IReadOnlyList<string>? allowedToolRoots = null,
        long maxPackageBytes = BiosProviderHttp.DefaultMaxDownloadBytes,
        ILogger? log = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxPackageBytes);

        _launcher = launcher ?? new SystemProcessLauncher();
        _signatureVerifier = signatureVerifier ?? WinVerifyTrustSignatureVerifier.Instance;
        _wuaApiFactory = wuaApiFactory;
        _isCustomStagingRoot = !string.IsNullOrWhiteSpace(stagingRoot);
        _stagingRoot = ResolveStagingRoot(stagingRoot);
        _allowedToolRoots = ResolveAllowedToolRoots(allowedToolRoots);
        _maxPackageBytes = maxPackageBytes;
        _log = log;
    }

    public async Task<BiosAgentBitLockerResult> SuspendBitLockerAsync(string systemDrive, CancellationToken ct = default)
    {
        if (systemDrive is not { Length: 2 } || !char.IsAsciiLetter(systemDrive[0]) || systemDrive[1] != ':')
        {
            return new BiosAgentBitLockerResult(
                Suspended: false,
                Allowed: false,
                ExitCode: -1,
                Error: "Invalid system drive specifier; expected '<DriveLetter>:' (e.g., 'C:').");
        }

        var drive = $"{char.ToUpperInvariant(systemDrive[0])}:";
        var tool = SystemCommandRunner.SystemTool("manage-bde.exe");
        string[] args = ["-protectors", "-disable", drive, "-RebootCount", "1"];

        ProcessResult pr;
        try
        {
            pr = await _launcher.RunAsync(tool, args, BitLockerTimeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is Win32Exception or FileNotFoundException)
        {
            if (OperatingSystem.IsWindows() && _launcher is SystemProcessLauncher)
            {
                if (TrySuspendBitLockerViaWmiWindows(drive))
                    return new BiosAgentBitLockerResult(Suspended: true, Allowed: true, ExitCode: 0);
            }

            _log?.Warn($"[agent-bios] Failed to launch BitLocker suspension tool for {drive}: {ex.Message}");
            return new BiosAgentBitLockerResult(
                Suspended: false,
                Allowed: true,
                ExitCode: -1,
                Error: $"BitLocker suspension tool could not be launched: {ex.Message}");
        }
        catch (Exception ex)
        {
            _log?.Warn($"[agent-bios] BitLocker suspension failed for {drive}: {ex.Message}");
            return new BiosAgentBitLockerResult(
                Suspended: false,
                Allowed: true,
                ExitCode: -1,
                Error: $"BitLocker suspension failed: {ex.Message}");
        }

        if (pr.TimedOut)
        {
            return new BiosAgentBitLockerResult(
                Suspended: false,
                Allowed: true,
                ExitCode: -1,
                Error: "BitLocker suspension timed out.");
        }

        if (pr.ExitCode == 0)
            return new BiosAgentBitLockerResult(Suspended: true, Allowed: true, ExitCode: 0);

        var detail = string.IsNullOrWhiteSpace(pr.StdErr)
            ? $"manage-bde exited with code {pr.ExitCode}."
            : pr.StdErr.Trim();
        return new BiosAgentBitLockerResult(
            Suspended: false,
            Allowed: true,
            ExitCode: pr.ExitCode,
            Error: detail);
    }

    public async Task<BiosAgentInstallResult> RunBiosInstallerAsync(BiosAgentInstallRequest request, CancellationToken ct = default)
    {
        if (request is null)
            return Reject("No BIOS install request was provided.");

        if (!BiosAgentInstallModes.TryValidateVendorAndMode(request.VendorId, request.InstallMode, out _, out var mode))
            return Reject("Unsupported or mismatched BIOS vendor and install mode.");

        if (mode != BiosAgentInstallModes.FrameworkCabCapsule && !string.IsNullOrEmpty(request.InfRelativePath))
            return Reject("INF relative path is only permitted for cabinet capsule installs.");

        string? normalizedSha256 = null;
        if (request.ExpectedSha256 is not null && request.ExpectedSha256.Length > 0)
        {
            if (request.ExpectedSha256.Length != 64 || !Sha256HexRegex().IsMatch(request.ExpectedSha256))
                return Reject("Expected SHA-256 must be exactly 64 hexadecimal characters.");
            normalizedSha256 = request.ExpectedSha256.ToLowerInvariant();
        }

        var timeout = TimeSpan.FromMilliseconds(Math.Clamp(request.TimeoutMs, MinTimeoutMs, MaxTimeoutMs));

        if (mode == BiosAgentInstallModes.DellDcuCli)
            return await RunAllowlistedDcuCliAsync(request, normalizedSha256, timeout, ct).ConfigureAwait(false);

        if (!BiosAgentInstallModes.TryGetRequiredExtension(mode, out var requiredExt) || string.IsNullOrEmpty(requiredExt))
            return Reject("Unsupported BIOS install mode.");

        if (!TryValidatePackagePathSyntax(request.PackagePath, requiredExt, out var sourcePath, out var pathError))
            return Reject(pathError);

        if (!TryValidateRegularFileAndAncestors(sourcePath, _maxPackageBytes, out var fileError))
            return Reject(fileError);

        if (!TryCreateRunStagingDirectory(out var runStagingDir, out var stagingError))
            return Reject(stagingError);

        try
        {
            var stagedFileName = BiosVendorIdentity.SanitizeFileName(Path.GetFileName(sourcePath), "bios-package" + requiredExt);
            if (!stagedFileName.EndsWith(requiredExt, StringComparison.OrdinalIgnoreCase))
                stagedFileName = Path.GetFileNameWithoutExtension(stagedFileName) + requiredExt;

            var stagedPath = Path.Combine(runStagingDir, stagedFileName);
            var copyError = await CopyToAdminStagingAsync(sourcePath, stagedPath, ct).ConfigureAwait(false);
            if (copyError is not null)
                return Reject(copyError);

            if (!string.IsNullOrEmpty(normalizedSha256))
            {
                var (shaValid, _) = await BiosPackageVerifier.VerifyFileSha256Async(stagedPath, normalizedSha256, ct).ConfigureAwait(false);
                if (!shaValid)
                    return Reject("BIOS package failed Agent SHA-256 verification.");
            }

            string executablePath;
            IReadOnlyList<string> arguments;
            string workingDirectory;

            if (mode == BiosAgentInstallModes.FrameworkCabCapsule)
            {
                var cabSigned = await _signatureVerifier.VerifyAuthenticodeAsync(stagedPath, BiosAgentInstallModes.AllowedSignerOrganizations(mode), ct).ConfigureAwait(false);
                if (!cabSigned && string.IsNullOrEmpty(normalizedSha256))
                    return Reject("BIOS cabinet package failed Agent signature verification.");

                var extractDir = Path.Combine(runStagingDir, "cab");
                if (!TryCreateSecureSubdirectory(extractDir, out var extractDirError))
                    return Reject(extractDirError);

                var extractError = await ExtractCabToStagingAsync(stagedPath, extractDir, ct).ConfigureAwait(false);
                if (extractError is not null)
                    return Reject(extractError);

                if (!TryResolveInfPath(extractDir, request.InfRelativePath, out var stagedInfPath, out var infError))
                    return Reject(infError);

                var trusted = cabSigned;
                if (!trusted && !string.IsNullOrEmpty(normalizedSha256))
                    trusted = await HasSignedCatalogCoveringFileAsync(extractDir, stagedInfPath, ct).ConfigureAwait(false);

                if (!trusted)
                    return Reject("BIOS cabinet package failed Agent signature verification.");

                executablePath = SystemCommandRunner.SystemTool("pnputil.exe");
                arguments = BiosAgentInstallModes.BuildArguments(mode, request.AllowReboot, stagedInfPath);
                workingDirectory = extractDir;
            }
            else
            {
                var sigValid = await _signatureVerifier.VerifyAuthenticodeAsync(stagedPath, BiosAgentInstallModes.AllowedSignerOrganizations(mode), ct).ConfigureAwait(false);
                if (!sigValid)
                    return Reject("BIOS package failed Agent Authenticode signature verification.");

                if (mode == BiosAgentInstallModes.MicrosoftSurfaceMsi)
                {
                    executablePath = SystemCommandRunner.SystemTool("msiexec.exe");
                    arguments = BiosAgentInstallModes.BuildArguments(mode, request.AllowReboot, stagedPath);
                    workingDirectory = runStagingDir;
                }
                else if ((mode == BiosAgentInstallModes.HpSoftPaq || mode == BiosAgentInstallModes.HpBiosUpdRec)
                    && IsHpSoftPaqExecutable(stagedPath))
                {
                    var extractDir = Path.Combine(runStagingDir, "extracted");
                    Directory.CreateDirectory(extractDir);

                    BiosAgentInstallResult? extractResult = null;
                    string? innerFlasher = null;
                    if (Bios.BiosArchiveAndXml.TryExtractEmbeddedCabToDirectory(stagedPath, extractDir))
                        innerFlasher = FindExtractedHpFlasher(extractDir);

                    if (innerFlasher is null)
                    {
                        extractResult = await ExecuteInstallerAsync(
                            stagedPath,
                            BuildHpSoftPaqExtractArguments(extractDir),
                            timeout,
                            runStagingDir,
                            ct).ConfigureAwait(false);
                        if (extractResult.ExitCode == 0)
                            innerFlasher = FindExtractedHpFlasher(extractDir);
                    }

                    if (innerFlasher is not null)
                    {
                        var innerSigValid = await _signatureVerifier.VerifyAuthenticodeAsync(
                            innerFlasher,
                            BiosAgentInstallModes.AllowedExtractedFlasherSignerOrganizations(BiosAgentInstallModes.HpBiosUpdRec),
                            ct).ConfigureAwait(false);
                        if (!innerSigValid)
                            return Reject("Extracted HP BIOS flasher failed Agent Authenticode signature verification.");

                        executablePath = innerFlasher;
                        arguments = BiosAgentInstallModes.BuildArguments(BiosAgentInstallModes.HpBiosUpdRec, request.AllowReboot);
                        workingDirectory = Path.GetDirectoryName(innerFlasher) ?? extractDir;
                    }
                    else
                    {
                        // Running the SoftPaq itself can't keep the PC from rebooting (sp*.exe rejects -r), so stop here.
                        var foundExes = ListExtractedExeNames(extractDir);
                        var diag = $"extractExit={(extractResult is null ? "cab-only" : extractResult.ExitCode.ToString())}, foundExes=[{string.Join(", ", foundExes)}]";
                        var logTail = string.IsNullOrWhiteSpace(extractResult?.LogTail) ? diag : $"{extractResult!.LogTail}\n{diag}";
                        return new BiosAgentInstallResult(
                            Executed: false,
                            Allowed: true,
                            ExitCode: extractResult?.ExitCode ?? -1,
                            TimedOut: false,
                            LogTail: logTail,
                            Error: HpFlasherNotFound);
                    }
                }
                else if ((mode == BiosAgentInstallModes.LenovoWinUptp || mode == BiosAgentInstallModes.LenovoPackageSilent)
                    && IsLenovoSfxExecutable(stagedPath))
                {
                    var extractDir = Path.Combine(runStagingDir, "extracted");
                    Directory.CreateDirectory(extractDir);
                    var extractResult = await ExecuteInstallerAsync(
                        stagedPath,
                        BuildLenovoSfxExtractArguments(extractDir),
                        timeout,
                        runStagingDir,
                        ct).ConfigureAwait(false);

                    var innerFlasher = extractResult.ExitCode == 0 ? FindExtractedLenovoFlasher(extractDir) : null;
                    if (innerFlasher is not null)
                    {
                        var innerSigValid = await _signatureVerifier.VerifyAuthenticodeAsync(
                            innerFlasher,
                            BiosAgentInstallModes.AllowedExtractedFlasherSignerOrganizations(BiosAgentInstallModes.LenovoWinUptp),
                            ct).ConfigureAwait(false);
                        if (!innerSigValid)
                            return Reject("Extracted Lenovo BIOS flasher failed Agent Authenticode signature verification.");

                        executablePath = innerFlasher;
                        arguments = BiosAgentInstallModes.BuildArguments(BiosAgentInstallModes.LenovoWinUptp, request.AllowReboot);
                        workingDirectory = Path.GetDirectoryName(innerFlasher) ?? extractDir;
                    }
                    else
                    {
                        // The package already ran once. A package that ignores /EXTRACT=YES installs and flashes during that run,
                        // so running it again could flash twice.
                        return ExtractionFailed(extractResult, LenovoFlasherNotFound);
                    }
                }
                else
                {
                    executablePath = stagedPath;
                    arguments = BiosAgentInstallModes.BuildArguments(mode, request.AllowReboot);
                    workingDirectory = runStagingDir;
                }
            }

            return await ExecuteInstallerAsync(executablePath, arguments, timeout, workingDirectory, ct).ConfigureAwait(false);
        }
        finally
        {
            TryDeleteDirectoryRecursive(runStagingDir);
        }
    }

    internal const string HpFlasherNotFound =
        "Couldn't unpack the HP SoftPaq to find its BIOS flasher, so nothing was flashed. Install this BIOS update with HP Support Assistant or HP Image Assistant.";
    internal const string LenovoFlasherNotFound =
        "Couldn't unpack the Lenovo BIOS package to find its flasher, so it wasn't run again. Restart the PC and check the BIOS version: if the package applied the update itself, it shows there. Otherwise install it with Lenovo Vantage or Lenovo System Update.";

    /// <summary>
    /// A vendor package that ran only to unpack itself and gave no flasher: a failed install (never run a second time). Executed is
    /// false so the caller shows <paramref name="reason"/> instead of reading the unpack run's exit code as the flasher's.
    /// </summary>
    internal static BiosAgentInstallResult ExtractionFailed(BiosAgentInstallResult extract, string reason) =>
        new(Executed: false, Allowed: true, ExitCode: extract.ExitCode, TimedOut: false, LogTail: extract.LogTail, Error: reason);

    private static readonly string[] HpInnerFlasherNames =
    [
        "HpFirmwareUpdRec64.exe",
        "HPBIOSUPDREC64.exe",
        "HpFirmwareUpdRec.exe",
        "HPBIOSUPDREC.exe",
    ];

    private static readonly string[] LenovoInnerFlasherNames =
    [
        "WINUPTP64.exe",
        "WINUPTP.exe",
    ];

    internal static IReadOnlyList<string> BuildHpSoftPaqExtractArguments(string extractDir) =>
        ["-pdf", $"-f{extractDir}", "-s", "-e"];

    private static IReadOnlyList<string> ListExtractedExeNames(string extractDir)
    {
        if (!Directory.Exists(extractDir)) return [];
        try { return Directory.GetFiles(extractDir, "*.exe", SearchOption.AllDirectories).Select(Path.GetFileName).Where(n => n is not null).Cast<string>().Take(12).ToList(); }
        catch { return []; }
    }

    internal static IReadOnlyList<string> BuildLenovoSfxExtractArguments(string extractDir) =>
        ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", $"/DIR={extractDir}", "/EXTRACT=YES"];

    internal static bool IsHpSoftPaqExecutable(string path)
    {
        var name = Path.GetFileName(path);
        if (name.Length < 7 || !name.StartsWith("sp", StringComparison.OrdinalIgnoreCase)
            || !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return false;
        for (var i = 2; i < name.Length - 4; i++)
            if (!char.IsAsciiDigit(name[i])) return false;
        return true;
    }

    internal static bool IsLenovoSfxExecutable(string path)
    {
        var name = Path.GetFileName(path);
        return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            && !name.Contains("winuptp", StringComparison.OrdinalIgnoreCase);
    }

    internal static string? FindExtractedHpFlasher(string extractDir) =>
        FindExtractedFlasher(extractDir, HpInnerFlasherNames);

    internal static string? FindExtractedLenovoFlasher(string extractDir) =>
        FindExtractedFlasher(extractDir, LenovoInnerFlasherNames);

    private static string? FindExtractedFlasher(string extractDir, IReadOnlyList<string> preferredNames)
    {
        if (!Directory.Exists(extractDir)) return null;
        string[] exes;
        try { exes = Directory.GetFiles(extractDir, "*.exe", SearchOption.AllDirectories); }
        catch { return null; }

        foreach (var preferred in preferredNames)
        {
            var match = exes.FirstOrDefault(p =>
                string.Equals(Path.GetFileName(p), preferred, StringComparison.OrdinalIgnoreCase));
            if (match is not null) return match;
        }
        return null;
    }

    public async Task<BiosWuaInstallOutcome> InstallWindowsUpdateAsync(Guid updateId, TimeSpan timeout, CancellationToken ct = default)
    {
        if (updateId == Guid.Empty)
        {
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: -1,
                RebootRequired: false,
                Message: "A valid non-empty Windows Update ID is required.");
        }

        if (_wuaApiFactory is null && !OperatingSystem.IsWindows())
        {
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: AgentWindowsUpdate.FailedCode,
                RebootRequired: false,
                Message: "Windows Update Agent is only available on Windows.");
        }

        var clampedTimeout = TimeSpan.FromMilliseconds(Math.Clamp(timeout.TotalMilliseconds, MinTimeoutMs, MaxTimeoutMs));

        // The COM install can't be stopped once started, so a timed-out one keeps running. Remember it: a retry for the same update
        // waits on that install instead of starting a second one.
        Task<SingleUpdateInstallResult> install;
        lock (_wuaInstallsLock)
        {
            if (!_wuaInstalls.TryGetValue(updateId, out install!) || install.IsCompleted)
            {
                install = Task.Run(() =>
                {
                    var api = _wuaApiFactory is not null
                        ? _wuaApiFactory()
                        : CreateWindowsWuaApi();
                    try
                    {
                        return AgentWindowsUpdate.InstallOneDetailed(api, updateId);
                    }
                    finally
                    {
                        if (api is IDisposable disposable)
                        {
                            try { disposable.Dispose(); } catch { }
                        }
                    }
                }, CancellationToken.None);
                _wuaInstalls[updateId] = install;
            }
        }

        SingleUpdateInstallResult r;
        try
        {
            r = await install.WaitAsync(clampedTimeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException)
        {
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: AgentWindowsUpdate.FailedCode,
                RebootRequired: false,
                Message: $"Windows Update is still installing firmware update {updateId:D} after {clampedTimeout.TotalSeconds:F0}s. It may finish and be applied at the next restart; asking again waits for this same install.");
        }
        catch (Exception ex)
        {
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: AgentWindowsUpdate.FailedCode,
                RebootRequired: false,
                Message: $"Windows Update install failed: {AgentWindowsUpdate.Describe(ex)}");
        }

        if (!string.IsNullOrEmpty(r.Error))
        {
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: r.ResultCode > 0 ? r.ResultCode : AgentWindowsUpdate.FailedCode,
                RebootRequired: false,
                Message: r.Error);
        }

        if (!r.Found)
        {
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: -1,
                RebootRequired: false,
                Message: $"Windows Update no longer offers update {updateId:D}.");
        }

        if (r.ResultCode == -1)
        {
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: r.DownloadResult,
                RebootRequired: false,
                Message: $"Windows Update download failed for {r.Title} (result code {r.DownloadResult}).");
        }

        if (r.Installed)
        {
            return new BiosWuaInstallOutcome(
                Succeeded: true,
                ResultCode: r.ResultCode,
                RebootRequired: r.RebootRequired,
                Message: r.RebootRequired
                    ? $"Installed {r.Title}. Reboot required."
                    : $"Installed {r.Title}.");
        }

        return new BiosWuaInstallOutcome(
            Succeeded: false,
            ResultCode: r.ResultCode,
            RebootRequired: r.RebootRequired,
            Message: $"Windows Update install failed for {r.Title} (result={r.ResultCode}, hresult=0x{unchecked((uint)r.HResult):X8}).");
    }

    private async Task<BiosAgentInstallResult> RunAllowlistedDcuCliAsync(
        BiosAgentInstallRequest request,
        string? normalizedSha256,
        TimeSpan timeout,
        CancellationToken ct)
    {
        if (_allowedToolRoots.Count == 0)
            return Reject("No allowlisted Dell Command | Update installation roots are configured.");

        var pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        var candidates = _allowedToolRoots
            .Select(root => Path.GetFullPath(Path.Combine(root, "Dell", "CommandUpdate", "dcu-cli.exe")))
            .Distinct(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal)
            .ToList();

        string? resolvedTool = null;
        if (!string.IsNullOrEmpty(request.PackagePath))
        {
            if (!TryValidatePackagePathSyntax(request.PackagePath, ".exe", out var validatedPath, out var pathError))
                return Reject(pathError);

            var canonical = Path.GetFullPath(validatedPath);
            if (!candidates.Any(c => string.Equals(c, canonical, pathComparison)))
                return Reject("Dell Command | Update CLI path is outside allowlisted installation roots.");

            resolvedTool = canonical;
        }
        else
        {
            foreach (var candidate in candidates)
            {
                if (File.Exists(candidate) && !Directory.Exists(candidate))
                {
                    resolvedTool = candidate;
                    break;
                }
            }

            if (resolvedTool is null)
                return Reject("Dell Command | Update CLI was not found in allowlisted installation roots.");
        }

        if (!TryValidateRegularFileAndAncestors(resolvedTool, _maxPackageBytes, out var fileError))
            return Reject(fileError);

        if (!string.IsNullOrEmpty(normalizedSha256))
        {
            var (shaValid, _) = await BiosPackageVerifier.VerifyFileSha256Async(resolvedTool, normalizedSha256, ct).ConfigureAwait(false);
            if (!shaValid)
                return Reject("Dell Command | Update CLI failed Agent SHA-256 verification.");
        }

        var sigValid = await _signatureVerifier.VerifyAuthenticodeAsync(resolvedTool, BiosAgentInstallModes.AllowedSignerOrganizations(BiosAgentInstallModes.DellDcuCli), ct).ConfigureAwait(false);
        if (!sigValid)
            return Reject("Dell Command | Update CLI failed Agent Authenticode signature verification.");

        var arguments = BiosAgentInstallModes.BuildArguments(BiosAgentInstallModes.DellDcuCli, request.AllowReboot);
        return await ExecuteInstallerAsync(
            resolvedTool,
            arguments,
            timeout,
            Path.GetDirectoryName(resolvedTool),
            ct).ConfigureAwait(false);
    }

    private async Task<BiosAgentInstallResult> ExecuteInstallerAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        string? workingDirectory,
        CancellationToken ct)
    {
        ProcessResult pr;
        try
        {
            pr = await _launcher.RunAsync(executablePath, arguments, timeout, ct, workingDirectory).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log?.Warn($"[agent-bios] BIOS installer '{Path.GetFileName(executablePath)}' failed to launch: {ex.Message}");
            return new BiosAgentInstallResult(
                Executed: false,
                Allowed: true,
                ExitCode: -1,
                TimedOut: false,
                LogTail: null,
                Error: $"BIOS installer failed to launch: {ex.Message}");
        }

        var logTail = BiosInstallerRunner.BuildSanitizedLogTail(pr.StdOut, pr.StdErr, serialNumber: null);
        return new BiosAgentInstallResult(
            Executed: true,
            Allowed: true,
            ExitCode: pr.ExitCode,
            TimedOut: pr.TimedOut,
            LogTail: logTail,
            Error: pr.TimedOut ? "BIOS installer timed out." : null);
    }

    private async Task<string?> CopyToAdminStagingAsync(string sourcePath, string stagedPath, CancellationToken ct)
    {
        try
        {
            await using var src = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, CopyBufferSize, useAsync: true);
            if (!IsRegularNonSymlinkFile(sourcePath))
                return "BIOS package path changed to an unsafe link during staging.";

            await using var dst = new FileStream(stagedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, CopyBufferSize, useAsync: true);
            var buffer = new byte[CopyBufferSize];
            long totalCopied = 0;

            while (true)
            {
                var read = await src.ReadAsync(buffer, ct).ConfigureAwait(false);
                if (read == 0)
                    break;

                totalCopied += read;
                if (totalCopied > _maxPackageBytes)
                    return $"BIOS package exceeds maximum allowed size of {_maxPackageBytes} bytes.";

                await dst.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            }

            if (totalCopied <= 0)
                return "BIOS package file is empty.";

            await dst.FlushAsync(ct).ConfigureAwait(false);
            return null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return $"Failed to copy BIOS package into admin staging directory: {ex.Message}";
        }
    }

    private async Task<string?> ExtractCabToStagingAsync(string stagedCabPath, string extractDir, CancellationToken ct)
    {
        byte[] cabBytes;
        try
        {
            var info = new FileInfo(stagedCabPath);
            if (!info.Exists || info.Length <= 0 || info.Length > _maxPackageBytes || info.Length > Array.MaxLength)
                return "BIOS cabinet archive size is invalid.";

            cabBytes = await File.ReadAllBytesAsync(stagedCabPath, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return $"Failed to read BIOS cabinet archive: {ex.Message}";
        }

        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(extractDir));
        var rootWithSep = fullRoot.EndsWith(Path.DirectorySeparatorChar)
            ? fullRoot
            : fullRoot + Path.DirectorySeparatorChar;
        var pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        var cabStatus = BiosArchiveAndXml.TryExtractCabEntriesWithStatus(cabBytes, out var entries, _maxPackageBytes);
        if (cabStatus == CabExtractionStatus.Succeeded)
        {
            try
            {
                long totalWritten = 0;
                foreach (var (rawName, content) in entries)
                {
                    ct.ThrowIfCancellationRequested();

                    if (!TryValidateRelativeArchivePath(rawName, out var segments))
                        return "BIOS cabinet archive contains an unsafe entry path.";

                    var destPath = Path.GetFullPath(Path.Combine([fullRoot, .. segments]));
                    if (!destPath.StartsWith(rootWithSep, pathComparison))
                        return "BIOS cabinet archive entry escapes staging directory.";

                    totalWritten += content.LongLength;
                    if (totalWritten > _maxPackageBytes)
                        return $"BIOS cabinet archive exceeds maximum extracted size of {_maxPackageBytes} bytes.";

                    var currentDir = fullRoot;
                    for (var i = 0; i < segments.Length - 1; i++)
                    {
                        currentDir = Path.Combine(currentDir, segments[i]);
                        if (IsSymlinkOrReparsePath(currentDir))
                            return "BIOS cabinet archive extraction encountered an unsafe link.";
                        if (File.Exists(currentDir))
                            return "BIOS cabinet archive contains conflicting file and directory paths.";
                        if (!Directory.Exists(currentDir))
                            Directory.CreateDirectory(currentDir);
                        if (IsSymlinkOrReparsePath(currentDir))
                            return "BIOS cabinet archive extraction encountered an unsafe link.";
                    }

                    if (IsSymlinkOrReparsePath(destPath))
                        return "BIOS cabinet archive extraction encountered an unsafe target file.";
                    if (Directory.Exists(destPath))
                        return "BIOS cabinet archive contains conflicting file and directory paths.";

                    await File.WriteAllBytesAsync(destPath, content, ct).ConfigureAwait(false);
                }

                return null;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return "BIOS cabinet archive could not be extracted safely.";
            }
        }

        if (cabStatus == CabExtractionStatus.UnsupportedCompression
            && OperatingSystem.IsWindows()
            && _launcher is SystemProcessLauncher)
        {
            var expandTool = SystemCommandRunner.SystemTool("expand.exe");
            ProcessResult pr;
            try
            {
                pr = await _launcher.RunAsync(expandTool, ["-F:*", stagedCabPath, extractDir], ExpandTimeout, ct, extractDir)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                return $"Failed to expand BIOS cabinet archive: {ex.Message}";
            }

            if (pr.TimedOut || pr.ExitCode != 0)
                return "Failed to expand BIOS cabinet archive.";

            if (!VerifyExtractedTreeSafe(fullRoot, rootWithSep, pathComparison, _maxPackageBytes))
                return "Expanded BIOS cabinet contents failed safety verification.";

            return null;
        }

        return "BIOS cabinet archive could not be extracted safely.";
    }

    private static bool TryResolveInfPath(
        string extractDir,
        string? requestedRelativePath,
        out string resolvedInfPath,
        out string error)
    {
        resolvedInfPath = "";
        error = "";

        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(extractDir));
        var rootWithSep = fullRoot.EndsWith(Path.DirectorySeparatorChar)
            ? fullRoot
            : fullRoot + Path.DirectorySeparatorChar;
        var pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        if (!string.IsNullOrEmpty(requestedRelativePath))
        {
            if (requestedRelativePath != requestedRelativePath.Trim() ||
                !TryValidateRelativeArchivePath(requestedRelativePath, out var segments) ||
                !string.Equals(Path.GetExtension(segments[^1]), ".inf", StringComparison.OrdinalIgnoreCase))
            {
                error = "Requested INF relative path is invalid.";
                return false;
            }

            var candidate = Path.GetFullPath(Path.Combine([fullRoot, .. segments]));
            if (!candidate.StartsWith(rootWithSep, pathComparison) ||
                !File.Exists(candidate) ||
                Directory.Exists(candidate) ||
                !IsRegularNonSymlinkFileWithinRoot(candidate, fullRoot))
            {
                error = "Requested INF file was not found safely inside the extracted cabinet.";
                return false;
            }

            resolvedInfPath = candidate;
            return true;
        }

        var infCandidates = Directory
            .EnumerateFiles(fullRoot, "*.inf", SearchOption.AllDirectories)
            .OrderBy(static p => p, StringComparer.Ordinal);

        foreach (var candidate in infCandidates)
        {
            var fullCandidate = Path.GetFullPath(candidate);
            if (!fullCandidate.StartsWith(rootWithSep, pathComparison))
                continue;

            var rel = Path.GetRelativePath(fullRoot, fullCandidate);
            if (!TryValidateRelativeArchivePath(rel, out _))
                continue;

            if (!IsRegularNonSymlinkFileWithinRoot(fullCandidate, fullRoot))
                continue;

            resolvedInfPath = fullCandidate;
            return true;
        }

        error = "No valid firmware INF file was found inside the BIOS cabinet package.";
        return false;
    }

    private async Task<bool> HasSignedCatalogCoveringFileAsync(string extractDir, string targetFilePath, CancellationToken ct)
    {
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(extractDir));
        var rootWithSep = fullRoot.EndsWith(Path.DirectorySeparatorChar)
            ? fullRoot
            : fullRoot + Path.DirectorySeparatorChar;
        var pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        var fullTarget = Path.GetFullPath(targetFilePath);
        if (!fullTarget.StartsWith(rootWithSep, pathComparison) || !IsRegularNonSymlinkFileWithinRoot(fullTarget, fullRoot))
            return false;

        var catCandidates = Directory
            .EnumerateFiles(fullRoot, "*.cat", SearchOption.AllDirectories)
            .OrderBy(static p => p, StringComparer.Ordinal);

        foreach (var candidate in catCandidates)
        {
            var fullCandidate = Path.GetFullPath(candidate);
            if (!fullCandidate.StartsWith(rootWithSep, pathComparison))
                continue;
            if (!IsRegularNonSymlinkFileWithinRoot(fullCandidate, fullRoot))
                continue;

            if (await _signatureVerifier.VerifyCatalogMemberAsync(
                    fullCandidate,
                    fullTarget,
                    BiosAgentInstallModes.AllowedCatalogSignerOrganizations,
                    ct).ConfigureAwait(false))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryValidatePackagePathSyntax(
        string? rawPath,
        string requiredExtension,
        out string validatedPath,
        out string error)
    {
        validatedPath = "";
        error = "";

        if (string.IsNullOrWhiteSpace(rawPath))
        {
            error = "BIOS package path is required.";
            return false;
        }

        if (rawPath.Length > MaxPathLength)
        {
            error = "BIOS package path exceeds maximum allowed length.";
            return false;
        }

        if (rawPath != rawPath.Trim())
        {
            error = "BIOS package path must not contain leading or trailing whitespace.";
            return false;
        }

        if (rawPath.StartsWith(@"\\", StringComparison.Ordinal) ||
            rawPath.StartsWith("//", StringComparison.Ordinal) ||
            rawPath.StartsWith(@"\??\", StringComparison.Ordinal) ||
            rawPath.StartsWith(@"\/", StringComparison.Ordinal) ||
            rawPath.StartsWith(@"/\", StringComparison.Ordinal))
        {
            error = "Network, UNC, and device paths are not permitted for BIOS packages.";
            return false;
        }

        var isWindowsDriveRoot = rawPath.Length >= 3
            && char.IsAsciiLetter(rawPath[0])
            && rawPath[1] == ':'
            && (rawPath[2] == '\\' || rawPath[2] == '/');

        for (var i = 0; i < rawPath.Length; i++)
        {
            var c = rawPath[i];
            if (char.IsControl(c))
            {
                error = "BIOS package path contains disallowed control characters.";
                return false;
            }

            if (Array.IndexOf(ForbiddenPathChars, c) >= 0)
            {
                error = "BIOS package path contains disallowed special characters.";
                return false;
            }

            if (c == ':' && !(i == 1 && isWindowsDriveRoot))
            {
                error = "BIOS package path contains a disallowed colon (alternate data streams and URIs are forbidden).";
                return false;
            }
        }

        if (!Path.IsPathFullyQualified(rawPath))
        {
            error = "BIOS package path must be a fully qualified local path.";
            return false;
        }

        var segments = rawPath.Split(['\\', '/'], StringSplitOptions.None);
        foreach (var segment in segments)
        {
            if (segment is "." or "..")
            {
                error = "BIOS package path must not contain relative directory traversal segments.";
                return false;
            }
        }

        if (!string.Equals(Path.GetExtension(rawPath), requiredExtension, StringComparison.OrdinalIgnoreCase))
        {
            error = $"BIOS package file must have the '{requiredExtension}' extension for the selected install mode.";
            return false;
        }

        validatedPath = rawPath;
        return true;
    }

    private static bool TryValidateRelativeArchivePath(string? relativePath, out string[] segments)
    {
        segments = [];
        if (string.IsNullOrWhiteSpace(relativePath) || relativePath.Length > MaxPathLength)
            return false;

        if (relativePath.StartsWith('/') || relativePath.StartsWith('\\'))
            return false;

        foreach (var c in relativePath)
        {
            if (char.IsControl(c) || c == ':' || Array.IndexOf(ForbiddenPathChars, c) >= 0)
                return false;
        }

        var normalized = relativePath.Replace('\\', '/');
        if (normalized.EndsWith('/'))
            return false;

        var rawSegments = normalized.Split('/', StringSplitOptions.None);
        if (rawSegments.Length == 0)
            return false;

        foreach (var seg in rawSegments)
        {
            if (string.IsNullOrWhiteSpace(seg) || seg is "." or "..")
                return false;
        }

        segments = rawSegments;
        return true;
    }

    private static bool TryValidateRegularFileAndAncestors(string filePath, long maxBytes, out string error)
    {
        error = "";

        if (IsSymlinkOrReparsePath(filePath))
        {
            error = "BIOS package path must reference a regular non-link file.";
            return false;
        }

        if (Directory.Exists(filePath) || !File.Exists(filePath))
        {
            error = "BIOS package file does not exist or is a directory.";
            return false;
        }

        try
        {
            var fi = new FileInfo(filePath);
            if (!fi.Exists ||
                fi.LinkTarget is not null ||
                (fi.Attributes & FileAttributes.ReparsePoint) != 0 ||
                (fi.Attributes & FileAttributes.Directory) != 0)
            {
                error = "BIOS package path must reference a regular non-link file.";
                return false;
            }

            if (fi.Length <= 0 || fi.Length > maxBytes)
            {
                error = $"BIOS package file size must be between 1 and {maxBytes} bytes.";
                return false;
            }

            if (HasSymlinkOrReparseAncestor(fi.Directory))
            {
                error = "BIOS package path must not traverse a symbolic link or reparse point.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = $"Failed to inspect BIOS package file: {ex.Message}";
            return false;
        }
    }

    private static bool HasSymlinkOrReparseAncestor(DirectoryInfo? dir)
    {
        if (dir is null)
            return false;

        var startPath = Path.TrimEndingDirectorySeparator(dir.FullName);
        for (var current = new DirectoryInfo(startPath); current is not null; current = current.Parent)
        {
            if (current.LinkTarget is not null)
                return true;

            if (!current.Exists)
                continue;

            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                return true;
        }

        return false;
    }

    private static bool IsRegularNonSymlinkFile(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            return fi.Exists
                && fi.LinkTarget is null
                && (fi.Attributes & FileAttributes.ReparsePoint) == 0
                && (fi.Attributes & FileAttributes.Directory) == 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsRegularNonSymlinkFileWithinRoot(string filePath, string rootDir)
    {
        if (!IsRegularNonSymlinkFile(filePath))
            return false;

        try
        {
            var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootDir));
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            var current = new FileInfo(filePath).Directory;
            while (current is not null)
            {
                if (current.LinkTarget is not null || (current.Attributes & FileAttributes.ReparsePoint) != 0)
                    return false;

                var fullCurrent = Path.TrimEndingDirectorySeparator(Path.GetFullPath(current.FullName));
                if (string.Equals(fullCurrent, fullRoot, comparison))
                    return true;

                current = current.Parent;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsSymlinkOrReparsePath(string path)
    {
        try
        {
            var normalized = Path.TrimEndingDirectorySeparator(path);
            var fi = new FileInfo(normalized);
            if (fi.LinkTarget is not null)
                return true;

            var di = new DirectoryInfo(normalized);
            if (di.LinkTarget is not null)
                return true;

            if (fi.Exists)
                return (fi.Attributes & FileAttributes.ReparsePoint) != 0;

            if (di.Exists)
                return (di.Attributes & FileAttributes.ReparsePoint) != 0;

            return false;
        }
        catch
        {
            return true;
        }
    }

    private static bool VerifyExtractedTreeSafe(string fullRoot, string rootWithSep, StringComparison comparison, long maxBytes)
    {
        try
        {
            long total = 0;
            foreach (var dir in Directory.EnumerateDirectories(fullRoot, "*", SearchOption.AllDirectories))
            {
                var full = Path.GetFullPath(dir);
                if (!full.StartsWith(rootWithSep, comparison) || IsSymlinkOrReparsePath(full))
                    return false;
            }

            foreach (var file in Directory.EnumerateFiles(fullRoot, "*", SearchOption.AllDirectories))
            {
                var full = Path.GetFullPath(file);
                if (!full.StartsWith(rootWithSep, comparison) || !IsRegularNonSymlinkFile(full))
                    return false;

                var len = new FileInfo(full).Length;
                if (len < 0 || total > maxBytes - len)
                    return false;
                total += len;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool TryCreateRunStagingDirectory(out string runStagingDir, out string error)
    {
        runStagingDir = "";
        error = "";

        try
        {
            var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(_stagingRoot));
            if (IsSymlinkOrReparsePath(fullRoot) || HasSymlinkOrReparseAncestor(new DirectoryInfo(fullRoot)))
            {
                error = "Admin staging root traverses a symbolic link or reparse point.";
                return false;
            }

            if (!EnsureSecureDirectory(fullRoot, isNewUniqueDir: false, out error))
                return false;

            var candidate = Path.Combine(fullRoot, Guid.NewGuid().ToString("N"));
            if (!EnsureSecureDirectory(candidate, isNewUniqueDir: true, out error))
                return false;

            runStagingDir = candidate;
            return true;
        }
        catch (Exception ex)
        {
            error = $"Failed to initialize admin staging directory: {ex.Message}";
            return false;
        }
    }

    private bool TryCreateSecureSubdirectory(string path, out string error) =>
        EnsureSecureDirectory(path, isNewUniqueDir: true, out error);

    private bool EnsureSecureDirectory(string path, bool isNewUniqueDir, out string error)
    {
        error = "";
        try
        {
            if (OperatingSystem.IsWindows())
                return EnsureSecureDirectoryWindows(path, isNewUniqueDir, out error);

            if (IsSymlinkOrReparsePath(path))
            {
                error = "Staging directory is an unsafe symbolic link or reparse point.";
                return false;
            }

            if (isNewUniqueDir && Directory.Exists(path))
            {
                error = "Staging subdirectory unexpectedly already exists.";
                return false;
            }

            if (File.Exists(path))
            {
                error = "Staging directory path conflicts with an existing file.";
                return false;
            }

            Directory.CreateDirectory(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            if (IsSymlinkOrReparsePath(path))
            {
                error = "Staging directory is an unsafe symbolic link or reparse point.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = $"Failed to secure admin staging directory: {ex.Message}";
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private bool EnsureSecureDirectoryWindows(string path, bool isNewUniqueDir, out string error)
    {
        error = "";
        var normalizedPath = Path.TrimEndingDirectorySeparator(path);
        var dirInfo = new DirectoryInfo(normalizedPath);

        if (dirInfo.LinkTarget is not null || IsSymlinkOrReparsePath(normalizedPath))
        {
            error = "Staging directory is an unsafe symbolic link or reparse point.";
            return false;
        }

        if (File.Exists(normalizedPath))
        {
            error = "Staging directory path conflicts with an existing file.";
            return false;
        }

        if (isNewUniqueDir && dirInfo.Exists)
        {
            error = "Staging subdirectory unexpectedly already exists.";
            return false;
        }

        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        if (Environment.IsPrivilegedProcess)
        {
            // Ensure ProtectedState.AppDataFolder() exists BEFORE creating BiosStaging with admin-only ACLs
            // so Users ReadAndExecute on the parent AppDataFolder is never overwritten.
            if (!_isCustomStagingRoot && !isNewUniqueDir)
            {
                var parentPath = dirInfo.Parent?.FullName ?? ProtectedState.AppDataFolder();
                if (!string.IsNullOrWhiteSpace(parentPath))
                {
                    if (IsSymlinkOrReparsePath(parentPath))
                    {
                        error = "Parent directory of admin staging root is an unsafe symbolic link or reparse point.";
                        return false;
                    }

                    if (!Directory.Exists(parentPath))
                        Directory.CreateDirectory(parentPath);
                }
            }

            var security = BuildAdminOnlyDirectorySecurity(admins, system);
            if (!dirInfo.Exists)
            {
                FileSystemAclExtensions.Create(dirInfo, security);
            }
            else
            {
                if (dirInfo.LinkTarget is not null || (dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    error = "Staging directory is an unsafe reparse point.";
                    return false;
                }

                FileSystemAclExtensions.SetAccessControl(dirInfo, security);
            }

            dirInfo.Refresh();
            if (!dirInfo.Exists || dirInfo.LinkTarget is not null || (dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                error = "Staging directory could not be verified as a secure local directory.";
                return false;
            }

            if (!VerifyAdminDirectoryAclWindows(dirInfo, admins, system))
            {
                error = "Staging directory failed Windows owner and admin-only ACL verification.";
                return false;
            }

            return true;
        }

        // Non-elevated Windows process: NEVER relax ACLs on the default production staging root.
        if (!_isCustomStagingRoot)
        {
            error = "Default admin staging directory requires an elevated process on Windows.";
            return false;
        }

        using var currentIdentity = WindowsIdentity.GetCurrent();
        var currentUser = currentIdentity?.User;
        var scopedSecurity = BuildScopedNonElevatedDirectorySecurity(admins, system, currentUser);

        if (!dirInfo.Exists)
        {
            FileSystemAclExtensions.Create(dirInfo, scopedSecurity);
        }
        else
        {
            if (dirInfo.LinkTarget is not null || (dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                error = "Staging directory is an unsafe reparse point.";
                return false;
            }

            FileSystemAclExtensions.SetAccessControl(dirInfo, scopedSecurity);
        }

        dirInfo.Refresh();
        if (!dirInfo.Exists || dirInfo.LinkTarget is not null || (dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            error = "Staging directory could not be verified as a secure local directory.";
            return false;
        }

        if (!VerifyScopedNonElevatedDirectoryAclWindows(dirInfo, admins, system, currentUser))
        {
            error = "Staging directory failed Windows protected ACL verification.";
            return false;
        }

        return true;
    }

    [SupportedOSPlatform("windows")]
    private static DirectorySecurity BuildAdminOnlyDirectorySecurity(SecurityIdentifier admins, SecurityIdentifier system)
    {
        var security = new DirectorySecurity();
        security.SetOwner(admins);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            admins,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        return security;
    }

    [SupportedOSPlatform("windows")]
    private static DirectorySecurity BuildScopedNonElevatedDirectorySecurity(
        SecurityIdentifier admins,
        SecurityIdentifier system,
        SecurityIdentifier? currentUser)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        if (currentUser is not null && !currentUser.Equals(admins) && !currentUser.Equals(system))
        {
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        security.AddAccessRule(new FileSystemAccessRule(
            admins,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        return security;
    }

    [SupportedOSPlatform("windows")]
    private static bool VerifyAdminDirectoryAclWindows(
        DirectoryInfo dirInfo,
        SecurityIdentifier admins,
        SecurityIdentifier system)
    {
        var acl = FileSystemAclExtensions.GetAccessControl(dirInfo, AccessControlSections.Owner | AccessControlSections.Access);
        if (acl.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner
            || (!owner.Equals(admins) && !owner.Equals(system)))
        {
            return false;
        }

        if (!acl.AreAccessRulesProtected)
            return false;

        var rules = acl.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        if (rules.Count == 0)
            return false;

        foreach (AuthorizationRule rule in rules)
        {
            if (rule is not FileSystemAccessRule fsRule
                || fsRule.AccessControlType != AccessControlType.Allow
                || fsRule.IdentityReference is not SecurityIdentifier sid
                || (!sid.Equals(admins) && !sid.Equals(system)))
            {
                return false;
            }
        }

        return true;
    }

    [SupportedOSPlatform("windows")]
    private static bool VerifyScopedNonElevatedDirectoryAclWindows(
        DirectoryInfo dirInfo,
        SecurityIdentifier admins,
        SecurityIdentifier system,
        SecurityIdentifier? currentUser)
    {
        var acl = FileSystemAclExtensions.GetAccessControl(dirInfo, AccessControlSections.Access);
        if (!acl.AreAccessRulesProtected)
            return false;

        var rules = acl.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        if (rules.Count == 0)
            return false;

        foreach (AuthorizationRule rule in rules)
        {
            if (rule is not FileSystemAccessRule fsRule
                || fsRule.AccessControlType != AccessControlType.Allow
                || fsRule.IdentityReference is not SecurityIdentifier sid)
            {
                return false;
            }

            var allowed = sid.Equals(admins)
                || sid.Equals(system)
                || (currentUser is not null && sid.Equals(currentUser));
            if (!allowed)
                return false;
        }

        return true;
    }

    [SupportedOSPlatform("windows")]
    private bool TrySuspendBitLockerViaWmiWindows(string drive)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\CIMV2\Security\MicrosoftVolumeEncryption");
            scope.Connect();
            var query = new ObjectQuery($"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = '{drive}'");
            using var searcher = new ManagementObjectSearcher(scope, query);
            using var results = searcher.Get();
            foreach (ManagementObject volume in results)
            {
                using (volume)
                {
                    using var inParams = volume.GetMethodParameters("DisableKeyProtectors");
                    inParams["RebootCount"] = 1u;
                    using var outParams = volume.InvokeMethod("DisableKeyProtectors", inParams, null);
                    var returnCode = Convert.ToUInt32(outParams?["ReturnValue"] ?? 1u, CultureInfo.InvariantCulture);
                    return returnCode == 0u;
                }
            }
        }
        catch (Exception ex)
        {
            _log?.Warn($"[agent-bios] WMI BitLocker suspension fallback failed on {drive}: {ex.Message}");
        }

        return false;
    }

    private static IWindowsUpdateApi CreateWindowsWuaApi()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows Update Agent is only available on Windows.");

        return new WuaComApi();
    }

    private static string ResolveStagingRoot(string? stagingRoot)
    {
        if (!string.IsNullOrWhiteSpace(stagingRoot))
            return stagingRoot.Trim();

        var commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return !string.IsNullOrWhiteSpace(commonAppData)
            ? Path.Combine(ProtectedState.AppDataFolder(), "BiosStaging")
            : Path.Combine(Path.GetTempPath(), "rpd-bios-admin-staging");
    }

    private static IReadOnlyList<string> ResolveAllowedToolRoots(IReadOnlyList<string>? allowedToolRoots)
    {
        IEnumerable<string?> raw = allowedToolRoots ??
        [
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        ];

        var roots = new List<string>();
        foreach (var item in raw)
        {
            if (string.IsNullOrWhiteSpace(item))
                continue;
            var trimmed = item.Trim();
            if (!Path.IsPathFullyQualified(trimmed))
                continue;
            roots.Add(Path.GetFullPath(trimmed));
        }

        return roots;
    }

    private static void TryDeleteDirectoryRecursive(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch
        {
            // Best-effort cleanup of admin staging directory.
        }
    }

    private static BiosAgentInstallResult Reject(string reason) =>
        new(Executed: false, Allowed: false, ExitCode: -1, TimedOut: false, LogTail: null, Error: reason);
}
