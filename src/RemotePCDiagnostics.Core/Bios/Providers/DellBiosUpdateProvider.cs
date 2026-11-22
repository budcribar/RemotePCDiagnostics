using System.Buffers;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Built-in pure-C# BIOS update provider for Dell and Alienware systems.
/// Supports direct HTTPS Dell XML/CAB catalog lookup (<c>CatalogPC.cab</c>) matched by
/// validated 4-hex <c>SystemSku</c>, optional direct <c>dcu-cli.exe</c> invocation via
/// <c>ArgumentList</c> (zero shell/PowerShell), and silent staging for both direct Dell BIOS
/// executables (<c>/s</c>, <c>/r</c> only when <c>AllowReboot == true</c>) and Dell Command | Update CLI
/// (routing privileged operations through <see cref="IElevatedCommandBridge"/> when un-elevated).
/// </summary>
public sealed partial class DellBiosUpdateProvider : IBiosUpdateProvider
{
    public const string ProviderVendorId = "dell";
    public const string DefaultCatalogUrl = "https://downloads.dell.com/catalog/CatalogPC.cab";
    public static readonly IReadOnlyList<string> AllowedHostSuffixes = ["dell.com"];

    private const long MaxCatalogDownloadBytes = 64L * 1024 * 1024;
    private const long MaxCatalogDecompressedBytes = 64L * 1024 * 1024;
    private const int MaxInitialStreamCapacity = 1024 * 1024;
    private const int CopyBufferSize = 81920;
    private const int DcuNoUpdatesExitCode = 500;
    private const int MaxToolPathLength = 512;

    private const string MetadataKeySystemSku = "systemSku";
    private const string MetadataKeyInstallMode = "installMode";
    private const string MetadataKeySource = "source";

    private static readonly HashSet<int> DellExeRebootExitCodes = [0, 2, 3010];
    private static readonly HashSet<int> DellDcuRebootExitCodes = [0, 1];
    private static readonly HashSet<int> DellDcuNoUpdatesExitCodes = [DcuNoUpdatesExitCode];
    private static readonly TimeSpan InstallerTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan DcuScanTimeout = TimeSpan.FromMinutes(3);

    private static readonly char[] ForbiddenPathChars =
    [
        '&', '|', ';', '>', '<', '`', '$', '%', '"', '\'', '^', '!', '*', '?',
    ];

    [GeneratedRegex(@"\A[0-9A-Fa-f]{64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256HexRegex();

    private readonly HttpClient _httpClient;
    private readonly SystemCommandRunner? _commands;
    private readonly IBiosSignatureVerifier _signatureVerifier;
    private readonly IElevatedCommandBridge? _elevatedBridge;
    private readonly Func<bool>? _isProcessElevated;
    private readonly ILogger? _log;
    private readonly string _catalogUrl;
    private readonly string? _dcuCliPath;

    public DellBiosUpdateProvider(
        HttpClient? httpClient = null,
        SystemCommandRunner? commands = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        string? catalogUrl = null,
        string? dcuCliPath = null)
    {
        _httpClient = httpClient ?? BiosProviderHttp.SharedClient;
        _commands = commands;
        _signatureVerifier = signatureVerifier ?? WinVerifyTrustSignatureVerifier.Instance;
        _elevatedBridge = elevatedBridge;
        _isProcessElevated = isProcessElevated;
        _log = log;
        _catalogUrl = string.IsNullOrWhiteSpace(catalogUrl) ? DefaultCatalogUrl : catalogUrl.Trim();
        _dcuCliPath = string.IsNullOrWhiteSpace(dcuCliPath) ? null : dcuCliPath.Trim();
    }

    public static DellBiosUpdateProvider CreateWithHandler(
        HttpMessageHandler httpHandler,
        SystemCommandRunner? commands = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        string? catalogUrl = null,
        string? dcuCliPath = null) =>
        new(
            BiosProviderHttp.CreateClient(httpHandler),
            commands,
            signatureVerifier,
            elevatedBridge,
            isProcessElevated,
            log,
            catalogUrl,
            dcuCliPath);

    public string VendorId => ProviderVendorId;
    public string DisplayName => "Dell";
    public int Priority => 100;

    public BiosProviderCapabilities Capabilities { get; } = new(
        CanCheckLatest: true,
        CanInstall: true,
        SupportsSilentInstall: true,
        RequiresReboot: true,
        RequiresElevation: true,
        RequiresInternet: true);

    public bool CanHandle(BiosSystemIdentity system) =>
        system is not null && BiosVendorIdentity.IsDell(system);

    public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        var baseCurrent = system.CurrentBios ?? BiosCurrentInfo.Empty;
        var current = baseCurrent with
        {
            Version = baseCurrent.Version?.Trim() ?? "",
            ProviderId = VendorId,
        };

        if (BiosVendorIdentity.TryExtractFourHex(system.SystemSku, out var sku))
        {
            var metadata = current.Metadata is not null
                ? new Dictionary<string, string>(current.Metadata, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            metadata[MetadataKeySystemSku] = sku;
            current = current with { Metadata = metadata };
        }

        return Task.FromResult(current);
    }

    public Task<BiosLatestInfo> GetLatestVersionAsync(
        BiosSystemIdentity system,
        BiosCurrentInfo current,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        current ??= system.CurrentBios ?? BiosCurrentInfo.Empty;

        return _dcuCliPath is not null
            ? CheckViaDcuCliAsync(system, current, ct)
            : CheckViaCatalogAsync(system, current, ct);
    }

    public async Task<BiosInstallResult> InstallAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ct.ThrowIfCancellationRequested();

        var metadataRequestsDcu = request.Target?.Metadata is not null
            && request.Target.Metadata.TryGetValue(MetadataKeyInstallMode, out var modeValue)
            && string.Equals(modeValue?.Trim(), BiosAgentInstallModes.DellDcuCli, StringComparison.OrdinalIgnoreCase);

        var hasDownloadUrl = !string.IsNullOrWhiteSpace(request.Target?.DownloadUrl);

        if (metadataRequestsDcu || (!hasDownloadUrl && _dcuCliPath is not null))
            return await InstallViaDcuCliAsync(request, progress, ct).ConfigureAwait(false);

        if (!hasDownloadUrl)
        {
            const string msg = "Dell BIOS update target does not include a download URL and is not configured for Dell Command | Update CLI.";
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, request.Current?.Version, request.Target?.LatestVersion);
        }

        return await InstallViaDirectExeAsync(request, progress, ct).ConfigureAwait(false);
    }

    private async Task<BiosLatestInfo> CheckViaCatalogAsync(
        BiosSystemIdentity system,
        BiosCurrentInfo current,
        CancellationToken ct)
    {
        if (!BiosVendorIdentity.TryExtractFourHex(system.SystemSku, out var systemSku))
        {
            return BiosLatestInfo.Unsupported(
                VendorId,
                "Dell SystemSku (4-hex system ID) is missing or invalid; cannot query the Dell BIOS catalog.");
        }

        if (!BiosProviderHttp.TryValidateHttpsUrl(_catalogUrl, AllowedHostSuffixes, out _, out var catalogUrlErr))
        {
            return BiosLatestInfo.Failed(
                VendorId,
                $"Dell BIOS catalog URL is not allowed: {catalogUrlErr}");
        }

        try
        {
            using var response = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(
                _httpClient,
                _catalogUrl,
                AllowedHostSuffixes,
                HttpCompletionOption.ResponseHeadersRead,
                ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return BiosProviderHttp.ClassifyHttpStatus(
                    VendorId,
                    DisplayName,
                    response.StatusCode,
                    $"SystemSku {systemSku}");
            }

            var payloadBytes = await ReadBoundedBytesAsync(response.Content, MaxCatalogDownloadBytes, ct).ConfigureAwait(false);
            var xmlText = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(
                payloadBytes,
                "dell-catalog",
                _commands,
                ct,
                MaxCatalogDecompressedBytes).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(xmlText))
            {
                return BiosLatestInfo.Failed(
                    VendorId,
                    "Dell BIOS catalog payload did not contain readable XML.");
            }

            var doc = BiosArchiveAndXml.ParseXmlSafe(xmlText);
            return RedactLatestInfo(EvaluateDellCatalog(doc, systemSku, current), system.SerialNumber);
        }
        catch (Exception ex)
        {
            return RedactLatestInfo(
                BiosProviderHttp.ClassifyHttpFailure(VendorId, DisplayName, ex, ct),
                system.SerialNumber);
        }
    }

    private BiosLatestInfo EvaluateDellCatalog(XDocument doc, string systemSku, BiosCurrentInfo current)
    {
        var root = doc.Root;
        var baseLocation = root is not null ? GetAttribute(root, "baseLocation") : null;
        if (string.IsNullOrWhiteSpace(baseLocation))
            baseLocation = "downloads.dell.com";

        var candidates = new List<DellCatalogCandidate>();
        var hadUnsafeCandidate = false;

        foreach (var comp in doc.Descendants())
        {
            if (!comp.Name.LocalName.Equals("SoftwareComponent", StringComparison.OrdinalIgnoreCase))
                continue;

            if (!IsBiosSoftwareComponent(comp))
                continue;

            if (!MatchesSystemSku(comp, systemSku))
                continue;

            var rawPath = GetAttribute(comp, "path");
            if (string.IsNullOrWhiteSpace(rawPath))
                continue;

            if (!TryBuildDellPackageUrl(baseLocation, rawPath, out var downloadUrl))
            {
                hadUnsafeCandidate = true;
                _log?.Warn($"[BIOS/Dell] Rejected catalog entry for SystemSku {systemSku} due to unsafe package URL.");
                continue;
            }

            // Skip non-Windows packages (e.g., Linux .bin DUPs) once URL safety has been verified.
            if (!Uri.TryCreate(downloadUrl, UriKind.Absolute, out var parsedUri)
                || !parsedUri.AbsolutePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var version = FirstNonEmpty(
                GetAttribute(comp, "vendorVersion"),
                GetAttribute(comp, "dellVersion"));
            if (string.IsNullOrWhiteSpace(version))
                continue;

            var sha256 = ExtractSha256(comp);
            var sizeBytes = TryParsePositiveLong(GetAttribute(comp, "size"));
            var releaseDate = ExtractReleaseDate(comp);
            var severity = ExtractCriticality(comp);
            var packageId = FirstNonEmpty(
                GetAttribute(comp, "packageID"),
                GetAttribute(comp, "releaseID"));
            var releaseSummary = FirstNonEmpty(
                ExtractLocalizedDisplay(comp, "Name"),
                ExtractLocalizedDisplay(comp, "Description"));

            string? releaseNotesUrl = null;
            var importantInfo = FindChild(comp, "ImportantInfo");
            var rawNotesUrl = importantInfo is not null ? GetAttribute(importantInfo, "URL") : null;
            if (!string.IsNullOrWhiteSpace(rawNotesUrl)
                && !HasDotSegment(rawNotesUrl)
                && BiosProviderHttp.TryValidateHttpsUrl(rawNotesUrl, AllowedHostSuffixes, out var notesUri, out _))
            {
                releaseNotesUrl = notesUri.AbsoluteUri;
            }

            candidates.Add(new DellCatalogCandidate(
                Version: version,
                ReleaseDate: releaseDate,
                Severity: severity,
                PackageId: packageId,
                ReleaseSummary: releaseSummary,
                ReleaseNotesUrl: releaseNotesUrl,
                DownloadUrl: downloadUrl,
                Sha256: sha256,
                SizeBytes: sizeBytes));
        }

        if (candidates.Count == 0)
        {
            if (hadUnsafeCandidate)
            {
                return BiosLatestInfo.Failed(
                    VendorId,
                    "Dell BIOS catalog entry contained an unsafe or disallowed download URL.");
            }

            return BiosLatestInfo.Unsupported(
                VendorId,
                $"No Dell BIOS update found in catalog for SystemSku {systemSku}.");
        }

        var best = SelectNewestCandidate(candidates);
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [MetadataKeySystemSku] = systemSku,
            [MetadataKeyInstallMode] = BiosAgentInstallModes.DellBiosExe,
            [MetadataKeySource] = "dell-catalog",
        };

        var isNewer = BiosVersionComparer.IsNewer(
            current.Version,
            best.Version,
            current.ReleaseDate,
            best.ReleaseDate);

        if (!isNewer)
        {
            return BiosLatestInfo.UpToDate(
                providerId: VendorId,
                latestVersion: best.Version,
                releaseDate: best.ReleaseDate,
                metadata: metadata);
        }

        return BiosLatestInfo.UpdateAvailable(
            providerId: VendorId,
            latestVersion: best.Version,
            releaseDate: best.ReleaseDate,
            severity: best.Severity,
            packageId: best.PackageId,
            releaseSummary: best.ReleaseSummary,
            releaseNotesUrl: best.ReleaseNotesUrl,
            downloadUrl: best.DownloadUrl,
            sha256: best.Sha256,
            sizeBytes: best.SizeBytes,
            requiresReboot: true,
            metadata: metadata);
    }

    private async Task<BiosLatestInfo> CheckViaDcuCliAsync(
        BiosSystemIdentity system,
        BiosCurrentInfo current,
        CancellationToken ct)
    {
        if (!TryValidateDcuCliPath(_dcuCliPath, out var dcuPath, out var pathErr))
            return BiosLatestInfo.Failed(VendorId, pathErr);

        if (_commands is null)
            return BiosLatestInfo.Unavailable(VendorId, "Command runner is unavailable to run Dell Command | Update CLI.");

        if (!TryValidateDcuCliFileAndAncestors(dcuPath, requireExists: !_commands.IsScripted, out var fileErr, out var missingTool))
        {
            return missingTool
                ? BiosLatestInfo.Unavailable(VendorId, fileErr)
                : BiosLatestInfo.Failed(VendorId, fileErr);
        }

        var reportDir = Path.Combine(Path.GetTempPath(), $"rpd-dell-dcu-{Guid.NewGuid():N}");
        Directory.CreateDirectory(reportDir);

        try
        {
            string[] args = ["/scan", "-updateType=bios", "-silent", $"-report={reportDir}"];
            ProcessResult pr;
            try
            {
                // Call Launcher.RunAsync directly so raw output containing SerialNumber never leaks into commands.Log.
                pr = await _commands.Launcher.RunAsync(dcuPath, args, DcuScanTimeout, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                var safeMessage = BiosInstallerRunner.RedactSerialNumber(ex.Message, system.SerialNumber);
                _log?.Warn($"[BIOS/Dell] Failed to execute Dell Command | Update CLI: {safeMessage}");
                return BiosLatestInfo.Unavailable(VendorId, $"Dell Command | Update CLI execution failed: {safeMessage}");
            }

            if (pr.TimedOut)
                return BiosLatestInfo.Unavailable(VendorId, "Dell Command | Update BIOS scan timed out.");

            var dcuMeta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [MetadataKeyInstallMode] = BiosAgentInstallModes.DellDcuCli,
                [MetadataKeySource] = "dcu-cli",
            };
            if (BiosVendorIdentity.TryExtractFourHex(system.SystemSku, out var validSku))
                dcuMeta[MetadataKeySystemSku] = validSku;

            if (pr.ExitCode == DcuNoUpdatesExitCode)
            {
                return BiosLatestInfo.UpToDate(
                    providerId: VendorId,
                    latestVersion: current.Version,
                    releaseDate: current.ReleaseDate,
                    message: "Dell Command | Update reported no applicable BIOS updates.",
                    metadata: dcuMeta);
            }

            if (pr.ExitCode != 0)
            {
                return BiosLatestInfo.Failed(
                    VendorId,
                    $"Dell Command | Update BIOS scan failed with exit code {pr.ExitCode}.");
            }

            var reportPath = Path.Combine(reportDir, "DCUApplicableUpdates.xml");
            if (!File.Exists(reportPath))
            {
                return BiosLatestInfo.Failed(
                    VendorId,
                    "Dell Command | Update BIOS scan succeeded but DCUApplicableUpdates.xml was not generated.");
            }

            var fi = new FileInfo(reportPath);
            if (fi.LinkTarget is not null
                || (fi.Attributes & FileAttributes.ReparsePoint) != 0
                || (fi.Attributes & FileAttributes.Directory) != 0)
            {
                return BiosLatestInfo.Failed(
                    VendorId,
                    "Dell Command | Update report file is a symbolic link, directory, or reparse point and was rejected.");
            }

            if (fi.Length <= 0 || fi.Length > BiosArchiveAndXml.DefaultMaxXmlCharacters)
            {
                return BiosLatestInfo.Failed(
                    VendorId,
                    "Dell Command | Update report file size is invalid or exceeds safety limits.");
            }

            var xmlText = await File.ReadAllTextAsync(reportPath, ct).ConfigureAwait(false);
            XDocument doc;
            try
            {
                doc = BiosArchiveAndXml.ParseXmlSafe(xmlText);
            }
            catch (Exception ex)
            {
                return RedactLatestInfo(
                    BiosProviderHttp.ClassifyHttpFailure(VendorId, DisplayName, ex, ct),
                    system.SerialNumber);
            }

            return RedactLatestInfo(EvaluateDcuReport(doc, current, dcuMeta), system.SerialNumber);
        }
        finally
        {
            TryDeleteDirectoryRecursive(reportDir);
        }
    }

    private BiosLatestInfo EvaluateDcuReport(
        XDocument doc,
        BiosCurrentInfo current,
        IReadOnlyDictionary<string, string> dcuMeta)
    {
        var candidates = new List<DellCatalogCandidate>();
        foreach (var update in doc.Descendants())
        {
            if (!update.Name.LocalName.Equals("update", StringComparison.OrdinalIgnoreCase))
                continue;

            var type = GetChildValue(update, "type");
            var category = GetChildValue(update, "category");
            var isBios = string.Equals(type, "BIOS", StringComparison.OrdinalIgnoreCase)
                || string.Equals(category, "BIOS", StringComparison.OrdinalIgnoreCase)
                || string.Equals(category, "BI", StringComparison.OrdinalIgnoreCase);

            if (!isBios)
                continue;

            var version = GetChildValue(update, "version");
            if (string.IsNullOrWhiteSpace(version))
                continue;

            var packageId = GetChildValue(update, "release");
            var name = GetChildValue(update, "name");
            var releaseDate = BiosVersionComparer.TryParseReleaseDate(GetChildValue(update, "date"));
            var severity = ParseSeverityText(GetChildValue(update, "urgency"));
            var sizeBytes = TryParsePositiveLong(GetChildValue(update, "bytes"));

            candidates.Add(new DellCatalogCandidate(
                Version: version,
                ReleaseDate: releaseDate,
                Severity: severity,
                PackageId: packageId,
                ReleaseSummary: name,
                ReleaseNotesUrl: null,
                DownloadUrl: null,
                Sha256: null,
                SizeBytes: sizeBytes));
        }

        if (candidates.Count == 0)
        {
            return BiosLatestInfo.UpToDate(
                providerId: VendorId,
                latestVersion: current.Version,
                releaseDate: current.ReleaseDate,
                message: "No applicable BIOS updates were reported by Dell Command | Update.",
                metadata: dcuMeta);
        }

        var best = SelectNewestCandidate(candidates);
        var isNewer = BiosVersionComparer.IsNewer(
            current.Version,
            best.Version,
            current.ReleaseDate,
            best.ReleaseDate);

        if (!isNewer)
        {
            return BiosLatestInfo.UpToDate(
                providerId: VendorId,
                latestVersion: best.Version,
                releaseDate: best.ReleaseDate,
                metadata: dcuMeta);
        }

        return BiosLatestInfo.UpdateAvailable(
            providerId: VendorId,
            latestVersion: best.Version,
            releaseDate: best.ReleaseDate,
            severity: best.Severity,
            packageId: best.PackageId,
            releaseSummary: best.ReleaseSummary,
            releaseNotesUrl: null,
            downloadUrl: null,
            sha256: null,
            sizeBytes: best.SizeBytes,
            requiresReboot: true,
            metadata: dcuMeta);
    }

    private async Task<BiosInstallResult> InstallViaDirectExeAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress,
        CancellationToken ct)
    {
        var prev = request.Current?.Version;
        var target = request.Target?.LatestVersion;

        string? autoStagingDir = null;
        var effectiveRequest = request;
        if (string.IsNullOrWhiteSpace(request.StagingDirectory))
        {
            autoStagingDir = Path.Combine(Path.GetTempPath(), $"rpd-bios-dell-{Guid.NewGuid():N}");
            effectiveRequest = request with { StagingDirectory = autoStagingDir };
        }

        try
        {
            var verified = await BiosPackageVerification.DownloadAndVerifyAsync(
                _httpClient,
                effectiveRequest,
                VendorId,
                AllowedHostSuffixes,
                "dell-bios-update.exe",
                _signatureVerifier,
                progress,
                _log,
                ct).ConfigureAwait(false);

            if (!verified.Succeeded || string.IsNullOrWhiteSpace(verified.FilePath))
            {
                var err = verified.ErrorMessage ?? "Dell BIOS package download or verification failed.";
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, err));
                return BiosInstallResult.Failed(err, prev, target);
            }

            if (!TryEnsureExecutableExtension(verified.FilePath, out var packagePath, out var extError))
            {
                TryDeleteFile(verified.FilePath);
                var safeExtError = BiosInstallerRunner.RedactSerialNumber(extError, request.System?.SerialNumber);
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, safeExtError));
                return BiosInstallResult.Failed(safeExtError, prev, target);
            }

            var bitLocker = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
                effectiveRequest,
                _commands,
                progress,
                _log,
                ct,
                bridge: _elevatedBridge,
                isProcessElevated: _isProcessElevated).ConfigureAwait(false);

            if (bitLocker.ElevationRequired)
            {
                var msg = bitLocker.Message
                    ?? $"Administrator rights (or the elevated Agent service) are required to suspend BitLocker. {ElevationService.AdminRepairHint}";
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
                return BiosInstallResult.Failed(msg, prev, target, exitCode: SystemCommandRunner.AgentFailedExitCode);
            }

            progress?.Report(new BiosInstallProgress(
                BiosInstallStage.Staging,
                0,
                $"Staging Dell BIOS update {target ?? "package"}..."));

            var args = BiosAgentInstallModes.BuildArguments(BiosAgentInstallModes.DellBiosExe, request.AllowReboot);
            var expectedSha256 = !string.IsNullOrWhiteSpace(verified.ActualSha256)
                ? verified.ActualSha256
                : await BiosPackageVerifier.ComputeSha256HexAsync(packagePath, ct).ConfigureAwait(false);

            var agentRequest = new BiosAgentInstallRequest(
                VendorId: VendorId,
                InstallMode: BiosAgentInstallModes.DellBiosExe,
                PackagePath: packagePath,
                ExpectedSha256: expectedSha256,
                AllowReboot: request.AllowReboot,
                InfRelativePath: null,
                TimeoutMs: (int)InstallerTimeout.TotalMilliseconds);

            var result = await BiosInstallerRunner.RunInstallerAsync(
                commands: _commands,
                executablePath: packagePath,
                arguments: args,
                request: effectiveRequest,
                bitLockerSuspended: bitLocker.Suspended,
                rebootSuccessExitCodes: DellExeRebootExitCodes,
                completedSuccessExitCodes: null,
                timeout: InstallerTimeout,
                log: _log,
                ct: ct,
                workingDirectory: Path.GetDirectoryName(packagePath),
                agentRequest: agentRequest,
                bridge: _elevatedBridge,
                isProcessElevated: _isProcessElevated).ConfigureAwait(false);

            if (result.Succeeded && result.RequiresReboot)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.RebootRequired, 100, result.Message));
            else if (result.Succeeded)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Completed, 100, result.Message));
            else
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, result.Message));

            return result;
        }
        finally
        {
            if (autoStagingDir is not null)
                TryDeleteDirectoryRecursive(autoStagingDir);
        }
    }

    private async Task<BiosInstallResult> InstallViaDcuCliAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress,
        CancellationToken ct)
    {
        var prev = request.Current?.Version;
        var target = request.Target?.LatestVersion;

        string? validatedPath = null;
        if (_dcuCliPath is not null)
        {
            if (!TryValidateDcuCliPath(_dcuCliPath, out validatedPath, out var pathErr))
            {
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, pathErr));
                return BiosInstallResult.Failed(pathErr, prev, target);
            }
        }
        else
        {
            validatedPath = FindInstalledDcuCli();
        }

        var elevated = _isProcessElevated is not null
            ? _isProcessElevated()
            : (_commands is not null ? _commands.IsProcessElevated : ElevationService.DetectProcessElevated());

        if (elevated)
        {
            if (string.IsNullOrWhiteSpace(validatedPath))
            {
                const string msg = "Dell Command | Update CLI (dcu-cli.exe) was not found.";
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
                return BiosInstallResult.Failed(msg, prev, target);
            }

            var isScripted = _commands is not null && _commands.IsScripted;
            if (!TryValidateDcuCliFileAndAncestors(validatedPath, requireExists: !isScripted, out var fileErr, out _))
            {
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, fileErr));
                return BiosInstallResult.Failed(fileErr, prev, target);
            }

            if (!isScripted
                && request.VerifyHash
                && !await _signatureVerifier.VerifyAuthenticodeAsync(validatedPath, ct).ConfigureAwait(false))
            {
                const string msg = "Dell Command | Update CLI failed Authenticode signature verification.";
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
                return BiosInstallResult.Failed(msg, prev, target);
            }
        }
        else if (!string.IsNullOrWhiteSpace(validatedPath))
        {
            if (!TryValidateDcuCliFileAndAncestors(validatedPath, requireExists: false, out var fileErr, out _))
            {
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, fileErr));
                return BiosInstallResult.Failed(fileErr, prev, target);
            }
        }

        var bitLocker = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
            request,
            _commands,
            progress,
            _log,
            ct,
            bridge: _elevatedBridge,
            isProcessElevated: _isProcessElevated).ConfigureAwait(false);

        if (bitLocker.ElevationRequired)
        {
            var msg = bitLocker.Message
                ?? $"Administrator rights (or the elevated Agent service) are required to suspend BitLocker. {ElevationService.AdminRepairHint}";
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target, exitCode: SystemCommandRunner.AgentFailedExitCode);
        }

        progress?.Report(new BiosInstallProgress(
            BiosInstallStage.Installing,
            0,
            "Applying Dell BIOS update via Dell Command | Update CLI..."));

        var args = BiosAgentInstallModes.BuildArguments(BiosAgentInstallModes.DellDcuCli, request.AllowReboot);
        var agentRequest = new BiosAgentInstallRequest(
            VendorId: VendorId,
            InstallMode: BiosAgentInstallModes.DellDcuCli,
            PackagePath: validatedPath,
            ExpectedSha256: null, // NEVER pass a BIOS payload SHA-256 here; Agent validates Authenticode/allowlisted dcu-cli.exe.
            AllowReboot: request.AllowReboot,
            InfRelativePath: null,
            TimeoutMs: (int)InstallerTimeout.TotalMilliseconds);

        var result = await BiosInstallerRunner.RunInstallerAsync(
            commands: _commands,
            executablePath: validatedPath ?? "dcu-cli.exe",
            arguments: args,
            request: request,
            bitLockerSuspended: bitLocker.Suspended,
            rebootSuccessExitCodes: DellDcuRebootExitCodes,
            completedSuccessExitCodes: DellDcuNoUpdatesExitCodes,
            timeout: InstallerTimeout,
            log: _log,
            ct: ct,
            workingDirectory: validatedPath is not null ? Path.GetDirectoryName(validatedPath) : null,
            agentRequest: agentRequest,
            bridge: _elevatedBridge,
            isProcessElevated: _isProcessElevated).ConfigureAwait(false);

        if (result.Succeeded && result.Status == BiosInstallStatus.Completed && result.ExitCode == DcuNoUpdatesExitCode)
        {
            var upToDate = new BiosInstallResult(
                Succeeded: true,
                Status: BiosInstallStatus.AlreadyUpToDate,
                RequiresReboot: false,
                BitLockerSuspended: result.BitLockerSuspended,
                PreviousVersion: result.PreviousVersion,
                TargetVersion: result.TargetVersion,
                Message: "Dell Command | Update reported that BIOS is already up to date.",
                ExitCode: DcuNoUpdatesExitCode,
                LogTail: result.LogTail);
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Completed, 100, upToDate.Message));
            return upToDate;
        }

        if (result.Succeeded && result.RequiresReboot)
            progress?.Report(new BiosInstallProgress(BiosInstallStage.RebootRequired, 100, result.Message));
        else if (result.Succeeded)
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Completed, 100, result.Message));
        else
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, result.Message));

        return result;
    }

    internal static bool TryBuildDellPackageUrl(string? baseLocation, string? path, out string packageUrl)
    {
        packageUrl = "";
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var trimmedPath = path.Trim();
        if (ContainsUnsafeUrlChars(trimmedPath))
            return false;

        // If path is an absolute HTTPS URL, validate directly against dell.com (rejecting traversal).
        if (trimmedPath.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (HasDotSegment(trimmedPath))
                return false;

            if (!BiosProviderHttp.TryValidateHttpsUrl(trimmedPath, AllowedHostSuffixes, out var directUri, out _))
                return false;

            packageUrl = directUri.AbsoluteUri;
            return true;
        }

        // Reject other schemes (http://, ftp://, file://) and protocol-relative URLs (//evil.com/...).
        if (trimmedPath.Contains("://", StringComparison.Ordinal) || trimmedPath.StartsWith("//", StringComparison.Ordinal))
            return false;

        var rawBase = string.IsNullOrWhiteSpace(baseLocation) ? "downloads.dell.com" : baseLocation.Trim();
        if (ContainsUnsafeUrlChars(rawBase))
            return false;

        if (rawBase.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            rawBase = rawBase["https://".Length..];
        else if (rawBase.Contains("://", StringComparison.Ordinal) || rawBase.StartsWith("//", StringComparison.Ordinal))
            return false;

        var cleanBase = rawBase.TrimEnd('/');
        if (cleanBase.Length == 0)
            return false;

        var baseSegments = cleanBase.Split('/');
        var expectedHost = baseSegments[0];
        if (string.IsNullOrWhiteSpace(expectedHost)
            || expectedHost.Contains(':', StringComparison.Ordinal)
            || expectedHost.Contains('%', StringComparison.Ordinal))
        {
            return false;
        }

        for (var i = 1; i < baseSegments.Length; i++)
        {
            var seg = baseSegments[i];
            if (seg.Length == 0 || IsUnsafePathSegment(seg))
                return false;
        }

        var cleanPath = trimmedPath.TrimStart('/');
        if (cleanPath.Length == 0)
            return false;

        var pathSegments = cleanPath.Split('/');
        foreach (var seg in pathSegments)
        {
            if (seg.Length == 0 || IsUnsafePathSegment(seg))
                return false;
        }

        var candidate = $"https://{cleanBase}/{cleanPath}";
        if (!BiosProviderHttp.TryValidateHttpsUrl(candidate, AllowedHostSuffixes, out var finalUri, out _))
            return false;

        // Confirm host parsed identically to the expected baseLocation host (blocks authority confusion).
        if (!string.Equals(finalUri.Host, expectedHost, StringComparison.OrdinalIgnoreCase))
            return false;

        // When baseLocation specifies a path prefix, ensure the final canonical URI stays strictly inside it.
        if (baseSegments.Length > 1)
        {
            if (!Uri.TryCreate($"https://{cleanBase}/", UriKind.Absolute, out var baseUri))
                return false;

            if (!finalUri.AbsolutePath.StartsWith(baseUri.AbsolutePath, StringComparison.OrdinalIgnoreCase)
                || finalUri.AbsolutePath.Length <= baseUri.AbsolutePath.Length)
            {
                return false;
            }
        }

        packageUrl = finalUri.AbsoluteUri;
        return true;
    }

    internal static bool TryValidateDcuCliPath(string? rawPath, out string validatedPath, out string error)
    {
        validatedPath = "";
        error = "";

        if (string.IsNullOrWhiteSpace(rawPath))
        {
            error = "Dell Command | Update CLI path is empty.";
            return false;
        }

        if (rawPath.Length > MaxToolPathLength)
        {
            error = $"Dell Command | Update CLI path exceeds maximum length ({MaxToolPathLength}).";
            return false;
        }

        if (rawPath.Length != rawPath.Trim().Length)
        {
            error = "Dell Command | Update CLI path must not have leading or trailing whitespace.";
            return false;
        }

        if (rawPath.StartsWith(@"\\", StringComparison.Ordinal)
            || rawPath.StartsWith("//", StringComparison.Ordinal)
            || rawPath.StartsWith(@"\??\", StringComparison.Ordinal)
            || rawPath.StartsWith(@"\/", StringComparison.Ordinal)
            || rawPath.StartsWith(@"/\", StringComparison.Ordinal))
        {
            error = "Dell Command | Update CLI path must not be a UNC or device path.";
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
                error = "Dell Command | Update CLI path contains control characters.";
                return false;
            }

            if (Array.IndexOf(ForbiddenPathChars, c) >= 0)
            {
                error = $"Dell Command | Update CLI path contains forbidden character '{c}'.";
                return false;
            }

            if (c == ':' && !(i == 1 && isWindowsDriveRoot))
            {
                error = "Dell Command | Update CLI path contains an invalid colon.";
                return false;
            }
        }

        var isFullyQualified = isWindowsDriveRoot || Path.IsPathFullyQualified(rawPath);
        if (!isFullyQualified)
        {
            error = "Dell Command | Update CLI path must be a fully qualified local path.";
            return false;
        }

        var segments = rawPath.Split(['\\', '/']);
        foreach (var seg in segments)
        {
            if (seg == "." || seg == "..")
            {
                error = "Dell Command | Update CLI path must not contain traversal segments.";
                return false;
            }
        }

        var leaf = segments[^1];
        if (!string.Equals(leaf, "dcu-cli.exe", StringComparison.OrdinalIgnoreCase))
        {
            error = "Dell Command | Update CLI path must target 'dcu-cli.exe'.";
            return false;
        }

        validatedPath = rawPath;
        return true;
    }

    private static string? FindInstalledDcuCli()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        string?[] roots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        ];

        foreach (var root in roots)
        {
            if (string.IsNullOrWhiteSpace(root))
                continue;

            var candidate = Path.Combine(root, "Dell", "CommandUpdate", "dcu-cli.exe");
            if (File.Exists(candidate) && TryValidateDcuCliFileAndAncestors(candidate, requireExists: true, out _, out _))
                return candidate;
        }

        return null;
    }

    private static bool TryValidateDcuCliFileAndAncestors(
        string filePath,
        bool requireExists,
        out string error,
        out bool missingFile)
    {
        error = "";
        missingFile = false;

        // When running scripted unit tests on non-Windows with a synthetic Windows path (e.g., C:\Program Files\...),
        // skip local filesystem inspection because Path.IsPathFullyQualified is false for foreign-OS paths.
        if (!requireExists && !Path.IsPathFullyQualified(filePath))
            return true;

        try
        {
            if (IsSymlinkOrReparsePath(filePath))
            {
                error = "Dell Command | Update CLI path must reference a regular non-link file.";
                return false;
            }

            if (Directory.Exists(filePath))
            {
                error = "Dell Command | Update CLI path must reference a regular file, not a directory.";
                return false;
            }

            if (HasSymlinkOrReparseAncestor(filePath))
            {
                error = "Dell Command | Update CLI path must not traverse a symbolic link or reparse point.";
                return false;
            }

            var exists = File.Exists(filePath);
            if (!exists)
            {
                if (requireExists)
                {
                    missingFile = true;
                    error = "Dell Command | Update CLI was not found at the configured path.";
                    return false;
                }

                return true;
            }

            var fi = new FileInfo(filePath);
            if (!fi.Exists
                || fi.LinkTarget is not null
                || (fi.Attributes & FileAttributes.ReparsePoint) != 0
                || (fi.Attributes & FileAttributes.Directory) != 0)
            {
                error = "Dell Command | Update CLI path must reference a regular non-link file.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = $"Failed to inspect Dell Command | Update CLI path: {ex.Message}";
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

    private static bool HasSymlinkOrReparseAncestor(string filePath)
    {
        var dirPath = Path.GetDirectoryName(filePath);
        if (string.IsNullOrWhiteSpace(dirPath))
            return false;

        var startPath = Path.TrimEndingDirectorySeparator(dirPath);
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

    private static bool IsBiosSoftwareComponent(XElement comp)
    {
        foreach (var child in comp.Elements())
        {
            if (!child.Name.LocalName.Equals("ComponentType", StringComparison.OrdinalIgnoreCase))
                continue;

            var value = GetAttribute(child, "value");
            if (string.Equals(value, "BIOS", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool MatchesSystemSku(XElement comp, string systemSku)
    {
        var supportedSystems = FindChild(comp, "SupportedSystems");
        if (supportedSystems is null)
            return false;

        foreach (var model in supportedSystems.Descendants())
        {
            if (!model.Name.LocalName.Equals("Model", StringComparison.OrdinalIgnoreCase))
                continue;

            var sysIdAttr = GetAttribute(model, "systemID");
            if (BiosVendorIdentity.TryExtractFourHex(sysIdAttr, out var hex)
                && string.Equals(hex, systemSku, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string? ExtractSha256(XElement comp)
    {
        var direct = GetAttribute(comp, "hashSHA256");
        if (TryExtractValidSha256(direct, out var valid))
            return valid;

        var crypto = FindChild(comp, "Cryptography");
        if (crypto is not null)
        {
            foreach (var hash in crypto.Descendants())
            {
                if (!hash.Name.LocalName.Equals("Hash", StringComparison.OrdinalIgnoreCase))
                    continue;

                var alg = GetAttribute(hash, "algorithm");
                if (string.Equals(alg, "SHA256", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(alg, "SHA-256", StringComparison.OrdinalIgnoreCase))
                {
                    if (TryExtractValidSha256(hash.Value, out valid))
                        return valid;
                }
            }
        }

        return null;
    }

    private static DateOnly? ExtractReleaseDate(XElement comp)
    {
        var dateTimeAttr = GetAttribute(comp, "dateTime");
        if (!string.IsNullOrWhiteSpace(dateTimeAttr)
            && DateTimeOffset.TryParse(dateTimeAttr, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto))
        {
            return DateOnly.FromDateTime(dto.UtcDateTime);
        }

        var releaseDateAttr = GetAttribute(comp, "releaseDate");
        if (!string.IsNullOrWhiteSpace(releaseDateAttr))
        {
            var parsed = BiosVersionComparer.TryParseReleaseDate(releaseDateAttr);
            if (parsed.HasValue)
                return parsed;

            if (DateOnly.TryParse(releaseDateAttr, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
                return d;
        }

        return null;
    }

    private static BiosUpdateSeverity ExtractCriticality(XElement comp)
    {
        var crit = FindChild(comp, "Criticality");
        if (crit is null)
            return BiosUpdateSeverity.Recommended;

        var val = GetAttribute(crit, "value");
        if (!string.IsNullOrWhiteSpace(val))
        {
            var parsed = ParseSeverityText(val);
            if (parsed != BiosUpdateSeverity.Unknown)
                return parsed;
        }

        var display = ExtractLocalizedDisplay(comp, "Criticality");
        return ParseSeverityText(display);
    }

    private static BiosUpdateSeverity ParseSeverityText(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return BiosUpdateSeverity.Unknown;

        var trimmed = raw.Trim();
        if (trimmed.Equals("3", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("urgent", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("critical", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("security", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Critical;
        }

        if (trimmed.Equals("2", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("recommended", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Recommended;
        }

        if (trimmed.Equals("1", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("optional", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Optional;
        }

        return BiosUpdateSeverity.Unknown;
    }

    private static string? ExtractLocalizedDisplay(XElement parent, string childName)
    {
        var container = FindChild(parent, childName);
        if (container is null)
            return null;

        string? first = null;
        foreach (var child in container.Elements())
        {
            if (!child.Name.LocalName.Equals("Display", StringComparison.OrdinalIgnoreCase))
                continue;

            var text = child.Value?.Trim();
            if (string.IsNullOrEmpty(text))
                continue;

            first ??= text;
            var lang = GetAttribute(child, "lang");
            if (string.Equals(lang, "en", StringComparison.OrdinalIgnoreCase))
                return text;
        }

        return first;
    }

    private static DellCatalogCandidate SelectNewestCandidate(List<DellCatalogCandidate> candidates)
    {
        var best = candidates[0];
        for (var i = 1; i < candidates.Count; i++)
        {
            var candidate = candidates[i];
            var cmp = BiosVersionComparer.Compare(best.Version, candidate.Version);
            if (cmp < 0)
            {
                best = candidate;
            }
            else if ((cmp is null or 0) && candidate.ReleaseDate.HasValue
                     && (!best.ReleaseDate.HasValue || candidate.ReleaseDate.Value > best.ReleaseDate.Value))
            {
                best = candidate;
            }
        }

        return best;
    }

    private static bool ContainsUnsafeUrlChars(string value)
    {
        foreach (var c in value)
        {
            if (char.IsControl(c) || char.IsWhiteSpace(c) || c is '\\' or '@' or '?' or '#')
                return true;
        }

        return false;
    }

    private static bool HasDotSegment(string url)
    {
        var schemeSep = url.IndexOf("://", StringComparison.Ordinal);
        if (schemeSep < 0 || !Uri.TryCreate(url, UriKind.Absolute, out _))
            return true;

        var afterScheme = url[(schemeSep + 3)..];
        var slashIdx = afterScheme.IndexOf('/');
        if (slashIdx < 0)
            return false;

        var pathPart = afterScheme[(slashIdx + 1)..];
        var queryOrFragIdx = pathPart.IndexOfAny(['?', '#']);
        if (queryOrFragIdx >= 0)
            pathPart = pathPart[..queryOrFragIdx];

        if (pathPart.Length == 0)
            return false;

        foreach (var seg in pathPart.Split('/'))
        {
            if (seg.Length == 0)
                continue;

            if (IsUnsafePathSegment(seg))
                return true;
        }

        return false;
    }

    private static bool IsUnsafePathSegment(string segment)
    {
        var current = segment;
        for (var round = 0; round < 5; round++)
        {
            if (current is "." or ".." || current.Trim() is "." or "..")
                return true;

            if (current.Contains("%2e", StringComparison.OrdinalIgnoreCase)
                || current.Contains("%2f", StringComparison.OrdinalIgnoreCase)
                || current.Contains("%5c", StringComparison.OrdinalIgnoreCase)
                || current.Contains("%00", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            for (var i = 0; i < current.Length; i++)
            {
                var c = current[i];
                if (char.IsControl(c) || c is '/' or '\\' or '?' or '#' or '@')
                    return true;

                if (c == '%')
                {
                    if (i + 2 >= current.Length
                        || !Uri.IsHexDigit(current[i + 1])
                        || !Uri.IsHexDigit(current[i + 2]))
                    {
                        return true;
                    }
                }
            }

            if (!current.Contains('%', StringComparison.Ordinal))
                return false;

            string decoded;
            try
            {
                decoded = Uri.UnescapeDataString(current);
            }
            catch
            {
                return true;
            }

            if (string.Equals(decoded, current, StringComparison.Ordinal))
                return false;

            current = decoded;
        }

        return true;
    }

    private static BiosLatestInfo RedactLatestInfo(BiosLatestInfo info, string? serialNumber)
    {
        if (string.IsNullOrWhiteSpace(serialNumber))
            return info;

        var safeMessage = info.Message is not null
            ? BiosInstallerRunner.RedactSerialNumber(info.Message, serialNumber)
            : null;
        var safeSummary = info.ReleaseSummary is not null
            ? BiosInstallerRunner.RedactSerialNumber(info.ReleaseSummary, serialNumber)
            : null;

        if (ReferenceEquals(safeMessage, info.Message) && ReferenceEquals(safeSummary, info.ReleaseSummary))
            return info;

        return info with { Message = safeMessage, ReleaseSummary = safeSummary };
    }

    private static bool TryExtractValidSha256(string? raw, out string valid)
    {
        valid = "";
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        var trimmed = raw.Trim();
        if (!Sha256HexRegex().IsMatch(trimmed))
            return false;

        valid = trimmed.ToLowerInvariant();
        return true;
    }

    private static XElement? FindChild(XElement parent, string localName)
    {
        foreach (var child in parent.Elements())
        {
            if (child.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase))
                return child;
        }

        return null;
    }

    private static string? GetChildValue(XElement parent, string localName)
    {
        var child = FindChild(parent, localName);
        var val = child?.Value?.Trim();
        return string.IsNullOrEmpty(val) ? null : val;
    }

    private static string? GetAttribute(XElement element, string localName)
    {
        foreach (var attr in element.Attributes())
        {
            if (attr.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase))
            {
                var val = attr.Value?.Trim();
                if (!string.IsNullOrEmpty(val))
                    return val;
            }
        }

        return null;
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
                return value.Trim();
        }

        return null;
    }

    private static long? TryParsePositiveLong(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        return long.TryParse(raw.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) && value > 0
            ? value
            : null;
    }

    private static bool TryEnsureExecutableExtension(string filePath, out string executablePath, out string error) =>
        BiosPackageVerification.TryEnsureExecutableExtension(filePath, "Dell", out executablePath, out error);

    private static async Task<byte[]> ReadBoundedBytesAsync(HttpContent content, long maxBytes, CancellationToken ct)
    {
        var contentLength = content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > maxBytes)
            throw new InvalidDataException($"Dell BIOS catalog size ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxBytes} bytes).");

        await using var source = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var destination = contentLength is > 0
            ? new MemoryStream((int)Math.Min(contentLength.Value, MaxInitialStreamCapacity))
            : new MemoryStream();

        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            long totalRead = 0;
            while (true)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, CopyBufferSize), ct).ConfigureAwait(false);
                if (read == 0)
                    break;

                totalRead += read;
                if (totalRead > maxBytes)
                    throw new InvalidDataException($"Dell BIOS catalog stream exceeded maximum allowed limit ({maxBytes} bytes).");

                destination.Write(buffer, 0, read);
            }

            return destination.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    private static void TryDeleteDirectoryRecursive(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup of provider-owned temporary directory.
        }
    }

    private sealed record DellCatalogCandidate(
        string Version,
        DateOnly? ReleaseDate,
        BiosUpdateSeverity Severity,
        string? PackageId,
        string? ReleaseSummary,
        string? ReleaseNotesUrl,
        string? DownloadUrl,
        string? Sha256,
        long? SizeBytes);
}
