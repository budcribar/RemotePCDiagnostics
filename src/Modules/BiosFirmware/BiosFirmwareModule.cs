using System.Globalization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.BiosFirmware;

/// <summary>
/// BIOS &amp; UEFI firmware health check (<see cref="ModuleKind.Check"/>, <see cref="ModuleGroups.Hardware"/>, included in Run All).
/// Reads current firmware details, queries the matching vendor catalog via <see cref="IBiosUpdateService"/>, and attaches a
/// <see cref="RemediationKind.InstallBiosUpdate"/> fix when an installable update is available.
/// </summary>
public sealed class BiosFirmwareModule(IBiosUpdateService? bios = null, SystemCommandRunner? commands = null)
    : AreaModuleBase(commands?.Log)
{
    public const string ModuleName = ModuleSlugs.BiosFirmware;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.BiosFirmware;
    public override string DisplayName => "BIOS & firmware";
    protected override string FailedMessage => "Couldn't read BIOS / UEFI firmware details on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        if (bios is null)
        {
            return new AreaReport(
                [new AreaCard("bios-update", "BIOS update status", AreaLevel.Neutral, "BIOS service unavailable",
                    "BIOS update service is not available in this session.", ["Property", "Value"], [])],
                "BIOS update service unavailable",
                DiagnosticStatus.Ok);
        }

        progress.ReportStep(1, 2, "Reading current BIOS / UEFI firmware details…");
        progress.ReportStep(2, 2, "Checking vendor catalog for BIOS updates…");
        var outcome = await bios.CheckForUpdateAsync(ct).ConfigureAwait(false);
        var provider = ResolveMatchedProvider(bios, outcome);
        return Build(outcome, provider);
    }

    private static IBiosUpdateProvider? ResolveMatchedProvider(IBiosUpdateService service, BiosUpdateCheckOutcome outcome)
    {
        if (!string.IsNullOrWhiteSpace(outcome.ProviderId))
        {
            var byId = service.Providers.FirstOrDefault(p =>
                string.Equals(p.VendorId, outcome.ProviderId, StringComparison.OrdinalIgnoreCase));
            if (byId is not null)
                return byId;
        }
        return service.ResolveProvider(outcome.System);
    }

    /// <summary>Pure report builder so unit tests can verify every BIOS check status, card, and fix action.</summary>
    public static AreaReport Build(BiosUpdateCheckOutcome outcome, IBiosUpdateProvider? provider = null)
    {
        ArgumentNullException.ThrowIfNull(outcome);

        var cur = outcome.Current;
        var sys = outcome.System;
        var latest = outcome.Latest;
        var currentVer = string.IsNullOrWhiteSpace(cur.Version) ? "Not reported" : cur.Version;
        var providerName = !string.IsNullOrWhiteSpace(outcome.ProviderDisplayName)
            ? outcome.ProviderDisplayName
            : provider?.DisplayName;

        var cards = new List<AreaCard>();

        // 1. Update status card (with one-click fix when an installable update is available)
        var (updateLevel, overallStatus, headline, meta, summary) = Classify(latest, cur, providerName);
        var updateRows = new List<AreaRow>();
        if (!string.IsNullOrWhiteSpace(latest.LatestVersion))
            updateRows.Add(new(updateLevel, ["Latest version", latest.LatestVersion]));
        if (latest.ReleaseDate is { } lDate)
            updateRows.Add(new(AreaLevel.Neutral, ["Release date", lDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)]));
        if (latest.Severity != BiosUpdateSeverity.Unknown && latest.Status == BiosCheckStatus.UpdateAvailable)
            updateRows.Add(new(updateLevel, ["Severity", latest.Severity.ToString()]));
        if (!string.IsNullOrWhiteSpace(latest.PackageId))
            updateRows.Add(new(AreaLevel.Neutral, ["Package", latest.PackageId]));
        if (latest.SizeBytes is > 0)
            updateRows.Add(new(AreaLevel.Neutral, ["Download size", HardwareInventory.FormatBytes(latest.SizeBytes)]));
        if (!string.IsNullOrWhiteSpace(latest.ReleaseSummary))
            updateRows.Add(new(AreaLevel.Neutral, ["Summary", latest.ReleaseSummary]));
        if (BiosPackageVerifier.IsSafeDownloadUrl(latest.ReleaseNotesUrl))
            updateRows.Add(new(AreaLevel.Neutral, ["Release notes", latest.ReleaseNotesUrl!]));
        if (!string.IsNullOrWhiteSpace(latest.Message) && updateRows.Count == 0)
            updateRows.Add(new(updateLevel, ["Details", latest.Message]));

        IReadOnlyList<AreaAction>? actions = null;
        string? note = null;
        if (latest.Status == BiosCheckStatus.UpdateAvailable)
        {
            var canInstall = provider?.Capabilities.CanInstall ?? true;
            if (canInstall)
            {
                var targetVer = string.IsNullOrWhiteSpace(latest.LatestVersion) ? "latest" : latest.LatestVersion;
                actions =
                [
                    new AreaAction(
                        RemediationKind.InstallBiosUpdate,
                        $"Update BIOS to {targetVer}",
                        targetVer,
                        $"BIOS {targetVer}")
                ];
            }
            else
            {
                note = "Automated installation is not supported for this vendor; download and install the BIOS update from the manufacturer's support page.";
            }
        }

        cards.Add(new AreaCard(
            "bios-update",
            "BIOS update status",
            updateLevel,
            headline,
            meta,
            ["Property", "Value"],
            updateRows,
            Note: note,
            Actions: actions,
            PreserveRowOrder: true));

        // 2. Current BIOS / UEFI details card
        var currentRows = new List<AreaRow>();
        if (!string.IsNullOrWhiteSpace(sys.Manufacturer))
            currentRows.Add(new(AreaLevel.Neutral, ["Manufacturer", sys.Manufacturer]));
        if (!string.IsNullOrWhiteSpace(sys.Model))
            currentRows.Add(new(AreaLevel.Neutral, ["Model", sys.Model]));
        if (!string.IsNullOrWhiteSpace(sys.BoardProduct))
            currentRows.Add(new(AreaLevel.Neutral, ["Baseboard", sys.BoardProduct]));
        currentRows.Add(new(AreaLevel.Ok, ["BIOS version", currentVer]));
        if (!string.IsNullOrWhiteSpace(cur.Vendor))
            currentRows.Add(new(AreaLevel.Neutral, ["BIOS vendor", cur.Vendor]));
        var releaseDateText = cur.ReleaseDate is { } rel
            ? rel.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            : cur.ReleaseDateRaw;
        if (!string.IsNullOrWhiteSpace(releaseDateText))
            currentRows.Add(new(AreaLevel.Neutral, ["Release date", releaseDateText]));
        currentRows.Add(new(AreaLevel.Neutral, ["Firmware mode", cur.FirmwareMode.ToString()]));
        if (!string.IsNullOrWhiteSpace(cur.Family))
            currentRows.Add(new(AreaLevel.Neutral, ["BIOS family", cur.Family]));
        if (!string.IsNullOrWhiteSpace(providerName))
            currentRows.Add(new(AreaLevel.Neutral, ["Update provider", providerName]));

        var currentMetaParts = new List<string>();
        if (!string.IsNullOrWhiteSpace(cur.Vendor)) currentMetaParts.Add(cur.Vendor);
        currentMetaParts.Add(cur.FirmwareMode.ToString());
        if (!string.IsNullOrWhiteSpace(releaseDateText)) currentMetaParts.Add(releaseDateText);

        cards.Add(new AreaCard(
            "bios-current",
            "Current BIOS / UEFI",
            string.IsNullOrWhiteSpace(cur.Version) ? AreaLevel.Neutral : AreaLevel.Ok,
            currentVer,
            string.Join(" · ", currentMetaParts),
            ["Property", "Value"],
            currentRows,
            PreserveRowOrder: true));

        return new AreaReport(cards, summary, overallStatus);
    }

    private static (AreaLevel Level, DiagnosticStatus Status, string Headline, string Meta, string Summary) Classify(
        BiosLatestInfo latest,
        BiosCurrentInfo current,
        string? providerName)
    {
        var curVer = string.IsNullOrWhiteSpace(current.Version) ? "current" : current.Version;
        var prov = string.IsNullOrWhiteSpace(providerName) ? "vendor" : providerName;

        return latest.Status switch
        {
            BiosCheckStatus.UpdateAvailable => ClassifyUpdateAvailable(latest, curVer),
            BiosCheckStatus.UpToDate => (
                AreaLevel.Ok,
                DiagnosticStatus.Ok,
                "Up to date",
                $"Matches latest {prov} catalog.",
                "BIOS up to date"),
            BiosCheckStatus.UnsupportedHardware => (
                AreaLevel.Neutral,
                DiagnosticStatus.Ok,
                "No automated catalog for this model",
                string.IsNullOrWhiteSpace(latest.Message)
                    ? $"No automated {prov} BIOS catalog entry for this hardware."
                    : latest.Message,
                $"BIOS {curVer} (no automated vendor catalog)"),
            BiosCheckStatus.Offline => (
                AreaLevel.Warning,
                DiagnosticStatus.Warning,
                "Offline — couldn't check for updates",
                string.IsNullOrWhiteSpace(latest.Message) ? "No internet connection to reach the vendor catalog." : latest.Message,
                $"BIOS {curVer} (offline — couldn't check for updates)"),
            BiosCheckStatus.ProviderUnavailable => (
                AreaLevel.Warning,
                DiagnosticStatus.Warning,
                "Vendor catalog temporarily unavailable",
                string.IsNullOrWhiteSpace(latest.Message) ? $"Could not reach the {prov} BIOS catalog." : latest.Message,
                $"BIOS {curVer} (vendor catalog unavailable)"),
            _ => (
                AreaLevel.Warning,
                DiagnosticStatus.Warning,
                "BIOS update check failed",
                string.IsNullOrWhiteSpace(latest.Message) ? "Could not determine the latest BIOS version." : latest.Message,
                $"BIOS {curVer} (update check failed)"),
        };
    }

    private static (AreaLevel Level, DiagnosticStatus Status, string Headline, string Meta, string Summary) ClassifyUpdateAvailable(
        BiosLatestInfo latest,
        string curVer)
    {
        var target = string.IsNullOrWhiteSpace(latest.LatestVersion) ? "newer version" : latest.LatestVersion;
        var urgent = latest.Severity == BiosUpdateSeverity.Critical;
        var level = urgent ? AreaLevel.Error : AreaLevel.Warning;
        var status = urgent ? DiagnosticStatus.Error : DiagnosticStatus.Warning;
        var severityTag = urgent ? $" ({latest.Severity})" : "";
        var meta = string.IsNullOrWhiteSpace(latest.Message)
            ? $"Current {curVer} → Latest {target}{severityTag}"
            : latest.Message;

        return (
            level,
            status,
            $"Update available: {target}",
            meta,
            $"BIOS update available: {curVer} → {target}{severityTag}");
    }
}
