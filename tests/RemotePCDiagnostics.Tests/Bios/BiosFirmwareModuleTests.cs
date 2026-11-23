using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.Modules.BiosFirmware;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class BiosFirmwareModuleTests
{
    private static BiosUpdateCheckOutcome MakeOutcome(
        BiosLatestInfo latest,
        string version = "F.34",
        string? providerId = "hp",
        string? providerDisplayName = "HP")
    {
        var identity = BiosIdentityFactory.Hp(
            model: "HP OmniBook X Laptop 14-fe0xxx",
            boardProduct: "8CBE",
            biosVersion: version);
        return new BiosUpdateCheckOutcome(identity, identity.CurrentBios, latest, providerId, providerDisplayName);
    }

    [Fact]
    public void Build_UpdateAvailableRecommended_ReturnsWarningWithInstallAction()
    {
        var latest = new BiosLatestInfo(
            "hp",
            BiosCheckStatus.UpdateAvailable,
            LatestVersion: "F.36",
            ReleaseDate: new DateOnly(2026, 9, 15),
            Severity: BiosUpdateSeverity.Recommended,
            PackageId: "sp160001",
            SizeBytes: 24 * 1024 * 1024,
            ReleaseSummary: "Improves system stability.");
        var outcome = MakeOutcome(latest);

        var report = BiosFirmwareModule.Build(outcome);

        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.Contains("F.34", report.Summary, StringComparison.Ordinal);
        Assert.Contains("F.36", report.Summary, StringComparison.Ordinal);
        Assert.Equal(2, report.Cards.Count);

        var updateCard = report.Cards[0];
        Assert.Equal("bios-update", updateCard.Id);
        Assert.Equal(AreaLevel.Warning, updateCard.Level);
        var action = Assert.Single(updateCard.Actions!);
        Assert.Equal(RemediationKind.InstallBiosUpdate, action.Kind);
        Assert.Equal("F.36", action.Target);
        Assert.Contains("F.36", action.ButtonText, StringComparison.Ordinal);

        var currentCard = report.Cards[1];
        Assert.Equal("bios-current", currentCard.Id);
        Assert.Equal("F.34", currentCard.Headline);
    }

    [Fact]
    public void Build_UpdateAvailableSecurity_ReturnsErrorWithInstallAction()
    {
        var latest = new BiosLatestInfo(
            "hp",
            BiosCheckStatus.UpdateAvailable,
            LatestVersion: "F.36",
            Severity: BiosUpdateSeverity.Security);
        var report = BiosFirmwareModule.Build(MakeOutcome(latest));

        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.Equal(AreaLevel.Error, report.Cards[0].Level);
        Assert.Single(report.Cards[0].Actions!);
    }

    [Fact]
    public void Build_UpdateAvailableNonInstallableProvider_OmitsInstallActionAndAddsManualNote()
    {
        var latest = new BiosLatestInfo("msi", BiosCheckStatus.UpdateAvailable, LatestVersion: "1.20");
        var provider = new StubBiosProvider("msi", "MSI", canInstall: false);

        var report = BiosFirmwareModule.Build(MakeOutcome(latest, providerId: "msi", providerDisplayName: "MSI"), provider);

        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.Null(report.Cards[0].Actions);
        Assert.False(string.IsNullOrWhiteSpace(report.Cards[0].Note));
    }

    [Fact]
    public void Build_UpToDate_ReturnsOkWithNoActions()
    {
        var latest = new BiosLatestInfo("hp", BiosCheckStatus.UpToDate, LatestVersion: "F.34");
        var report = BiosFirmwareModule.Build(MakeOutcome(latest));

        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        Assert.Equal(AreaLevel.Ok, report.Cards[0].Level);
        Assert.Null(report.Cards[0].Actions);
        Assert.Contains("up to date", report.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_UnsupportedHardware_ReturnsOkNeutralWithoutErrorBadge()
    {
        var latest = BiosLatestInfo.Unsupported("hp", "No catalog entry.");
        var report = BiosFirmwareModule.Build(MakeOutcome(latest));

        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        Assert.Equal(AreaLevel.Neutral, report.Cards[0].Level);
        Assert.Null(report.Cards[0].Actions);
    }

    [Theory]
    [InlineData(BiosCheckStatus.Offline)]
    [InlineData(BiosCheckStatus.ProviderUnavailable)]
    [InlineData(BiosCheckStatus.Failed)]
    public void Build_TransientOrErrorStatuses_ReturnWarning(BiosCheckStatus status)
    {
        var latest = new BiosLatestInfo("hp", status, Message: "Catalog unreachable.");
        var report = BiosFirmwareModule.Build(MakeOutcome(latest));

        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.Equal(AreaLevel.Warning, report.Cards[0].Level);
        Assert.Null(report.Cards[0].Actions);
    }

    [Fact]
    public async Task RunAsync_WithStubService_ProducesAreaReportWithIncludeInRunAll()
    {
        var latest = new BiosLatestInfo("hp", BiosCheckStatus.UpdateAvailable, LatestVersion: "F.36");
        var svc = new StubBiosService(MakeOutcome(latest), new StubBiosProvider("hp", "HP", canInstall: true));
        var module = new BiosFirmwareModule(svc);

        Assert.True(module.IncludeInRunAll);
        Assert.Equal(ModuleIds.BiosFirmware, module.Id);
        Assert.Equal(ModuleSlugs.BiosFirmware, module.Name);

        var result = await module.RunAsync();
        Assert.Equal(DiagnosticStatus.Warning, result.Status);
        var report = Assert.IsType<AreaReport>(result.Payload);
        Assert.Single(report.Cards[0].Actions!);
    }

    [Fact]
    public async Task RemediationService_InstallBiosUpdate_PlansAndExecutesViaBiosService()
    {
        var latest = new BiosLatestInfo("hp", BiosCheckStatus.UpdateAvailable, LatestVersion: "F.36");
        var outcome = MakeOutcome(latest);
        var installResult = new BiosInstallResult(
            Succeeded: true,
            Status: BiosInstallStatus.RebootRequired,
            RequiresReboot: true,
            PreviousVersion: "F.34",
            TargetVersion: "F.36",
            Message: "BIOS F.36 staged; restart to finish.");
        var biosSvc = new StubBiosService(outcome, new StubBiosProvider("hp", "HP", canInstall: true), installResult);

        var remediation = new RemediationService(new SystemCommandRunner(), bios: biosSvc);
        var action = new AreaAction(RemediationKind.InstallBiosUpdate, "Update BIOS to F.36", "F.36", "BIOS F.36");

        var plan = remediation.Plan(action);
        Assert.True(plan.Allowed);
        Assert.Contains("F.36", plan.Title, StringComparison.Ordinal);

        var exec = await remediation.ExecuteAsync(action);
        Assert.True(exec.Success);
        Assert.Equal(1, exec.UpdatesInstalled);
        Assert.True(exec.RestartNeeded);
        Assert.NotNull(biosSvc.LastInstallRequest);
        Assert.True(biosSvc.LastInstallRequest!.Approved);
        Assert.True(biosSvc.LastInstallRequest.SuspendBitLocker);
        Assert.False(biosSvc.LastInstallRequest.AllowReboot);
    }

    [Fact]
    public void RemediationService_InstallBiosUpdate_NotAllowedWhenBiosServiceMissing()
    {
        var remediation = new RemediationService(new SystemCommandRunner());
        var plan = remediation.Plan(new AreaAction(RemediationKind.InstallBiosUpdate, "Update BIOS", "F.36", "BIOS F.36"));
        Assert.False(plan.Allowed);
    }

    [Fact]
    public void FixMetadata_ForInstallBiosUpdate_IsOptInSlowPermanentAndKeyed()
    {
        Assert.Equal("installbiosupdate", FixKeys.Of(RemediationKind.InstallBiosUpdate));
        Assert.True(FixTraits.Slow(RemediationKind.InstallBiosUpdate));
        Assert.True(FixTraits.MayNeedRestart(RemediationKind.InstallBiosUpdate));
        Assert.Equal(UndoSupport.None, Undoability.Of(RemediationKind.InstallBiosUpdate));

        var latest = new BiosLatestInfo("hp", BiosCheckStatus.UpdateAvailable, LatestVersion: "F.36");
        var report = BiosFirmwareModule.Build(MakeOutcome(latest));
        var result = new DiagnosticResult(ModuleSlugs.BiosFirmware, report.Status, report.Summary, DateTimeOffset.Now, report);
        var fixes = FixCatalog.Build([result], []);

        var fix = Assert.Single(fixes, f => f.Remediation?.Kind == RemediationKind.InstallBiosUpdate);
        Assert.False(fix.DefaultOn);
        Assert.Equal("BIOS & firmware", fix.AreaKey);
    }

    private sealed class StubBiosProvider(string vendorId, string displayName, bool canInstall) : IBiosUpdateProvider
    {
        public string VendorId => vendorId;
        public string DisplayName => displayName;
        public int Priority => 100;
        public BiosProviderCapabilities Capabilities => new(CanCheckLatest: true, CanInstall: canInstall, RequiresReboot: true, RequiresElevation: true, RequiresInternet: true);
        public bool CanHandle(BiosSystemIdentity system) => true;
        public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default) => Task.FromResult(system.CurrentBios);
        public Task<BiosLatestInfo> GetLatestVersionAsync(BiosSystemIdentity system, BiosCurrentInfo current, CancellationToken ct = default) => throw new NotImplementedException();
        public Task<BiosInstallResult> InstallAsync(BiosInstallRequest request, IProgress<BiosInstallProgress>? progress = null, CancellationToken ct = default) => throw new NotImplementedException();
    }

    private sealed class StubBiosService(BiosUpdateCheckOutcome outcome, IBiosUpdateProvider provider, BiosInstallResult? installResult = null) : IBiosUpdateService
    {
        public BiosInstallRequest? LastInstallRequest { get; private set; }
        public IReadOnlyList<IBiosUpdateProvider> Providers => [provider];
        public IBiosUpdateProvider? ResolveProvider(BiosSystemIdentity system) => provider;
        public Task<BiosCurrentInfo> GetCurrentVersionAsync(CancellationToken ct = default) => Task.FromResult(outcome.Current);
        public Task<BiosUpdateCheckOutcome> CheckForUpdateAsync(CancellationToken ct = default) => Task.FromResult(outcome);
        public Task<BiosSafetyCheckResult> EvaluateInstallSafetyAsync(BiosInstallRequest request, CancellationToken ct = default) =>
            Task.FromResult(new BiosSafetyCheckResult(true, [], []));
        public Task<BiosInstallResult> InstallUpdateAsync(BiosInstallRequest request, IProgress<BiosInstallProgress>? progress = null, CancellationToken ct = default)
        {
            LastInstallRequest = request;
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Installing, 50, "Staging BIOS update…"));
            return Task.FromResult(installResult ?? new BiosInstallResult(true, BiosInstallStatus.Succeeded, PreviousVersion: request.Current.Version, TargetVersion: request.Target.LatestVersion));
        }
    }
}
