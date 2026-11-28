using Microsoft.AspNetCore.Components;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.Webcam;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests;

public class InteractiveTestsTests
{
    [Fact]
    public void InteractiveRoute_IsRegistered_AndCatalogDescriptorsPointToInteractive()
    {
        Assert.Equal("interactive", ChecksScreenState.InteractiveRoute);

        var webcamDesc = BuiltInModules.Descriptors.Single(d => d.Id == ModuleIds.Webcam);
        Assert.Equal("interactive", webcamDesc.Page);
        Assert.False(webcamDesc.OnStressPage);

        var spkToMicDesc = BuiltInModules.Descriptors.Single(d => d.Id == ModuleIds.SpeakerToMic);
        Assert.Equal("interactive", spkToMicDesc.Page);
        Assert.False(spkToMicDesc.OnStressPage);

        var micToSpkDesc = BuiltInModules.Descriptors.Single(d => d.Id == ModuleIds.MicToSpeaker);
        Assert.Equal("interactive", micToSpkDesc.Page);
        Assert.False(micToSpkDesc.OnStressPage);
    }

    [Fact]
    public void ChecksScreenState_RoutesInteractiveModulesToInteractive_AndExcludesFromStressModules()
    {
        var store = new ResultStore();
        var diag = new DiagnosticsService(store, [
            new FakeModule("CpuStress", _ => Task.FromResult(FakeModule.Ok("CpuStress"))),
            new WebcamTestModule(new FakeWebcamIo()),
            new SpeakerToMicModule(new NullAudioIo()),
            new MicToSpeakerModule(new NullAudioIo()),
        ]);

        var screen = new ChecksScreenState(diag, store);

        Assert.Equal("interactive", screen.PageFor(ModuleSlugs.Webcam));
        Assert.Equal("interactive", screen.PageFor(ModuleSlugs.SpeakerToMic));
        Assert.Equal("interactive", screen.PageFor(ModuleSlugs.MicToSpeaker));

        Assert.Null(screen.GroupOf(ModuleSlugs.Webcam));
        Assert.Null(screen.GroupOf(ModuleSlugs.SpeakerToMic));
        Assert.Null(screen.GroupOf(ModuleSlugs.MicToSpeaker));

        Assert.DoesNotContain(screen.StressModules, m => m.Name == ModuleSlugs.Webcam);
        Assert.DoesNotContain(screen.StressModules, m => m.Name == ModuleSlugs.SpeakerToMic);
        Assert.DoesNotContain(screen.StressModules, m => m.Name == ModuleSlugs.MicToSpeaker);
    }

    [Fact]
    public void InteractiveTestsPage_HasRouteAttribute_AndInheritsStoreAwareComponent()
    {
        var pageType = typeof(InteractiveTestsPage);
        var routeAttr = (RouteAttribute?)Attribute.GetCustomAttribute(pageType, typeof(RouteAttribute));
        Assert.NotNull(routeAttr);
        Assert.Equal("/interactive", routeAttr.Template);
        Assert.True(typeof(RemotePCDiagnostics.UI.Shared.StoreAwareComponent).IsAssignableFrom(pageType));
    }

    [Fact]
    public void NavRail_ContainsInteractiveNavLink_AfterStressTests()
    {
        var navRailPath = Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Shared", "NavRail.razor");
        Assert.True(File.Exists(navRailPath));
        var content = File.ReadAllText(navRailPath);

        var stressIdx = content.IndexOf("data-testid=\"nav-stress\"", StringComparison.OrdinalIgnoreCase);
        var interactiveIdx = content.IndexOf("data-testid=\"nav-interactive\"", StringComparison.OrdinalIgnoreCase);
        var secAuditIdx = content.IndexOf("data-testid=\"nav-security-audit\"", StringComparison.OrdinalIgnoreCase);

        Assert.True(stressIdx >= 0, "Stress nav link should exist");
        Assert.True(interactiveIdx >= 0, "Interactive nav link should exist");
        Assert.True(secAuditIdx >= 0, "Security audit nav link should exist");

        Assert.True(interactiveIdx > stressIdx, "Interactive tests should be placed after Stress tests");
        Assert.True(secAuditIdx > interactiveIdx, "Security audit should be placed after Interactive tests");
        Assert.Contains("href=\"interactive\"", content);
    }

    [Fact]
    public void InteractiveTestsPage_MarkupContainsDisabledStateAndTooltipForRemoteDisplay()
    {
        var pagePath = Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Pages", "InteractiveTestsPage.razor");
        Assert.True(File.Exists(pagePath));
        var content = File.ReadAllText(pagePath);

        const string expectedTooltip = "Interactive tests must run locally on the physical machine";
        Assert.Contains(expectedTooltip, content);
        Assert.Contains("disabled=\"@(_selected.Count == 0 || _isRemoteDisplay)\"", content);
        Assert.Contains("disabled=\"@(Diagnostics.IsStressSuiteRunning || _isRemoteDisplay)\"", content);
        Assert.Contains("Remote technician has control. Release control to the local user", content);
        Assert.Contains("Local user has control of the session", content);
    }

    [Fact]
    public void PhysicalBenchQaCard_MarkupContainsDisabledStateAndTooltipForRemoteDisplay()
    {
        var cardPath = Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Shared", "PhysicalBenchQaCard.razor");
        Assert.True(File.Exists(cardPath));
        var content = File.ReadAllText(cardPath);

        const string expectedTooltip = "Interactive tests must run locally on the physical machine";
        Assert.Contains(expectedTooltip, content);
        Assert.Contains("data-testid=\"keyboard-capture-toggle\"", content);
        Assert.Contains("data-testid=\"display-test-launch\"", content);
        Assert.Contains("disabled=\"@IsRemoteDisplay\"", content);

        // Overlay timing enforcement: mousemove must not prematurely show HUD
        Assert.DoesNotContain("@onmousemove=\"OnOverlayMouseMove\"", content);
        Assert.Contains("@onclick=\"OnOverlayClick\"", content);
        Assert.Contains("AutoLaunchDisplay", content);
    }

    [Fact]
    public void PhysicalBenchQaService_StateTransitions_SupportInteractiveBatchWorkflow()
    {
        var svc = new PhysicalBenchQaService();
        Assert.Equal(PhysicalCheckOutcome.NotRun, svc.Current.KeyboardOutcome);
        Assert.Equal(PhysicalCheckOutcome.NotRun, svc.Current.DisplayOutcome);

        var triggered = false;
        svc.Changed += () => triggered = true;

        svc.Update(s => s with { KeyboardOutcome = PhysicalCheckOutcome.Passed, UniqueKeysPressed = 84 });
        Assert.True(triggered);
        Assert.Equal(PhysicalCheckOutcome.Passed, svc.Current.KeyboardOutcome);
        Assert.Equal(84, svc.Current.UniqueKeysPressed);

        triggered = false;
        svc.Update(s => s with { KeyboardOutcome = PhysicalCheckOutcome.NotRun });
        Assert.True(triggered);
        Assert.Equal(PhysicalCheckOutcome.NotRun, svc.Current.KeyboardOutcome);

        svc.Update(s => s with { DisplayOutcome = PhysicalCheckOutcome.Passed, SolidColorsInspected = 6 });
        Assert.Equal(PhysicalCheckOutcome.Passed, svc.Current.DisplayOutcome);
        Assert.Equal(6, svc.Current.SolidColorsInspected);
    }

    [Fact]
    public void InteractiveTestsPage_MarkupContainsAllTestIds_AndRunsInCorrectSequence()
    {
        var pagePath = Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Pages", "InteractiveTestsPage.razor");
        Assert.True(File.Exists(pagePath));
        var content = File.ReadAllText(pagePath);

        // Sequence must loop over AllTestIds in list order
        Assert.Contains("foreach (var id in AllTestIds)", content);
        Assert.Contains("WaitForPhysicalQaAsync(\"keyboard\"", content);
        Assert.Contains("WaitForPhysicalQaAsync(\"display\"", content);
        Assert.Contains("AutoLaunchDisplay=\"_isBatchRunning\"", content);
    }

    [Fact]
    public void BrandingCertificatePage_Markup_ContainsKeyboardDisplayOptions_AndBrandingAdminElements()
    {
        var pagePath = Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Pages", "BrandingCertificatePage.razor");
        Assert.True(File.Exists(pagePath));
        var content = File.ReadAllText(pagePath);

        Assert.Contains("data-testid=\"bench-qa-select-all\"", content);
        Assert.Contains("data-testid=\"bench-qa-tree\"", content);
        Assert.Contains("data-testid=\"bench-qa-group-@g.Id\"", content);
        Assert.Contains("data-testid=\"bench-qa-include-@it.Id\"", content);
        Assert.Contains(HardwareQaCertificate.Groups.SelectMany(g => g.Items), i => i.Id == "keyboard" && i.Label.Contains("keyboard", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(HardwareQaCertificate.Groups.SelectMany(g => g.Items), i => i.Id == "display" && i.Label.Contains("display", StringComparison.OrdinalIgnoreCase));

        // PhysicalBenchQaCard renders only while the run waits on a person check (the run owns that wait, so it survives leaving the page)
        Assert.Contains("@if (waitingFor is { Length: > 0 })", content);
        Assert.Contains("FilterSection=\"@waitingFor\"", content);
        Assert.DoesNotContain("\n<PhysicalBenchQaCard Service=\"ActivePhysicalQa\" />", content);

        // Local branding override form and manual relay inputs are removed (branding & publishing live on Admin)
        Assert.DoesNotContain("data-testid=\"branding-card\"", content);
        Assert.DoesNotContain("data-testid=\"relay-server-url\"", content);
        Assert.DoesNotContain("data-testid=\"relay-group-slug\"", content);
        Assert.DoesNotContain("data-testid=\"relay-api-key\"", content);

        // Certificate card should not contain redundant Checks or Stress tests nav buttons
        Assert.DoesNotContain("href=\"checks\"", content);
        Assert.DoesNotContain("href=\"stress\"", content);

        // Save certificate initiates browser file download and Publish posts via browser session cookie
        Assert.Contains("rpdSession.saveAsFile", content);
        Assert.Contains("rpdSession.publishQaCertificate", content);

        // dialogs.js provides saveAsFile and publishQaCertificate helpers
        var dialogsJsPath = Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "wwwroot", "dialogs.js");
        Assert.True(File.Exists(dialogsJsPath));
        var jsContent = File.ReadAllText(dialogsJsPath);
        Assert.Contains("function saveAsFile(", jsContent);
        Assert.Contains("function publishQaCertificate(", jsContent);
        Assert.Contains("window.saveAsFile = saveAsFile", jsContent);
        Assert.Contains("saveAsFile,", jsContent);
    }

    private static string FindRepoRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "RemotePCDiagnostics.sln")))
                return d.FullName;
        throw new DirectoryNotFoundException("Could not find RemotePCDiagnostics.sln above " + AppContext.BaseDirectory);
    }

    private sealed class FakeWebcamIo : IWebcamIo
    {
        public IReadOnlyList<WebcamDevice> ListDevices() => [new("cam1", "Test Cam", WebcamBus.BuiltIn)];
        public Task<WebcamCaptureResult> CaptureAsync(WebcamCaptureRequest req, CancellationToken ct) =>
            Task.FromResult(new WebcamCaptureResult(1280, 720, 30, "NV12", null));
        public bool IsCameraBlockedByPrivacy() => false;
    }
}
