using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Checks;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Preferences;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.ModuleUi;

namespace RemotePCDiagnostics.UI;

/// <summary>
/// The host services a page may use when the host provides them (null when it doesn't, e.g. Copilot hand-off in a remote session).
/// Pages inject this instead of <see cref="IServiceProvider"/>, so what a page can reach is listed in one place.
/// </summary>
public sealed record AppServices(
    RemediationService? Remediation = null,
    ServiceActionService? ServiceActions = null,
    MemorySuggestionService? Memory = null,
    ICopilotHandoff? Copilot = null,
    PreferencesService? Preferences = null,
    WorkflowService? Workflow = null,
    PluginRegistrar? Plugins = null,
    IModuleUiFrames? ModuleUiFrames = null,
    SupportDiagnostics? SupportDiagnostics = null,
    PhysicalBenchQaService? PhysicalQa = null,
    BenchQaRunner? BenchQa = null,
    ShopRelayClient? ShopRelay = null,
    ISessionRelauncher? Relauncher = null,
    RemoteSessionHealth? RemoteHealth = null,
    IElevationContext? Elevation = null,
    IFullscreenService? Fullscreen = null,
    IAppUpdateService? AppUpdate = null,
    SystemCommandRunner? Commands = null,
    CheckSettingsService? CheckSettings = null,
    IBiosUpdateService? Bios = null,
    RemotePCDiagnostics.Agent.Core.AgentModeMonitor? AgentLink = null,
    RemotePCDiagnostics.Core.Input.IPhysicalInputMonitor? PhysicalInput = null,
    RemotePCDiagnostics.Core.Input.PointerTestService? PointerTest = null)
{
    /// <summary>
    /// No Agent on this PC: none is installed and none does admin work for the app (the Microsoft Store app on its own). The app then just
    /// offers less: features that need the Agent are hidden, with no warnings, and only the Dashboard mentions what the Agent adds.
    /// False when the host doesn't say (tests).
    /// </summary>
    public bool NoAgent => AgentShopPillState.NoAgent(Elevation, AgentLink?.Current.Kind);

    /// <summary>
    /// Fixes that need administrator rights can run: the Agent is connected (or the host has no elevation service, as in tests). When false
    /// the pages leave those fixes out (<see cref="FixAccess"/>) instead of offering buttons that fail.
    /// </summary>
    public bool AgentFixes => Elevation is not { HasAdminCapabilities: false };
}
