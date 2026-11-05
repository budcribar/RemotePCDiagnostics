using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Preferences;
using RemotePCDiagnostics.Core.Workflow;

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
    PluginRegistrar? Plugins = null);
