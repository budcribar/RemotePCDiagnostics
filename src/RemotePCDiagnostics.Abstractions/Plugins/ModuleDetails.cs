namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// What a module's details UI (<see cref="IPluginContext.SetDetailsComponent"/>) is given besides its <c>DiagnosticModule</c> parameter.
/// </summary>
public static class ModuleDetails
{
    /// <summary>
    /// Name of the cascading value holding the module's latest result in the app (a <see cref="DiagnosticResult"/>, "not run yet" before
    /// the first run). Take it with <c>[CascadingParameter(Name = ModuleDetails.LastResult)] public DiagnosticResult? LastResult { get; set; }</c>.
    /// It updates after every run, also for an unsigned module whose UI runs in its own process.
    /// </summary>
    public const string LastResult = "RemotePCDiagnostics.LastResult";
}
