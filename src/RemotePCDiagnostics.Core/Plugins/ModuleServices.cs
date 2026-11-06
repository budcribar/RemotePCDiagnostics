using Microsoft.Extensions.DependencyInjection;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>Helpers for the modules that ship with the app (src/Modules), which build their module from the app's own services.</summary>
public static class ModuleServices
{
    /// <summary>A logger whose category is the type's full name, as every built-in class logs (null when the app registered no logger factory).</summary>
    public static ILogger? LoggerFor<T>(this IServiceProvider sp) =>
        sp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()?.CreateLogger(typeof(T).FullName ?? typeof(T).Name);
}
