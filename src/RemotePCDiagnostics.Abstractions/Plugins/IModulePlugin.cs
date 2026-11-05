using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// The entry point of a module DLL (named by "entryType" in its module.json). The host creates it once at startup, before the service
/// container is built, and calls <see cref="Register"/>. The plugin registers its module as an <see cref="IDiagnosticModule"/> singleton,
/// plus anything the module needs. Built-in modules go through the same call.
/// </summary>
public interface IModulePlugin
{
    void Register(IServiceCollection services, IPluginContext context);
}

/// <summary>What the host tells a plugin while it registers.</summary>
public interface IPluginContext
{
    /// <summary>The plugin's id ("builtin" for the modules that ship with the app).</summary>
    string PluginId { get; }
    /// <summary>Local or Remote: plugins honour the same remote rules as built-ins (actor attribution, the notice to the person at the PC).</summary>
    ISessionContext Session { get; }
    /// <summary>The running app's version (compare against the manifest's minHost).</summary>
    Version HostVersion { get; }
    /// <summary>The contract version the host implements (<see cref="ContractVersion.Current"/>).</summary>
    Version ContractVersion { get; }
    /// <summary>Writes a line to the app log.</summary>
    void Log(string message);
    /// <summary>Sets a module's own details UI (a Razor component with a <c>DiagnosticModule</c> parameter).</summary>
    void SetDetailsComponent(Guid moduleId, Type component);
}

/// <summary>The version of this contract assembly, separate from the app's version.</summary>
public static class ContractVersion
{
    /// <summary>1.1: hardware instances (IPerDeviceModule, IDetectableModule, DiagnosticResult.InstanceKey) and CouldNotRun.
    /// 1.2: IRunEnd, so a module's payload can say it was cancelled or couldn't run.</summary>
    /// <remarks>Major changes break plugins (removed type, changed signature); minor ones add optional members.</remarks>
    public static Version Current { get; } = new(1, 2, 0);

    /// <summary>A plugin built for <paramref name="builtFor"/> loads when the majors match and its minor is at or below the host's.</summary>
    public static bool IsCompatible(Version builtFor, Version? host = null)
    {
        host ??= Current;
        return builtFor.Major == host.Major && builtFor.Minor <= host.Minor;
    }
}
