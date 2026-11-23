using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Modules.BiosFirmware;

/// <summary>BIOS &amp; UEFI firmware check (reads SMBIOS details, checks vendor catalogs for updates, and offers a one-click update fix).</summary>
public sealed class BiosFirmwarePlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new BiosFirmwareModule(
            sp.GetService<IBiosUpdateService>(),
            sp.GetService<SystemCommandRunner>()),
            ModuleIds.BiosFirmware);
}
