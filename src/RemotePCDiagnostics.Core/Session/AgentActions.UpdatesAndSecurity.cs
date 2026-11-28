using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>Windows Update (the WUA COM API) and the Security fixes (Defender's WMI provider and the registry), with no PowerShell.</summary>
public sealed partial class WindowsAgentNativeOps
{
    /// <remarks>
    /// Windows Update's search, download and install block until they finish (minutes). <see cref="AgentNativeRunner"/> runs this on a
    /// pool thread and stops waiting at the request's timeout; the call itself then finishes in the background, as Windows Update did
    /// when the PowerShell running it was ended.
    /// </remarks>
    partial void RunMore(AgentNativeAction action, CancellationToken ct, ref ProcessResult result)
    {
        if (!OperatingSystem.IsWindows()) return;
        switch (action)
        {
            case WindowsUpdateAction update:
                using (var api = new WuaComApi()) result = AgentWindowsUpdate.InstallAll(api, update.DriversOnly);
                break;
            case InstallUpdateAction install:
                using (var api = new WuaComApi()) result = AgentWindowsUpdate.InstallOne(api, install.UpdateId);
                break;
            case SecurityReadAction or SecurityApplyAction or SecurityRestoreAction:
                result = AgentSecuritySettings.Run(new WindowsSecuritySettingsStore(), action);
                break;
            case Battery.HpBatteryReadAction or Battery.HpBatterySetAction:
                result = Battery.AgentHpBatteryCharge.Run(new Battery.WindowsHpBiosSettings(), action);
                break;
            case Battery.BatteryDrainPowerAction drain:
                result = Battery.AgentBatteryDrainPower.Windows().Run(drain);
                break;
        }
    }
}
