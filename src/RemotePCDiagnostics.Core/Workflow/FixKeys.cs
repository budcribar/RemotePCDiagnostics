using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Memory;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>
/// Fixed key text for each fix type, used in workflow fix ids (and so in remembered ticks). Written out on purpose instead of
/// <c>nameof</c>/<c>ToString()</c>: renaming an enum member in code must not change keys already saved on PCs. A new member needs a
/// new entry here (a test fails otherwise); never change an existing entry.
/// </summary>
public static class FixKeys
{
    public static readonly IReadOnlyDictionary<RemediationKind, string> Remediation = new Dictionary<RemediationKind, string>
    {
        [RemediationKind.CheckAndInstallDriverUpdates] = "checkandinstalldriverupdates",
        [RemediationKind.CheckAndInstallWindowsUpdates] = "checkandinstallwindowsupdates",
        [RemediationKind.RestartDevice] = "restartdevice",
        [RemediationKind.EnableDevice] = "enabledevice",
        [RemediationKind.ScanHardwareChanges] = "scanhardwarechanges",
        [RemediationKind.SetBalancedPowerPlan] = "setbalancedpowerplan",
        [RemediationKind.DisableFastStartup] = "disablefaststartup",
        [RemediationKind.ScheduleCleanRestart] = "schedulecleanrestart",
        [RemediationKind.CancelScheduledRestart] = "cancelscheduledrestart",
        [RemediationKind.EndProcessGroup] = "endprocessgroup",
        [RemediationKind.DisableSystemProxy] = "disablesystemproxy",
        [RemediationKind.FlushDnsAndRenewIp] = "flushdnsandrenewip",
        [RemediationKind.SetPublicDns] = "setpublicdns",
        [RemediationKind.ResetDhcpDns] = "resetdhcpdns",
        [RemediationKind.CleanTempFiles] = "cleantempfiles",
        [RemediationKind.OptimizeSsd] = "optimizessd",
        [RemediationKind.RepairComponentStore] = "repaircomponentstore",
        [RemediationKind.RepairSystemFiles] = "repairsystemfiles",
    };

    public static readonly IReadOnlyDictionary<MemoryActionType, string> Memory = new Dictionary<MemoryActionType, string>
    {
        [MemoryActionType.CloseApp] = "closeapp",
        [MemoryActionType.ForceCloseApp] = "forcecloseapp",
        [MemoryActionType.ShutdownBuildServers] = "shutdownbuildservers",
        [MemoryActionType.DisableStartup] = "disablestartup",
        [MemoryActionType.EnableBrowserMemorySaver] = "enablebrowsermemorysaver",
        [MemoryActionType.OpenSettings] = "opensettings",
        [MemoryActionType.StopService] = "stopservice",
        [MemoryActionType.SetServiceManual] = "setservicemanual",
        [MemoryActionType.SetServiceDisabled] = "setservicedisabled",
        [MemoryActionType.RestartPc] = "restartpc",
        [MemoryActionType.DisableFastStartup] = "disablefaststartup",
        [MemoryActionType.DisableTransparency] = "disabletransparency",
        [MemoryActionType.AutoManagePageFile] = "automanagepagefile",
        [MemoryActionType.AddDefenderExclusions] = "adddefenderexclusions",
        [MemoryActionType.DisableWidgets] = "disablewidgets",
        [MemoryActionType.DisableSearchHighlights] = "disablesearchhighlights",
        [MemoryActionType.ReduceHibernateFile] = "reducehibernatefile",
        [MemoryActionType.SkipOfficeStartScreen] = "skipofficestartscreen",
        [MemoryActionType.SetPdfDefaultPrinter] = "setpdfdefaultprinter",
        [MemoryActionType.DisableOfficeOptionalExperiences] = "disableofficeoptionalexperiences",
        [MemoryActionType.ShutdownWsl] = "shutdownwsl",
        [MemoryActionType.BlockBrowserExtension] = "blockbrowserextension",
        [MemoryActionType.StopBrowserBackground] = "stopbrowserbackground",
        [MemoryActionType.RemoveApp] = "removeapp",
        [MemoryActionType.RemoveXboxApps] = "removexboxapps",
        [MemoryActionType.StopSilentAppInstalls] = "stopsilentappinstalls",
        [MemoryActionType.RemoveNarratorAddons] = "removenarratoraddons",
        [MemoryActionType.CleanStorage] = "cleanstorage",
    };

    public static string Of(RemediationKind k) => Remediation.TryGetValue(k, out var v) ? v : throw new InvalidOperationException($"No fix key for {k}; add one to FixKeys.");
    public static string Of(MemoryActionType t) => Memory.TryGetValue(t, out var v) ? v : throw new InvalidOperationException($"No fix key for {t}; add one to FixKeys.");
}
