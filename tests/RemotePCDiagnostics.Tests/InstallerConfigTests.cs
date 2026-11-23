using System.Xml.Linq;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public sealed class InstallerConfigTests
{
    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "RemotePCDiagnostics.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate repository root containing RemotePCDiagnostics.sln.");
    }

    [Fact]
    public void InstallerPublishProfile_PublishesMultiFileSelfContainedLayoutAndModuleUiHost()
    {
        var root = FindRepoRoot();
        var pubxmlPath = Path.Combine(root, "src", "RemotePCDiagnostics.Host", "Properties", "PublishProfiles", "Installer.pubxml");
        Assert.True(File.Exists(pubxmlPath), $"Missing publish profile: {pubxmlPath}");

        var doc = XDocument.Load(pubxmlPath);
        string? Prop(string name) => doc.Descendants(name).FirstOrDefault()?.Value;

        Assert.Equal("Release", Prop("Configuration"));
        Assert.Equal("win-x64", Prop("RuntimeIdentifier"));
        Assert.Equal("true", Prop("SelfContained"));
        Assert.Equal("false", Prop("PublishSingleFile"));

        var raw = File.ReadAllText(pubxmlPath);
        Assert.Contains("RemotePCDiagnostics.ModuleUiHost.csproj", raw);
        Assert.Contains("RemotePCDiagnostics.Agent.csproj", raw);
        Assert.Contains("Grpc.Tools", raw);
        Assert.Contains("RemotePCDiagnostics.Agent.deps.json", raw);
        Assert.Contains("--self-contained true", raw);
        Assert.Contains("moduleui", raw);
    }

    [Fact]
    public void PortablePublishProfile_BundlesSelfContainedMemTestModuleHostAndModuleUiHost()
    {
        var root = FindRepoRoot();
        var pubxmlPath = Path.Combine(root, "src", "RemotePCDiagnostics.Host", "Properties", "PublishProfiles", "Portable.pubxml");
        Assert.True(File.Exists(pubxmlPath), $"Missing publish profile: {pubxmlPath}");

        var doc = XDocument.Load(pubxmlPath);
        string? Prop(string name) => doc.Descendants(name).FirstOrDefault()?.Value;

        Assert.Equal("Release", Prop("Configuration"));
        Assert.Equal("win-x64", Prop("RuntimeIdentifier"));
        Assert.Equal("true", Prop("SelfContained"));
        Assert.Equal("true", Prop("PublishSingleFile"));
        Assert.Equal("true", Prop("IncludeAllContentForSelfExtract"));

        var raw = File.ReadAllText(pubxmlPath);
        Assert.Contains("RemotePCDiagnostics.MemTest.csproj", raw);
        Assert.Contains("RemotePCDiagnostics.ModuleHost.csproj", raw);
        Assert.Contains("RemotePCDiagnostics.ModuleUiHost.csproj", raw);
        Assert.Contains(@"moduleui\", raw);
    }

    [Fact]
    public void InnoSetupScript_StaysInSyncWithHostAndWorkflowContracts()
    {
        var root = FindRepoRoot();
        var issPath = Path.Combine(root, "installer", "RemotePCDiagnostics.iss");
        Assert.True(File.Exists(issPath), $"Missing Inno Setup script: {issPath}");

        var iss = File.ReadAllText(issPath);

        // Main application executable contract.
        Assert.Contains(@"#define AppExeName ""RemotePCDiagnostics.Host.exe""", iss);

        // Install directory and plugin/check drop folders expected by ModuleLoader and JsonCheck.
        var modulesSubfolder = Path.GetFileName(ModuleLoaderOptions.DefaultModulesFolder());
        Assert.Contains(@"DefaultDirName={autopf}\RemotePCDiagnostics", iss);
        Assert.Contains($@"Name: ""{{app}}\{modulesSubfolder}""", iss);
        Assert.Contains(@"Name: ""{app}\checks""", iss);

        // Single-instance mutex detection & admin elevation.
        Assert.Contains(@"#define AppMutexName ""Global\RemotePCDiagnostics.Host""", iss);
        Assert.Contains("AppMutex={#AppMutexName}", iss);
        Assert.Contains("CloseApplications=yes", iss);
        Assert.Contains("PrivilegesRequired=admin", iss);

        // Start Menu and Desktop shortcuts auto-created directly (frictionless setup without tasks) and launch Host.exe with no UAC prompt.
        Assert.Contains(@"Name: ""{autoprograms}\{#AppName}""; Filename: ""{app}\{#AppExeName}""; Parameters: ""{#RemoteParameters}""", iss);
        Assert.Contains(@"Name: ""{autodesktop}\{#AppName}""; Filename: ""{app}\{#AppExeName}""; Parameters: ""{#RemoteParameters}""", iss);
        Assert.DoesNotContain("Tasks: desktopicon", iss);

        // Direct Progress -> Auto-Launch: skip wizard friction and launch through Agent.exe --launch so Host starts un-elevated with the Agent pipe.
        Assert.Contains("DisableWelcomePage=yes", iss);
        Assert.Contains("DisableDirPage=yes", iss);
        Assert.Contains("DisableReadyPage=yes", iss);
        Assert.Contains("DisableFinishedPage=yes", iss);
        Assert.Contains("ShouldSkipPage", iss);
        Assert.Contains(@"Filename: ""{app}\RemotePCDiagnostics.Agent.exe""; Parameters: ""--launch {param:RELAUNCHARGS}""; WorkingDir: ""{app}""; Check: ShouldRelaunchAfterUpdate; Flags: nowait runhidden", iss);
        Assert.Contains(@"Filename: ""{app}\RemotePCDiagnostics.Agent.exe""; Parameters: ""--launch {#RemoteParameters}"";", iss);
        Assert.Contains("nowait skipifsilent runhidden", iss);
        Assert.DoesNotContain("postinstall", iss);

        // WebView2 Evergreen Runtime check & bootstrapper.
        Assert.Contains("{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", iss);
        Assert.Contains("https://go.microsoft.com/fwlink/p/?LinkId=2124703", iss);
        Assert.Contains("IsWebView2Installed", iss);

        // Uninstall cleanup: workflow scheduled task, RunOnce resume value, and optional state/log removal.
        Assert.Contains(WorkflowService.ResumeTaskName, iss);
        Assert.Contains(RebootResumeCoordinator.RunOnceValueName, iss);
        Assert.Contains(RebootResumeCoordinator.ResumeTaskName, iss);
        Assert.Contains(@"{commonappdata}\RemotePCDiagnostics", iss);
        Assert.Contains(@"{localappdata}\RemotePCDiagnostics", iss);
        Assert.Contains("/CLEANSTATE", iss);
        Assert.Contains("MB_DEFBUTTON2", iss);

        // Uninstalling Setup also removes an agent installed by install-agent-*.cmd or Install-Computer.cmd.
        Assert.Contains(@"RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe", iss);
        Assert.Contains("Exec(AgentExe, 'uninstall'", iss);
        Assert.Contains("delete RemotePCDiagnosticsAgent", iss);
        Assert.Contains(@"agent.json", iss);

        // A remote update reinstalls the agent service without replacing enrollment, consent, or lifetime.
        Assert.Contains("PreserveAgentSettings", iss);
        Assert.Contains("CmdLineParamExists('/PRESERVEAGENT')", iss);
        Assert.Contains("Parameters: \"install\"; StatusMsg: \"Updating Remote PC Diagnostics Agent service...\"; Flags: runhidden waituntilterminated; Check: PreserveAgentSettings", iss);

        // Silent Setup answers the AppMutex prompt with Cancel and exits 1 before CloseApplications.
        // InitializeSetup closes the Host first. Not /T, or a Setup started by the elevated helper would die with the Host.
        Assert.Contains("function InitializeSetup(): Boolean;", iss);
        Assert.Contains("WizardSilent()", iss);
        Assert.Contains("CheckForMutexes('{#AppMutexName}')", iss);
        Assert.Contains("'/F /IM {#AppExeName}'", iss);
        Assert.DoesNotContain("'/F /T", iss);
        Assert.DoesNotContain("'/T", iss);
    }

    [Fact]
    public void BuildInstallerScript_StagesVerifiesAndCompilesSetupPackage()
    {
        var root = FindRepoRoot();
        var scriptPath = Path.Combine(root, "installer", "Build-Installer.ps1");
        Assert.True(File.Exists(scriptPath), $"Missing build script: {scriptPath}");

        var script = File.ReadAllText(scriptPath);
        Assert.Contains("-p:PublishProfile=Installer", script);
        Assert.Contains("--verify-package", script);
        Assert.Contains("RemotePCDiagnostics.Agent.deps.json", script);
        Assert.Contains("RemotePCDiagnostics.iss", script);
        Assert.Contains("RemotePCDiagnostics.ModuleUiHost.exe", script);
        Assert.Contains("RemotePCDiagnostics.ModuleHost.exe", script);
        Assert.Contains(ModuleLoaderOptions.BundledFolderName, script);
        Assert.Contains("PublishPreRelease", script);
    }

    [Fact]
    public void CiWorkflow_ReplacesSingleRollingPreReleaseOnMainPush()
    {
        var root = FindRepoRoot();
        var ciPath = Path.Combine(root, ".github", "workflows", "ci.yml");
        Assert.True(File.Exists(ciPath), $"Missing CI workflow: {ciPath}");

        var ci = File.ReadAllText(ciPath);
        Assert.Contains("branches:", ci);
        Assert.Contains("github.ref == 'refs/heads/main'", ci);
        Assert.Contains("gh release delete", ci);
        Assert.Contains("--cleanup-tag --yes", ci);
        Assert.Contains("gh release create prerelease", ci);
        Assert.Contains("--prerelease", ci);
    }

    [Fact]
    public void CiWorkflow_NeverInstallsAnAgentThatEnrolsWithThePublicRelay()
    {
        // The TestShop bundle is built for the public relay with unattended consent. Installed as built on a CI runner, its agent
        // service registered the runner there as a persistent computer. The smoke install must send the agent to a loopback address.
        var root = FindRepoRoot();
        var iss = File.ReadAllText(Path.Combine(root, "installer", "RemotePCDiagnostics.iss"));
        Assert.Contains("--server={param:AGENTSERVER|\" + AgentServerUrl + \"}", iss);

        var ci = File.ReadAllText(Path.Combine(root, ".github", "workflows", "ci.yml"));
        Assert.Contains("$smokeServer = 'http://127.0.0.1:9'", ci);
        var silentInstalls = ci.Split('\n').Where(line => line.Contains("-FilePath $bundleExe", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(silentInstalls);
        Assert.All(silentInstalls, line => Assert.Contains("/AGENTSERVER=$smokeServer", line));
        Assert.Contains("$cfgJson.server -ne $smokeServer", ci);
        // No install or run step names the public relay as the agent's server; only the bundle build bakes it in as the default.
        Assert.DoesNotContain("$cfgJson.server -ne 'https://server.remoteblazorwebview.com", ci);
    }

    [Fact]
    public void PublishScript_BuildsInstallerAndReplacesRollingPreRelease()
    {
        var root = FindRepoRoot();
        var publishPs1 = Path.Combine(root, "publish.ps1");
        Assert.True(File.Exists(publishPs1), $"Missing root publish script: {publishPs1}");

        var content = File.ReadAllText(publishPs1);
        Assert.Contains("installer/Build-Installer.ps1", content);
        Assert.Contains("gh release delete", content);
        Assert.Contains("gh release create 'prerelease'", content);
        Assert.Contains("--prerelease", content);

        // Ensure BOM-free PowerShell 5.1 / ISCC compatibility (no smart quotes or non-ASCII punctuation).
        foreach (var rel in new[] { "publish.ps1", "installer/Build-Installer.ps1", "installer/RemotePCDiagnostics.iss" })
        {
            var bytes = File.ReadAllBytes(Path.Combine(root, rel));
            Assert.DoesNotContain(bytes, b => b > 127);
        }
    }

    [Fact]
    public void Upgrade_stops_the_old_agent_before_the_new_one_starts()
    {
        var root = FindRepoRoot();
        var iss = File.ReadAllText(Path.Combine(root, "installer", "RemotePCDiagnostics.iss"));

        // The Host mutex stays the only AppMutex. Adding the agent mutex makes a silent update exit 1
        // while the agent that launched Setup is still running. PR #128 owns that Host-mutex path.
        Assert.Contains(@"#define AppMutexName ""Global\RemotePCDiagnostics.Host""", iss);
        Assert.Contains("AppMutex={#AppMutexName}", iss);
        Assert.Contains(@"#define AgentMutexName ""Global\RemotePCDiagnostics.Agent""", iss);
        Assert.Contains("not listed as AppMutex", iss);
        Assert.DoesNotContain("AppMutex={#AppMutexName},{#AgentMutexName}", iss);
        Assert.DoesNotContain("AppMutex={#AgentMutexName}", iss);

        var prepare = iss.IndexOf("function PrepareToInstall", StringComparison.Ordinal);
        var stopCall = iss.IndexOf("StopPreviousAgents();", prepare, StringComparison.Ordinal);
        var webViewExit = iss.IndexOf("IsWebView2Installed()", prepare, StringComparison.Ordinal);
        Assert.True(stopCall > prepare && stopCall < webViewExit, "The old agent has to be stopped before PrepareToInstall can return early.");
        Assert.True(iss.IndexOf("procedure StopPreviousAgents", StringComparison.Ordinal) < prepare);

        Assert.Contains("StopOneAgentService('RemotePCDiagnosticsAgent');", iss);
        Assert.Contains("StopOneAgentService('RemotePCDiagnostics.Agent');", iss);
        Assert.Contains("StopOneAgentService('Remote PC Diagnostics Agent');", iss);
        Assert.Contains("StopOneAgentService('RemotePCDiagnostics Agent');", iss);
        Assert.Contains("/Delete /TN \"Remote PC Diagnostics Agent\" /F", iss);
        Assert.Contains("does not taskkill", iss);
        Assert.Contains("delete \"RemotePCDiagnostics.Agent\"", iss);
        Assert.Contains("agent-instance.txt", iss);

        var wxs = File.ReadAllText(Path.Combine(root, "msi", "Package.wxs"));
        Assert.Contains("Name=\"RemotePCDiagnosticsAgent\" Stop=\"both\" Start=\"install\" Wait=\"yes\"", wxs);
        Assert.Contains("Name=\"RemotePCDiagnostics.Agent\" Stop=\"both\" Wait=\"yes\" Remove=\"both\"", wxs);
        Assert.Contains("Name=\"Remote PC Diagnostics Agent\" Stop=\"both\" Wait=\"yes\" Remove=\"both\"", wxs);
        Assert.Contains("Name=\"RemotePCDiagnostics Agent\" Stop=\"both\" Wait=\"yes\" Remove=\"both\"", wxs);
        Assert.Contains("After=\"InstallFiles\"", wxs);
        var stopAt = wxs.IndexOf("StopExistingAgentService", StringComparison.Ordinal);
        var installAt = wxs.IndexOf("After=\"InstallFiles\"", StringComparison.Ordinal);
        Assert.True(stopAt > 0 && stopAt < installAt);
    }

    [Fact]
    public void Install_and_upgrade_set_Automatic_and_start_the_service()
    {
        var root = FindRepoRoot();
        var iss = File.ReadAllText(Path.Combine(root, "installer", "RemotePCDiagnostics.iss"));
        var wxs = File.ReadAllText(Path.Combine(root, "msi", "Package.wxs"));

        // Both packages say Automatic. Delayed start would leave the PC off the relay after boot.
        Assert.Contains("start= " + AgentServiceControl.AutomaticStartType, iss);
        Assert.Contains(AgentServiceControl.FailureRestartActions, iss);
        Assert.Contains(AgentServiceControl.ClearedFailureActions, iss);
        Assert.DoesNotContain("delayed-auto", iss);
        Assert.DoesNotContain("start= disabled", iss);
        Assert.Contains("procedure DeinitializeSetup();", iss);
        Assert.Contains("EnsureAgentServiceAutomaticAndRunning();", iss);
        Assert.Contains("procedure EnsureAgentServiceAutomaticAndRunning();", iss);

        var stop = iss.IndexOf("procedure StopOneAgentService", StringComparison.Ordinal);
        var afterStop = iss.IndexOf("procedure EnsureAgentServiceAutomaticAndRunning", stop, StringComparison.Ordinal);
        var body = iss[stop..afterStop];
        var clearAt = body.IndexOf("ClearAgentFailureRestart(Name);", StringComparison.Ordinal);
        var stopAt = body.IndexOf("stop \"", StringComparison.Ordinal);
        Assert.True(clearAt >= 0 && stopAt > clearAt, "Failure restart is cleared before the service is stopped.");

        // Silent and /PRESERVEAGENT both run Agent.exe install. The ensure step is not behind skipifsilent.
        var preserve = iss.IndexOf("Check: PreserveAgentSettings", StringComparison.Ordinal);
        var preserveLine = iss.LastIndexOf("Filename:", preserve, StringComparison.Ordinal);
        Assert.DoesNotContain("skipifsilent", iss[preserveLine..preserve]);
        Assert.Contains(AgentLayout.SetupTaskName, iss);

        Assert.Contains("start= " + AgentServiceControl.AutomaticStartType, wxs);
        Assert.Contains(AgentServiceControl.FailureRestartActions, wxs);
        Assert.Contains("Start=\"install\"", wxs);
        Assert.DoesNotContain("delayed-auto", wxs);
        Assert.DoesNotContain("start= disabled", wxs);
        Assert.Contains("Id=\"EnsureAgentServiceRunning\"", wxs);
        var install = wxs.IndexOf("After=\"InstallFiles\"", StringComparison.Ordinal);
        var ensure = wxs.IndexOf("After=\"InstallAgentService\"", StringComparison.Ordinal);
        Assert.True(install > 0 && ensure > install);
        Assert.Contains("NOT REMOVE~=&quot;ALL&quot;", wxs);
    }

    [Fact]
    public void Plain_setup_upgrades_an_installed_agent_from_the_bundled_msi_without_an_enrollment_key()
    {
        var root = FindRepoRoot();
        var iss = File.ReadAllText(Path.Combine(root, "installer", "RemotePCDiagnostics.iss"));
        var script = File.ReadAllText(Path.Combine(root, "installer", "Build-Installer.ps1"));

        Assert.Contains("#ifndef AgentMsiPath", iss);
        Assert.Contains("function ShouldUpgradeBundledAgent(): Boolean;", iss);
        Assert.Contains("(not HasSetupParam('AGENTMSI')) and AgentServiceIsInstalled()", iss);
        Assert.Contains("DestName: \"RemotePCDiagnostics.Agent.msi\"", iss);

        var bundled = iss.IndexOf("Check: ShouldUpgradeBundledAgent", StringComparison.Ordinal);
        var bundledLine = iss[iss.LastIndexOf("Filename:", bundled, StringComparison.Ordinal)..iss.IndexOf('\n', bundled)];
        Assert.Contains("/i \"\"{tmp}\\RemotePCDiagnostics.Agent.msi\"\" /qn /norestart", bundledLine);
        Assert.DoesNotContain("ENROLLMENT_KEY", bundledLine);
        Assert.DoesNotContain("SERVER_URL", bundledLine);
        Assert.DoesNotContain("--key", bundledLine);

        var passed = iss.IndexOf("Check: HasSetupParam('AGENTMSI')", StringComparison.Ordinal);
        var passedLine = iss[iss.LastIndexOf("Filename:", passed, StringComparison.Ordinal)..iss.IndexOf('\n', passed)];
        Assert.Contains("{param:AGENTMSI}", passedLine);
        Assert.DoesNotContain("ENROLLMENT_KEY", passedLine);
        Assert.DoesNotContain("SERVER_URL", passedLine);

        Assert.Contains("-AgentMsiPath", script);
        Assert.Contains("not both", script);
    }

    [Fact]
    public void Ci_plain_setup_embeds_the_agent_msi_and_the_testshop_bundle_does_not()
    {
        var ci = File.ReadAllText(Path.Combine(FindRepoRoot(), ".github", "workflows", "ci.yml"));
        var installerAt = ci.IndexOf("Build and smoke-test Windows installer", StringComparison.Ordinal);
        var testshopAt = ci.IndexOf("Build and smoke-test TestShop", StringComparison.Ordinal);
        Assert.True(installerAt > 0 && testshopAt > installerAt);

        var installerJob = ci[installerAt..testshopAt];
        var setupBuilds = installerJob.Split('\n').Where(line => line.Contains("Build-Installer.ps1", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(setupBuilds);
        Assert.All(setupBuilds, line => Assert.DoesNotContain("-AgentEnrollmentKey", line));
        Assert.All(setupBuilds, line => Assert.DoesNotContain("-AgentExePath", line));
        Assert.Contains(setupBuilds, line => line.Contains("-AgentMsiPath $agentMsi", StringComparison.Ordinal));
        Assert.Contains("Plain Setup installed the agent service on a fresh PC", installerJob);
        Assert.Contains("Setup upgrade changed agent.json", installerJob);
        Assert.Contains("$smokeServer = 'http://127.0.0.1:9'", installerJob);

        var agentAt = ci.IndexOf("\n  agent:", testshopAt, StringComparison.Ordinal);
        var testshopJob = ci[testshopAt..agentAt];
        Assert.Contains("-AgentExePath $agentExe", testshopJob);
        Assert.DoesNotContain("-AgentMsiPath", testshopJob);
    }
}
