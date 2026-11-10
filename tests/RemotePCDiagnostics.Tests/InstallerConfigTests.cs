using System.Xml.Linq;
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
        Assert.Contains("--self-contained true", raw);
        Assert.Contains("moduleui", raw);
    }

    [Fact]
    public void InnoSetupScript_StaysInSyncWithHostAndWorkflowContracts()
    {
        var root = FindRepoRoot();
        var issPath = Path.Combine(root, "installer", "RemotePCDiagnostics.iss");
        Assert.True(File.Exists(issPath), $"Missing Inno Setup script: {issPath}");

        var iss = File.ReadAllText(issPath);

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

        // Start Menu + optional Desktop shortcut task.
        Assert.Contains(@"Name: ""desktopicon""", iss);
        Assert.Contains(@"Name: ""{autoprograms}\{#AppName}""", iss);
        Assert.Contains(@"Name: ""{autodesktop}\{#AppName}""", iss);
        Assert.Contains("Tasks: desktopicon", iss);

        // Post-install launch must use shellexec because Host manifest requires Administrator.
        Assert.Contains("postinstall skipifsilent shellexec", iss);

        // WebView2 Evergreen Runtime check & bootstrapper.
        Assert.Contains("{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", iss);
        Assert.Contains("https://go.microsoft.com/fwlink/p/?LinkId=2124703", iss);
        Assert.Contains("IsWebView2Installed", iss);

        // Uninstall cleanup: workflow scheduled task, RunOnce resume value, and optional state/log removal.
        Assert.Contains(WorkflowService.ResumeTaskName, iss);
        Assert.Contains(RebootResumeCoordinator.RunOnceValueName, iss);
        Assert.Contains(@"{commonappdata}\RemotePCDiagnostics", iss);
        Assert.Contains(@"{localappdata}\RemotePCDiagnostics", iss);
        Assert.Contains("/CLEANSTATE", iss);
        Assert.Contains("MB_DEFBUTTON2", iss);
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
}
