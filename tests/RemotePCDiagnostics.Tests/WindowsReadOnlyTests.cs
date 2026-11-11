using System.Diagnostics;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Scripts;

namespace RemotePCDiagnostics.Tests;

/// <summary>A fact that runs on Windows only (skipped elsewhere): it talks to the real PC.</summary>
public sealed class WindowsFactAttribute : FactAttribute
{
    // xunit.v3 records where each test is declared; a derived attribute passes the caller's file and line on.
    public WindowsFactAttribute([System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    { if (!OperatingSystem.IsWindows()) Skip = "Needs Windows."; }
}

/// <summary>
/// Runs every read-only embedded PowerShell script for real (category WindowsReadOnly: <c>dotnet test --filter Category=WindowsReadOnly</c>).
/// Nothing here changes the PC. Scripts that change things (temp clean-up, Windows Update) are only checked to load.
/// </summary>
[Trait("Category", "WindowsReadOnly")]
public class WindowsReadOnlyTests
{
    /// <summary>Read-only scripts, and whether they always print something.</summary>
    public static TheoryData<string, bool> ReadOnlyScripts => new()
    {
        { "ProblemDevices", false },      // empty when no device has a problem
        { "DriveHealth", true },
        { "NetAdapterStatistics", false }, // empty without a connected adapter
        { "FastStartupState", true },
        { "IpConfig", true },
        { "DefenderExclusions", true },
        { "DockDevices", true },
        { "MemoryProbe", true },
    };

    /// <summary>Scripts that change the PC: never run by a test.</summary>
    private static readonly string[] Changing = ["CleanTempFiles", "WindowsUpdate"];
    /// <summary>Needs the Windows Search service, which a PC may have turned off: run, but its exit code isn't asserted.</summary>
    private const string SearchIndex = "SearchIndexProjects";

    [Fact]
    public void Every_embedded_script_is_listed_here_and_loads()
    {
        var listed = ReadOnlyScripts.Select(r => (string)((ITheoryDataRow)r).GetData()[0]!).Concat(Changing).Append(SearchIndex).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(listed, PowerShellScripts.Names);
        Assert.All(PowerShellScripts.Names, n => Assert.False(string.IsNullOrWhiteSpace(PowerShellScripts.Get(n))));
        Assert.Throws<InvalidOperationException>(() => PowerShellScripts.Get("NoSuchScript"));
        Assert.Contains("Type='Driver'", RemediationService.BuildWindowsUpdateScript(driversOnly: true));
        Assert.Contains("Type='Software'", RemediationService.BuildWindowsUpdateScript(driversOnly: false));
        Assert.DoesNotContain("__CRITERIA__", RemediationService.BuildWindowsUpdateScript(driversOnly: false));
    }

    [WindowsTheory]
    [MemberData(nameof(ReadOnlyScripts))]
    public async Task Read_only_script_runs_on_this_PC(string name, bool printsSomething)
    {
        var (exit, output, error) = await RunAsync(PowerShellScripts.Get(name));
        Assert.True(exit == 0, $"{name} exited {exit}: {error}");
        if (printsSomething) Assert.False(string.IsNullOrWhiteSpace(output), $"{name} printed nothing: {error}");
    }

    [WindowsFact]
    public async Task Script_output_parses()
    {
        var ip = WifiConfigModule.ParseIpSnapshot((await RunAsync(WifiConfigModule.IpConfigScript)).Output);
        Assert.NotNull(ip);
        var (auto, _) = MemoryProbe.Parse((await RunAsync(MemoryProbe.Script)).Output);
        Assert.NotNull(auto);
        Assert.NotNull(DefenderProbe.Parse((await RunAsync(DefenderProbe.Script)).Output));
    }

    [WindowsFact]
    public async Task Search_index_script_runs()
    {
        var (exit, _, error) = await RunAsync(PowerShellScripts.Get(SearchIndex));
        Assert.True(exit is 0 or 1, $"exited {exit}: {error}"); // 1: the Windows Search provider isn't available on this PC
    }

    private static async Task<(int Exit, string Output, string Error)> RunAsync(string script)
    {
        var psi = new ProcessStartInfo(SystemCommandRunner.PowerShell) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var output = p.StandardOutput.ReadToEndAsync(timeout.Token);
        var error = p.StandardError.ReadToEndAsync(timeout.Token);
        await p.WaitForExitAsync(timeout.Token);
        return (p.ExitCode, await output, await error);
    }
}

/// <summary>A theory that runs on Windows only (skipped elsewhere).</summary>
public sealed class WindowsTheoryAttribute : TheoryAttribute
{
    public WindowsTheoryAttribute([System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    { if (!OperatingSystem.IsWindows()) Skip = "Needs Windows."; }
}
