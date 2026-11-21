using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Modules.DeveloperSetup;

namespace RemotePCDiagnostics.Tests;

public sealed class DeveloperBenchmarkTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-devbench-test-" + Guid.NewGuid().ToString("N"));

    public DeveloperBenchmarkTests() => Directory.CreateDirectory(_root);
    public void Dispose() { try { Directory.Delete(_root, recursive: true); } catch { } }

    // ---- Toolchain detection & Dev Drive query parsing ----

    [Fact]
    public async Task Detector_ReturnsOnlyInstalledToolchains_AndOmitsAbsentOnes()
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Program Files\dotnet\dotnet.exe",
            @"C:\Program Files\Go\bin\go.exe",
        };
        var launcher = new FakeLauncher((exe, args) =>
        {
            if (exe.EndsWith("dotnet.exe", StringComparison.OrdinalIgnoreCase)) return new(0, "10.0.404\r\n", "");
            if (exe.EndsWith("go.exe", StringComparison.OrdinalIgnoreCase)) return new(0, "go version go1.24.1 windows/amd64\r\n", "");
            return new(1, "", "not found");
        });
        var detector = new DeveloperToolchainDetector(launcher, files.Contains, _ => "", isWindows: true);
        var found = await detector.DetectAllAsync();

        Assert.Equal(2, found.Count);
        Assert.Contains(found, t => t.Language == DeveloperLanguage.CSharp && t.Version == "10.0.404" && t.MajorVersion == 10);
        Assert.Contains(found, t => t.Language == DeveloperLanguage.Go && t.MajorVersion == 1);
        Assert.DoesNotContain(found, t => t.Language == DeveloperLanguage.Rust);
        Assert.DoesNotContain(found, t => t.Language == DeveloperLanguage.TypeScript);
        Assert.DoesNotContain(found, t => t.Language == DeveloperLanguage.Python);
        Assert.DoesNotContain(found, t => t.Language == DeveloperLanguage.Cpp);
    }

    [Theory]
    [InlineData(22621, 2338, true)]
    [InlineData(26100, 0, true)]
    [InlineData(22621, 2337, false)]
    [InlineData(19045, 5000, false)]
    public void Windows11DevDriveBuildCheck_MatchesMinimum22621_2338(int build, int ubr, bool expected) =>
        Assert.Equal(expected, DeveloperToolchainDetector.IsWindows11DevDriveCapable(build, ubr));

    [Fact]
    public void ParseFsutilDevDriveQuery_HandlesDevDriveNtfsAndPolicy()
    {
        var dd = DeveloperToolchainDetector.ParseFsutilDevDriveQuery(0, "D: is a developer volume.\r\nVolume is trusted. Performance mode is enabled.", true);
        Assert.True(dd.SupportedByOs);
        Assert.True(dd.IsDevDrive);
        Assert.True(dd.PolicyEnabled);
        Assert.True(dd.DefenderPerformanceModeActive);

        var ntfs = DeveloperToolchainDetector.ParseFsutilDevDriveQuery(0, "C: is NOT a developer volume.", true);
        Assert.True(ntfs.SupportedByOs);
        Assert.False(ntfs.IsDevDrive);
        Assert.True(ntfs.PolicyEnabled);

        var disabled = DeveloperToolchainDetector.ParseFsutilDevDriveQuery(1, "Developer volumes are disabled by policy.", true);
        Assert.False(disabled.PolicyEnabled);

        var win10 = DeveloperToolchainDetector.ParseFsutilDevDriveQuery(1, "Error: invalid parameter", false);
        Assert.False(win10.SupportedByOs);
    }

    // ---- Scoring, CPU-class bucketing, baselines, and sample storage ----

    [Theory]
    [InlineData("Intel(R) Core(TM) i7-1355U", 10, DeveloperCpuClass.MobileLowPower)]
    [InlineData("AMD Ryzen 7 7840U", 16, DeveloperCpuClass.MobileLowPower)]
    [InlineData("Intel(R) Core(TM) i7-13700H", 20, DeveloperCpuClass.MobileMainstream)]
    [InlineData("AMD Ryzen 9 7945HX", 32, DeveloperCpuClass.MobileMainstream)]
    [InlineData("Intel(R) Core(TM) i9-14900K", 32, DeveloperCpuClass.Desktop)]
    [InlineData("AMD Ryzen 7 7800X3D", 16, DeveloperCpuClass.Desktop)]
    public void ClassifyCpu_BucketsCommonCpus(string name, int cores, DeveloperCpuClass expected) =>
        Assert.Equal(expected, DeveloperScoring.ClassifyCpu(name, cores));

    [Fact]
    public void Baselines_RequireAtLeastThreeReferenceMachines_AndEvaluateBands()
    {
        var underSampled = new DeveloperBaselineRow(DeveloperCpuClass.Desktop, DeveloperLanguage.CSharp, DeveloperCSharpPin.PinId, 10,
            ["i9-14900K", "Ryzen 7 7800X3D"], [32, 16], 10.0, 6.0, SampleCount: 2, new DateOnly(2026, 11, 20));
        var calibrated = underSampled with { SampleCount = 3 };

        var catUnder = new DeveloperBaselineCatalog(1, [underSampled]);
        Assert.Null(catUnder.FindUsable(DeveloperCpuClass.Desktop, DeveloperLanguage.CSharp, DeveloperCSharpPin.PinId, 10));

        var catReady = new DeveloperBaselineCatalog(1, [calibrated]);
        var row = catReady.FindUsable(DeveloperCpuClass.Desktop, DeveloperLanguage.CSharp, DeveloperCSharpPin.PinId, 10);
        Assert.NotNull(row);
        Assert.Equal(100.0, DeveloperScoring.ComputeScore(6.0, row));
        Assert.Equal(DeveloperBand.Pass, DeveloperScoring.EvaluateBand(7.5, row, comparable: true));      // 1.25x
        Assert.Equal(DeveloperBand.Warning, DeveloperScoring.EvaluateBand(12.0, row, comparable: true));  // 2.0x
        Assert.Equal(DeveloperBand.Fail, DeveloperScoring.EvaluateBand(12.1, row, comparable: true));     // >2.0x
        Assert.Equal(DeveloperBand.NoBaseline, DeveloperScoring.EvaluateBand(15.0, row, comparable: false)); // non-comparable condition
    }

    [Fact]
    public void OverallScore_UsesGeometricMean_AndSingleLanguageEqualsItself()
    {
        Assert.Equal(92.5, DeveloperScoring.OverallScore([92.5]));
        Assert.Equal(100.0, DeveloperScoring.OverallScore([50.0, 200.0]));
        Assert.Null(DeveloperScoring.OverallScore([]));
    }

    [Fact]
    public void SampleStore_WritesSeparateAnonymousFile_WithoutMachineOrUserIdentity()
    {
        var path = Path.Combine(_root, ProtectedState.DevBenchmarksFile);
        var store = new FileDeveloperSampleStore(path);
        store.Append(new DeveloperBenchmarkSample(
            DeveloperLanguage.CSharp, DeveloperCSharpPin.PinId, "ABCDEF", "10.0.404", 10,
            DeveloperCpuClass.Desktop, "AMD Ryzen 7 7800X3D", 16, false, "Balanced", true,
            9.2, 6.4, 5.1, 1.3, 3, 5, DateTimeOffset.UtcNow));

        var raw = File.ReadAllText(path);
        Assert.DoesNotContain(Environment.MachineName, raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Environment.UserName, raw, StringComparison.OrdinalIgnoreCase);
        Assert.Single(store.Load().Samples);
        Assert.Null(ProtectedStateFiles.InvalidState(ProtectedState.DevBenchmarksFile, raw));
    }

    // ---- Agent allowlist rules (temporary Defender exclusion + temporary Dev Drive VHDX) ----

    [Fact]
    public void MachineTweakRules_AllowsOnlyRpcdTempBuildFolders_AndRpcdDevDriveVhdx()
    {
        var paths = new DefenderPaths(
            [@"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData"],
            [@"C:\Program Files"],
            _ => true, _ => true)
        {
            UserTempFolders = [@"C:\Users\alice\AppData\Local\Temp"],
            IsReparsePoint = p => p.EndsWith("-link0000", StringComparison.OrdinalIgnoreCase),
        };

        Assert.Null(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Users\alice\AppData\Local\Temp\rpcd-devbench-0123456789abcdef"), paths));
        // Only the signed-in user's own Temp: never Windows\Temp, another user's Temp, or any other folder named Temp.
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Windows\Temp\rpcd-devbench-0123456789abcdef"), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Temp\rpcd-devbench-0123456789abcdef"), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Users\bob\AppData\Local\Temp\rpcd-devbench-0123456789abcdef"), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Users\alice\AppData\Local\Temp\sub\rpcd-devbench-0123456789abcdef"), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Users\alice\AppData\Local\Temp\rpcd-devbench-link0000"), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Users\alice\AppData\Local\Temp\rpcd-devbench-0123456789abcdef"), paths with { UserTempFolders = [] }));
        // Removing a leftover is allowed wherever it is (the Agent's startup sweep does the same).
        Assert.Null(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempRemove, Target: @"C:\Users\bob\AppData\Local\Temp\rpcd-devbench-0123456789abcdef"), paths));
        Assert.Null(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempRemove, Target: @"C:\Users\alice\AppData\Local\Temp\rpcd-devbench-0123456789abcdef"), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Users\alice\AppData\Local\Temp"), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Users\alice\AppData\Local\Temp\other-folder"), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"D:\work\rpcd-devbench-0123456789abcdef"), paths));

        Assert.Null(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DevDriveCreate, Number: 50, Text: "S-1-5-21-100-200-300-1001"), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DevDriveCreate, Number: 10), paths));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DevDriveCreate, Number: 50, Text: "not-a-sid"), paths));

        var validVhdx = @"C:\ProgramData\RemotePCDiagnostics\devdrive-temp\rpcd-devdrive-0123456789abcdef.vhdx";
        Assert.True(DevDriveRules.IsRpcdDevDriveVhdx(validVhdx, @"C:\ProgramData\RemotePCDiagnostics\devdrive-temp"));
        Assert.False(DevDriveRules.IsRpcdDevDriveVhdx(@"C:\Temp\rpcd-devdrive-0123456789abcdef.vhdx", @"C:\ProgramData\RemotePCDiagnostics\devdrive-temp"));
        Assert.False(DevDriveRules.IsRpcdDevDriveVhdx(@"C:\ProgramData\RemotePCDiagnostics\devdrive-temp\other.vhdx", @"C:\ProgramData\RemotePCDiagnostics\devdrive-temp"));
    }

    // ---- Phase 1 clean build + AV comparison & Phase 2 Dev Drive comparison ----

    [Fact]
    public async Task CSharpCleanBuild_TimesRestoreSeparately_CleansTempAndRemovesTempExclusion()
    {
        var tempRoot = Path.Combine(_root, "temp");
        Directory.CreateDirectory(tempRoot);
        var env = new FakeDevEnv
        {
            Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "10.0.404", 10)],
            FreeGb = 80,
            AgentConnected = true,
            Defender = new(true, [], [], true),
        };
        var tweaks = new FakeDevTweaks();
        var store = new FileDeveloperSampleStore(Path.Combine(_root, "dev-benchmarks.json"));
        var commands = new List<string>();
        var launcher = new FakeLauncher((_, args) =>
        {
            commands.Add(string.Join(' ', args));
            return new(0, "ok", "");
        });

        var runner = new DeveloperBuildRunner(env, launcher, tweaks, store, DeveloperBaselineCatalog.Empty, tempRootOverride: tempRoot);
        var res = await runner.RunCSharpCleanBuildAsync(new DeveloperBuildOptions(ColdRepeats: 2, WarmWarmups: 1, WarmRepeats: 3, IncludeAntivirusComparison: true, AllowHyperfine: false));

        Assert.True(res.Succeeded);
        Assert.Equal(2, res.ColdSamples.Count);
        Assert.Equal(3, res.WarmSamples.Count);
        Assert.NotNull(res.RestoreSeconds);
        Assert.NotNull(res.WarmExcludedMedianSeconds);
        Assert.Equal(DeveloperBand.NoBaseline, res.Band);
        Assert.Contains("no baseline yet", res.FormatDetail());
        Assert.Single(tweaks.TempAdded);
        Assert.Single(tweaks.TempRemoved);
        Assert.Equal(tweaks.TempAdded[0], tweaks.TempRemoved[0]);
        Assert.Empty(Directory.EnumerateDirectories(tempRoot)); // temp build folder deleted
        Assert.Single(store.Load().Samples);
    }

    [Fact]
    public async Task CSharpCleanBuild_Below10GbFreeSpace_ReportsCouldNotRun()
    {
        var env = new FakeDevEnv
        {
            Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "10.0.404", 10)],
            FreeGb = 4.2,
        };
        var runner = new DeveloperBuildRunner(env, new FakeLauncher((_, _) => new(0, "", "")), tempRootOverride: _root);
        var res = await runner.RunCSharpCleanBuildAsync();

        Assert.False(res.Succeeded);
        Assert.Contains("Could not run", res.Note);
    }

    [Fact]
    public async Task DevDriveComparison_PrechecksAndCleansUpVhdxOnSuccess()
    {
        var tempRoot = Path.Combine(_root, "dd-temp");
        var fakeDevDriveFolder = Path.Combine(_root, "dd-mount");
        Directory.CreateDirectory(tempRoot);
        Directory.CreateDirectory(fakeDevDriveFolder);

        var env = new FakeDevEnv
        {
            Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "10.0.404", 10)],
            FreeGb = 120,
            AgentConnected = true,
            WindowsBuild = (26100, 1000),
            DevDriveStatus = new(true, false, true, true),
            Conditions = new(false, 45, "Balanced"),
        };
        var tweaks = new FakeDevTweaks
        {
            MountResult = new(true, @"C:\ProgramData\RemotePCDiagnostics\devdrive-temp\rpcd-devdrive-12345678.vhdx", "Z", fakeDevDriveFolder),
        };
        var runner = new DeveloperBuildRunner(env, new FakeLauncher((_, _) => new(0, "", "")), tweaks, tempRootOverride: tempRoot);

        var pre = await runner.EvaluateDevDrivePrecheckAsync();
        Assert.True(pre.Eligible);

        var res = await runner.RunDevDriveComparisonAsync(new DeveloperBuildOptions(ColdRepeats: 1, WarmWarmups: 0, WarmRepeats: 1, AllowHyperfine: false));
        Assert.True(res.Succeeded);
        Assert.Equal("NTFS, then Dev Drive", res.Order);
        Assert.True(res.DefenderPerformanceModeActive);
        Assert.Single(tweaks.DevDrivesRemoved);
        Assert.Empty(Directory.EnumerateDirectories(tempRoot));
        Assert.Empty(Directory.EnumerateDirectories(fakeDevDriveFolder));
    }

    [Fact]
    public async Task DevDrivePrecheck_RejectsBatteryOrOlderWindows()
    {
        var env = new FakeDevEnv { WindowsBuild = (19045, 0), FreeGb = 100, AgentConnected = true };
        var runner = new DeveloperBuildRunner(env);
        var preWin10 = await runner.EvaluateDevDrivePrecheckAsync();
        Assert.False(preWin10.Eligible);

        env.WindowsBuild = (26100, 0);
        env.DevDriveStatus = new(true, false, true);
        env.Conditions = new(OnBattery: true, 45, "Balanced");
        var preBattery = await runner.EvaluateDevDrivePrecheckAsync();
        Assert.False(preBattery.Eligible);
        Assert.Contains("AC power", preBattery.Reason);
    }

    [Fact]
    public void CSharpPin_TargetsTheInstalledSdk_AndNotANewerOrX64OnlyFramework()
    {
        Assert.Equal("net9.0", DeveloperCSharpPin.TargetFrameworkForSdk(9));
        Assert.Equal("net8.0", DeveloperCSharpPin.TargetFrameworkForSdk(8));
        Assert.Equal("net10.0", DeveloperCSharpPin.TargetFrameworkForSdk(10));
        Assert.Equal("net11.0", DeveloperCSharpPin.TargetFrameworkForSdk(11));
        Assert.Null(DeveloperCSharpPin.TargetFrameworkForSdk(7));
        Assert.Null(DeveloperCSharpPin.TargetFrameworkForSdk(null));
        Assert.Contains("6.0.428", DeveloperCSharpPin.UnsupportedSdkReason("6.0.428", 6));
        Assert.Null(DeveloperCSharpPin.UnsupportedSdkReason("9.0.200", 9));

        var (proj, _) = DeveloperCSharpPin.Materialize(Path.Combine(_root, "pin9"), 9);
        var text = File.ReadAllText(proj);
        Assert.Contains("<TargetFramework>net9.0</TargetFramework>", text);
        Assert.DoesNotContain("net10.0", text);
        Assert.DoesNotContain("RuntimeIdentifier", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("win-x64", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CleanBuildOutputs_DeletesCompilerOutputs_AndKeepsNuGetRestoreAssets()
    {
        var proj = Path.Combine(_root, "clean", "BenchApp");
        var obj = Path.Combine(proj, "obj");
        Directory.CreateDirectory(Path.Combine(obj, "Release"));
        Directory.CreateDirectory(Path.Combine(proj, "bin", "Release"));
        File.WriteAllText(Path.Combine(obj, "project.assets.json"), "{}");
        File.WriteAllText(Path.Combine(obj, "project.nuget.cache"), "{}");
        File.WriteAllText(Path.Combine(obj, "BenchApp.csproj.nuget.g.props"), "<Project />");
        File.WriteAllText(Path.Combine(obj, "BenchApp.csproj.nuget.g.targets"), "<Project />");
        File.WriteAllText(Path.Combine(obj, "BenchApp.csproj.nuget.dgspec.json"), "{}");
        File.WriteAllText(Path.Combine(obj, "AssemblyInfo.cs"), "// compiler");
        File.WriteAllText(Path.Combine(obj, "Release", "out.dll"), "dll");
        File.WriteAllText(Path.Combine(proj, "bin", "Release", "out.dll"), "dll");

        DeveloperBuildRunner.CleanBuildOutputs(Path.Combine(_root, "clean"));

        Assert.True(File.Exists(Path.Combine(obj, "project.assets.json")));
        Assert.True(File.Exists(Path.Combine(obj, "project.nuget.cache")));
        Assert.True(File.Exists(Path.Combine(obj, "BenchApp.csproj.nuget.g.props")));
        Assert.True(File.Exists(Path.Combine(obj, "BenchApp.csproj.nuget.g.targets")));
        Assert.True(File.Exists(Path.Combine(obj, "BenchApp.csproj.nuget.dgspec.json")));
        Assert.False(File.Exists(Path.Combine(obj, "AssemblyInfo.cs")));
        Assert.False(Directory.Exists(Path.Combine(obj, "Release")));
        Assert.False(Directory.Exists(Path.Combine(proj, "bin")));
    }

    [Fact]
    public void CleanPrepareCommand_KeepsNuGetAssets_AndDoesNotUseBrokenInclude()
    {
        var cmd = DeveloperBuildRunner.CleanPrepareCommand(Path.Combine(_root, "work"));
        Assert.Contains("project.assets.json", cmd);
        Assert.Contains("nuget.g.props", cmd);
        Assert.DoesNotContain("-Include bin,obj", cmd);
    }

    [Fact]
    public void FormatToolFailure_ReportsExitCode_AndFirstErrorLines()
    {
        var text = DeveloperBuildRunner.FormatToolFailure("cold dotnet build", 1, timedOut: false,
            "Build FAILED.\r\n    1 Error(s)\r\n",
            "BenchApp.csproj : error NETSDK1004: Assets file 'project.assets.json' not found.\r\nerror CS0103: The name 'x' does not exist\r\n");
        Assert.Contains("Could not run: cold dotnet build failed (exit 1).", text);
        Assert.Contains("error NETSDK1004", text);
        Assert.Contains("error CS0103", text);
        Assert.DoesNotContain("Error(s)", text);

        var timed = DeveloperBuildRunner.FormatToolFailure("cold dotnet build", -1, timedOut: true, null, null);
        Assert.Equal("Could not run: cold dotnet build failed (timed out).", timed);
        Assert.False(DeveloperBuildRunner.IsToolErrorLine("    1 Error(s)"));
        Assert.True(DeveloperBuildRunner.IsToolErrorLine("error NETSDK1004: Assets file not found."));
    }

    [Fact]
    public void ScrubPaths_HidesTheBuildFolder_TheProfile_AndShortProfileNames()
    {
        var profile = @"C:\Users\Jane Doe";
        var work = profile + @"\AppData\Local\Temp\rpcd-build-abc";
        var text = work + @"\BenchApp\Program.cs(3,1): error CS0103 | "
            + profile + @"\.nuget\packages\x : error NU1101 | "
            + @"C:\Users\JANEDO~1\AppData\Local\Temp\rpcd-build-abc\BenchApp.csproj : error NETSDK1004";

        var scrubbed = DeveloperBuildRunner.ScrubPaths(text, work, profile)!;

        Assert.DoesNotContain("Jane", scrubbed, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("JANEDO~1", scrubbed);
        Assert.Contains(@"<build folder>\BenchApp\Program.cs(3,1): error CS0103", scrubbed);
        Assert.Contains(@"%USERPROFILE%\.nuget\packages\x : error NU1101", scrubbed);
        Assert.Contains(@"C:\Users\<user>\AppData", scrubbed);
        Assert.Null(DeveloperBuildRunner.ScrubPaths(null, work, profile));
    }

    [Fact]
    public async Task CSharpCleanBuild_FailureNote_DoesNotNameTheBuildFolder()
    {
        var env = new FakeDevEnv { Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "9.0.200", 9)] };
        string? buildFolder = null;
        var launcher = new FakeLauncher((_, args) =>
        {
            buildFolder ??= Directory.GetParent(Path.GetDirectoryName(args[1])!)!.FullName;
            return args[0] == "restore"
                ? new(0, "restore ok", "")
                : new(1, "", Path.Combine(buildFolder, "BenchApp", "Program.cs") + "(3,1): error CS0103: The name 'x' does not exist\r\n");
        });
        var runner = new DeveloperBuildRunner(env, launcher, tempRootOverride: _root);
        var res = await runner.RunCSharpCleanBuildAsync(new DeveloperBuildOptions(ColdRepeats: 1, WarmWarmups: 0, WarmRepeats: 1, AllowHyperfine: false));

        Assert.False(res.Succeeded);
        Assert.NotNull(buildFolder);
        Assert.DoesNotContain(buildFolder!, res.Note);
        Assert.Contains("<build folder>", res.Note);
        Assert.Contains("error CS0103", res.Note);
    }

    [Fact]
    public async Task CSharpCleanBuild_KeepsNuGetAssets_SoNoRestoreBuildSucceeds()
    {
        var tempRoot = Path.Combine(_root, "assets");
        Directory.CreateDirectory(tempRoot);
        string? work = null;
        var launcher = new FakeLauncher((_, args) =>
        {
            var project = args[1];
            work ??= Directory.GetParent(Path.GetDirectoryName(project)!)!.FullName;
            if (args[0] == "restore")
            {
                foreach (var proj in Directory.EnumerateFiles(work, "*.csproj", SearchOption.AllDirectories))
                    SeedRestoredProject(proj);
                return new(0, "", "");
            }

            foreach (var proj in Directory.EnumerateFiles(work, "*.csproj", SearchOption.AllDirectories))
            {
                var dir = Path.GetDirectoryName(proj)!;
                var obj = Path.Combine(dir, "obj");
                var name = Path.GetFileName(proj);
                if (!File.Exists(Path.Combine(obj, "project.assets.json"))
                    || !File.Exists(Path.Combine(obj, name + ".nuget.g.props"))
                    || !File.Exists(Path.Combine(obj, name + ".nuget.g.targets")))
                {
                    return new(1, "", "error NETSDK1004: Assets file 'project.assets.json' not found. Run a NuGet package restore to generate this file.");
                }
                if (Directory.Exists(Path.Combine(dir, "bin"))
                    || File.Exists(Path.Combine(obj, "Release", "out.dll"))
                    || File.Exists(Path.Combine(obj, "AssemblyInfo.cs")))
                    return new(1, "", "error : compiler outputs were left in place");
            }
            return new(0, "ok", "");
        });

        var env = new FakeDevEnv { Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "9.0.200", 9)] };
        var runner = new DeveloperBuildRunner(env, launcher, tempRootOverride: tempRoot);
        var res = await runner.RunCSharpCleanBuildAsync(new DeveloperBuildOptions(ColdRepeats: 1, WarmWarmups: 0, WarmRepeats: 1, AllowHyperfine: false));

        Assert.True(res.Succeeded, res.Note);
    }

    [Fact]
    public async Task CSharpCleanBuild_WhenBuildFails_ReportsExitCodeAndErrorLines()
    {
        var env = new FakeDevEnv { Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "9.0.200", 9)] };
        var launcher = new FakeLauncher((_, args) => args[0] == "restore"
            ? new(0, "restore ok", "")
            : new(1, "Build FAILED.\r\n    1 Error(s)\r\n",
                "BenchApp.csproj : error NETSDK1004: Assets file 'obj\\project.assets.json' not found. Run a NuGet package restore to generate this file.\r\n"));
        var runner = new DeveloperBuildRunner(env, launcher, tempRootOverride: _root);
        var res = await runner.RunCSharpCleanBuildAsync(new DeveloperBuildOptions(ColdRepeats: 1, WarmWarmups: 0, WarmRepeats: 1, AllowHyperfine: false));

        Assert.False(res.Succeeded);
        Assert.Equal(1, res.ToolExitCode);
        Assert.Contains("Could not run: cold dotnet build failed (exit 1).", res.Note);
        Assert.Contains("error NETSDK1004", res.Note);
        Assert.DoesNotContain("1 Error(s)", res.Note);
        Assert.Equal(res.Note, res.FormatDetail());
    }

    [Fact]
    public async Task CSharpCleanBuild_RunsDotnetInTheWritableTempFolder()
    {
        var tempRoot = Path.Combine(_root, "cwd-run");
        Directory.CreateDirectory(tempRoot);
        var launcher = new RecordingLauncher();
        var env = new FakeDevEnv { Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "9.0.200", 9)] };
        var runner = new DeveloperBuildRunner(env, launcher, tempRootOverride: tempRoot);
        var res = await runner.RunCSharpCleanBuildAsync(new DeveloperBuildOptions(ColdRepeats: 1, WarmWarmups: 0, WarmRepeats: 1, AllowHyperfine: false));

        Assert.True(res.Succeeded, res.Note);
        Assert.NotEmpty(launcher.Directories);
        Assert.All(launcher.Directories, dir =>
        {
            Assert.False(string.IsNullOrWhiteSpace(dir));
            Assert.StartsWith(tempRoot, dir, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public async Task SystemProcessLauncher_RunsInTheRequestedDirectory()
    {
        var dir = Path.Combine(_root, "cwd check");
        Directory.CreateDirectory(dir);
        var exe = OperatingSystem.IsWindows() ? Path.Combine(Environment.SystemDirectory, "cmd.exe") : "/bin/sh";
        // No spaces in the Windows command: ArgumentList quoting would otherwise hide cmd's redirection.
        IReadOnlyList<string> args = OperatingSystem.IsWindows()
            ? ["/c", "cd>cwd-ok.txt"]
            : ["-c", "printf ok > cwd-ok.txt"];
        IProcessLauncher launcher = new SystemProcessLauncher();
        var result = await launcher.RunAsync(exe, args, TimeSpan.FromSeconds(15), CancellationToken.None, dir);

        Assert.Equal(0, result.ExitCode);
        Assert.True(File.Exists(Path.Combine(dir, "cwd-ok.txt")));
    }

    [Fact]
    public async Task BenchmarkService_HidesCSharp_WhenSdkIsOlderThanThePin()
    {
        var env = new FakeDevEnv { Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "6.0.428", 6)] };
        var svc = new BenchmarkService(new BenchmarkRunner(new DummyBenchProbes()), new InMemoryBenchmarkStore(), devRunner: new DeveloperBuildRunner(env), devEnv: env);
        await svc.RefreshDeveloperEnvironmentAsync();
        Assert.False(svc.IsKindAvailable(BenchmarkKind.DeveloperCSharp));
        Assert.DoesNotContain(svc.AvailableBenchmarks, i => i.Kind == BenchmarkKind.DeveloperCSharp);

        var res = await new DeveloperBuildRunner(env, new FakeLauncher((_, _) => new(0, "", "")), tempRootOverride: _root).RunCSharpCleanBuildAsync();
        Assert.False(res.Succeeded);
        Assert.Contains(".NET SDK 8 or newer", res.Note);
        Assert.Contains("6.0.428", res.Note);

        env.Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "9.0.200", 9)];
        await svc.RefreshDeveloperEnvironmentAsync();
        Assert.True(svc.IsKindAvailable(BenchmarkKind.DeveloperCSharp));
    }

    [Fact]
    public async Task CSharpPin_RealSdk_BuildsAfterCleanKeepsRestoreAssets()
    {
        // A missing or too-old SDK shows as Skipped, not Passed, so a run that never built anything is visible.
        var dotnet = FindDotnet();
        if (dotnet is null)
            Assert.Skip("No dotnet SDK found on PATH, DOTNET_HOST_PATH or DOTNET_ROOT; the real clean-build test did not run.");

        IProcessLauncher launcher = new SystemProcessLauncher();
        var version = await launcher.RunAsync(dotnet, ["--version"], TimeSpan.FromSeconds(20), CancellationToken.None, _root);
        Assert.True(version.ExitCode == 0, DeveloperBuildRunner.FormatToolFailure("dotnet --version", version.ExitCode, version.TimedOut, version.StdOut, version.StdErr));
        var major = DeveloperScoring.ParseMajorVersion(version.StdOut);
        if (DeveloperCSharpPin.TargetFrameworkForSdk(major) is null)
            Assert.Skip($"dotnet SDK {version.StdOut.Trim()} is older than the pin can build; the real clean-build test did not run.");

        var temp = Path.Combine(_root, "real-sdk");
        var (project, _) = DeveloperCSharpPin.Materialize(temp, major!.Value);
        var restore = await launcher.RunAsync(dotnet, ["restore", project, "--ignore-failed-sources", "-v", "q"], TimeSpan.FromMinutes(3), CancellationToken.None, temp);
        Assert.True(restore.ExitCode == 0, DeveloperBuildRunner.FormatToolFailure("dotnet restore", restore.ExitCode, restore.TimedOut, restore.StdOut, restore.StdErr));

        DeveloperBuildRunner.CleanBuildOutputs(temp);
        Assert.True(File.Exists(Path.Combine(temp, "BenchApp", "obj", "project.assets.json")));

        var build = await launcher.RunAsync(dotnet, ["build", project, "-c", "Release", "--no-restore", "-v", "q"], TimeSpan.FromMinutes(3), CancellationToken.None, temp);
        Assert.True(build.ExitCode == 0, DeveloperBuildRunner.FormatToolFailure("cold dotnet build", build.ExitCode, build.TimedOut, build.StdOut, build.StdErr));
    }

    private static string? FindDotnet()
    {
        var name = OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet";
        // `dotnet test` sets DOTNET_HOST_PATH to the dotnet that launched the run, even when it is not on PATH.
        var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrWhiteSpace(host) && File.Exists(host)) return host;
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir.Trim().Trim('"'), name);
            if (File.Exists(candidate)) return candidate;
        }
        var home = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        if (string.IsNullOrWhiteSpace(home))
            home = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".dotnet");
        var fallback = Path.Combine(home, name);
        return File.Exists(fallback) ? fallback : null;
    }

    [Fact]
    public async Task AdminExport_IncludesTheBuildExitCode_AndWhyAnOldSdkIsHidden()
    {
        const string note = "Could not run: cold dotnet build failed (exit 1). error NETSDK1004: Assets file not found.";
        var dev = new DeveloperBuildResult(DeveloperLanguage.CSharp, DeveloperCSharpPin.PinId, "ABC", "9.0.200", 9,
            1.2, null, [], null, [], Note: note, ToolExitCode: 1);
        var run = new BenchmarkRun(BenchmarkPhase.Before, DateTimeOffset.Parse("2026-11-20T10:00:00Z"),
            new BenchmarkConditions(false, 40, "Balanced"),
            [new BenchmarkMeasurement(BenchmarkKind.DeveloperCSharp, [], note, DeveloperBuild: dev)]);
        var env = new FakeDevEnv { Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "6.0.428", 6)] };
        var store = new InMemoryBenchmarkStore();
        store.Save(new BenchmarkState(new BenchmarkSettings(), run));
        var svc = new BenchmarkService(new BenchmarkRunner(new DummyBenchProbes()), store, devRunner: new DeveloperBuildRunner(env), devEnv: env);
        await svc.RefreshDeveloperEnvironmentAsync();

        using var doc = JsonDocument.Parse(AgentExports.Benchmark(svc));
        var measurement = doc.RootElement.GetProperty("before").GetProperty("measurements")[0];
        Assert.Contains("exit 1", measurement.GetProperty("note").GetString());
        Assert.Contains("NETSDK1004", measurement.GetProperty("developerBuild").GetProperty("note").GetString());
        Assert.Equal(1, measurement.GetProperty("developerBuild").GetProperty("toolExitCode").GetInt32());
        Assert.Contains("6.0.428", doc.RootElement.GetProperty("developer").GetProperty("csharpUnavailableReason").GetString());
    }

    [Fact]
    public void DeveloperSetup_WarnsWhenCSharpSdkCannotBuildTheBenchmark_AndStaysQuietForSdk9()
    {
        var old = DeveloperSetupModule.Build(
            [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "6.0.428", 6)],
            40, null, new(true, false, true), new(false, 40, "Balanced"));
        Assert.Equal(DiagnosticStatus.Warning, old.Status);
        var card = Assert.Single(old.Cards, c => c.Id == "toolchains");
        Assert.Contains(".NET SDK 8 or newer", card.Meta);
        Assert.Contains("6.0.428", card.Meta);
        Assert.Contains("hidden", card.Meta);

        var current = DeveloperSetupModule.Build(
            [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "9.0.200", 9)],
            40, null, new(true, false, true), new(false, 40, "Balanced"));
        Assert.Equal(DiagnosticStatus.Ok, current.Status);
        Assert.DoesNotContain("hidden", Assert.Single(current.Cards, c => c.Id == "toolchains").Meta);
    }

    [Fact]
    public void ParseHyperfineTimes_ExtractsTimesArray()
    {
        var times = DeveloperBuildRunner.ParseHyperfineTimes("""{"results":[{"times":[3.1234,2.9876,3.05]}]}""");
        Assert.NotNull(times);
        Assert.Equal([3.123, 2.988, 3.05], times);
    }

    // ---- DeveloperSetup check module ----

    [Fact]
    public void DeveloperSetup_ReportsNoToolchainsCleanly_AndOffersBalancedPowerPlanFixOnPowerSaver()
    {
        var report = DeveloperSetupModule.Build(
            toolchains: [],
            freeSpaceGb: 6.5,
            defender: null,
            devDrive: new(true, false, true),
            conditions: new(false, 50, "Power saver"));

        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        var tcCard = Assert.Single(report.Cards, c => c.Id == "toolchains");
        Assert.Empty(tcCard.Rows);
        Assert.Contains("No developer toolchains found", tcCard.Headline);

        var ddCard = Assert.Single(report.Cards, c => c.Id == "devdrive");
        Assert.Contains("Dev Drive not used; the opt-in test can show how much it would help.", ddCard.Meta);

        var powerCard = Assert.Single(report.Cards, c => c.Id == "power");
        Assert.NotNull(powerCard.Actions);
        Assert.Contains(powerCard.Actions, a => a.Kind == RemediationKind.SetBalancedPowerPlan);
    }

    // ---- BenchmarkService / BenchmarkModels invariants ----

    [Fact]
    public async Task BenchmarkService_DeveloperCSharpIsOffByDefault_ZeroWeight_HiddenWhenAbsent_AndComparisonsRequireConsent()
    {
        var settings = new BenchmarkSettings();
        Assert.DoesNotContain(BenchmarkKind.DeveloperCSharp, settings.Enabled);
        Assert.Equal(0.0, Benchmarks.Info(BenchmarkKind.DeveloperCSharp).Weight);

        var env = new FakeDevEnv { Toolchains = [] };
        var devRunner = new DeveloperBuildRunner(env);
        var store = new InMemoryBenchmarkStore();
        var svc = new BenchmarkService(new BenchmarkRunner(new DummyBenchProbes()), store, devRunner: devRunner, devEnv: env);

        await svc.RefreshDeveloperEnvironmentAsync();
        Assert.False(svc.IsKindAvailable(BenchmarkKind.DeveloperCSharp));
        Assert.Null(await svc.RunDevDriveComparisonAsync(userConfirmed: false));
        Assert.Null(await svc.RunAntivirusComparisonAsync(userConfirmed: false));

        env.Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "10.0.404", 10)];
        await svc.RefreshDeveloperEnvironmentAsync();
        Assert.True(svc.IsKindAvailable(BenchmarkKind.DeveloperCSharp));
    }

    [Fact]
    public async Task BenchmarkService_ReportsHiddenKindsAsUnavailable_AndSavesAnEnableTheSameWayThePageDoes()
    {
        var env = new FakeDevEnv { Toolchains = [] };
        var store = new InMemoryBenchmarkStore();
        var svc = new BenchmarkService(new BenchmarkRunner(new DummyBenchProbes()), store, devEnv: env);
        await svc.RefreshDeveloperEnvironmentAsync();

        var hidden = svc.TestChoices().Single(t => t.Id == "DeveloperCSharp");
        Assert.False(hidden.Available);
        Assert.False(hidden.Enabled);
        Assert.Null(hidden.Control);
        Assert.Equal(BenchmarkTestRules.UnavailableReason, hidden.Reason);
        var speed = svc.TestChoices().Single(t => t.Id == "Speedometer");
        Assert.True(speed.Available);
        Assert.True(speed.Enabled);
        Assert.Equal("bench-enable-Speedometer", speed.Control);

        svc.UpdateSettings(svc.Settings with
        {
            Enabled = BenchmarkTestRules.WithEnabled(svc.Settings, BenchmarkKind.Speedometer, on: false, svc.IsKindAvailable(BenchmarkKind.Speedometer)),
        });
        Assert.DoesNotContain(BenchmarkKind.Speedometer, store.Load()!.Settings.Enabled);
        svc.UpdateSettings(svc.Settings with
        {
            Enabled = BenchmarkTestRules.WithEnabled(svc.Settings, BenchmarkKind.DeveloperCSharp, on: true, svc.IsKindAvailable(BenchmarkKind.DeveloperCSharp)),
        });
        Assert.DoesNotContain(BenchmarkKind.DeveloperCSharp, store.Load()!.Settings.Enabled);

        env.Toolchains = [new(DeveloperLanguage.CSharp, ".NET SDK (C#)", "dotnet", "10.0.404", 10)];
        await svc.RefreshDeveloperEnvironmentAsync();
        svc.UpdateSettings(svc.Settings with
        {
            Enabled = BenchmarkTestRules.WithEnabled(svc.Settings, BenchmarkKind.DeveloperCSharp, on: true, svc.IsKindAvailable(BenchmarkKind.DeveloperCSharp)),
        });
        Assert.Contains(BenchmarkKind.DeveloperCSharp, store.Load()!.Settings.Enabled);

        using var doc = JsonDocument.Parse(AgentExports.Benchmark(svc));
        var dev = doc.RootElement.GetProperty("tests").EnumerateArray().Single(t => t.GetProperty("id").GetString() == "DeveloperCSharp");
        Assert.True(dev.GetProperty("available").GetBoolean());
        Assert.True(dev.GetProperty("enabled").GetBoolean());
        Assert.Equal("bench-enable-DeveloperCSharp", dev.GetProperty("control").GetString());
        Assert.False(dev.TryGetProperty("reason", out _));
    }

    // ---- Fakes ----

    private static void SeedRestoredProject(string proj)
    {
        var dir = Path.GetDirectoryName(proj)!;
        var obj = Path.Combine(dir, "obj");
        var name = Path.GetFileName(proj);
        Directory.CreateDirectory(Path.Combine(obj, "Release"));
        File.WriteAllText(Path.Combine(obj, "project.assets.json"), "{}");
        File.WriteAllText(Path.Combine(obj, "project.nuget.cache"), "{}");
        File.WriteAllText(Path.Combine(obj, name + ".nuget.g.props"), "<Project />");
        File.WriteAllText(Path.Combine(obj, name + ".nuget.g.targets"), "<Project />");
        File.WriteAllText(Path.Combine(obj, name + ".nuget.dgspec.json"), "{}");
        File.WriteAllText(Path.Combine(obj, "AssemblyInfo.cs"), "// compiler");
        File.WriteAllText(Path.Combine(obj, "Release", "out.dll"), "dll");
        var bin = Path.Combine(dir, "bin");
        Directory.CreateDirectory(bin);
        File.WriteAllText(Path.Combine(bin, "out.dll"), "dll");
    }

    private sealed class FakeLauncher(Func<string, IReadOnlyList<string>, ProcessResult> run) : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(run(fileName, arguments));
        }
    }

    private sealed class RecordingLauncher : IProcessLauncher
    {
        public List<string?> Directories { get; } = [];

        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct = default) =>
            RunAsync(fileName, arguments, timeout, ct, null);

        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, string? workingDirectory)
        {
            ct.ThrowIfCancellationRequested();
            Directories.Add(workingDirectory);
            return Task.FromResult(new ProcessResult(0, "", ""));
        }
    }

    private sealed class FakeDevEnv : IDeveloperEnvironmentProbe
    {
        public IReadOnlyList<DetectedToolchain> Toolchains { get; set; } = [];
        public double? FreeGb { get; set; } = 100;
        public DevDriveVolumeStatus DevDriveStatus { get; set; } = new(true, false, true);
        public DefenderProbe.Status? Defender { get; set; }
        public BenchmarkConditions Conditions { get; set; } = new(false, 45, "Balanced");
        public (int Build, int Ubr) WindowsBuild { get; set; } = (26100, 1000);
        public bool AgentConnected { get; set; }

        public Task<IReadOnlyList<DetectedToolchain>> DetectToolchainsAsync(CancellationToken ct = default) => Task.FromResult(Toolchains);
        public string? FindHyperfine() => null;
        public double? ReadTempVolumeFreeGb() => FreeGb;
        public Task<DevDriveVolumeStatus> QueryDevDriveAsync(string? driveLetter = null, CancellationToken ct = default) => Task.FromResult(DevDriveStatus);
        public Task<DefenderProbe.Status?> ReadDefenderAsync(CancellationToken ct = default) => Task.FromResult(Defender);
        public BenchmarkConditions ReadConditions() => Conditions;
        public (string? CpuName, int CoreCount) ReadCpuInfo() => ("AMD Ryzen 7 7800X3D", 16);
        public (int Build, int Ubr) ReadWindowsBuild() => WindowsBuild;
        public string? ReadCurrentUserSid() => "S-1-5-21-100-200-300-1001";
        public bool IsAgentConnected => AgentConnected;
    }

    private sealed class FakeDevTweaks : IMachineTweaks
    {
        public List<string> TempAdded { get; } = [];
        public List<string> TempRemoved { get; } = [];
        public List<string> DevDrivesRemoved { get; } = [];
        public DevDriveMountResult MountResult { get; set; } = new(false, Error: "not configured");

        public void WriteDword(RegistrySetting setting, int value) { }
        public void DeleteDword(RegistrySetting setting) { }
        public bool DeleteKeyIfEmpty(string key) => true;
        public void AddExtensionBlock(BrowserKind browser, string valueName, string extensionId) { }
        public void RemoveExtensionBlock(BrowserKind browser, string valueName, string extensionId) { }
        public Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct) => Task.FromResult(new ActionOutcome(true, "ok"));
        public Task<ActionOutcome> RestorePageFileAsync(string settings, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, "ok"));
        public Task<string?> ReadDefenderAsync(CancellationToken ct) => Task.FromResult<string?>(null);
        public Task<(bool Ok, string? Output)> AddDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct) => Task.FromResult<(bool, string?)>((true, "{}"));
        public Task<bool> RemoveDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct) => Task.FromResult(true);

        public Task<(bool Ok, string? Output)> AddTempBuildDefenderExclusionAsync(string folder, CancellationToken ct)
        {
            TempAdded.Add(folder);
            return Task.FromResult<(bool, string?)>((true, "{}"));
        }

        public Task<bool> RemoveTempBuildDefenderExclusionAsync(string folder, CancellationToken ct)
        {
            TempRemoved.Add(folder);
            return Task.FromResult(true);
        }

        public Task<DevDriveMountResult> CreateTempDevDriveAsync(int sizeGb, string? grantUserSid, CancellationToken ct) =>
            Task.FromResult(MountResult);

        public Task<bool> RemoveTempDevDriveAsync(string vhdxPath, CancellationToken ct)
        {
            DevDrivesRemoved.Add(vhdxPath);
            return Task.FromResult(true);
        }
    }

    private sealed class InMemoryBenchmarkStore : IBenchmarkStore
    {
        private BenchmarkState? _state;
        public BenchmarkState? Load() => _state;
        public void Save(BenchmarkState state) => _state = state;
    }

    private sealed class DummyBenchProbes : IBenchmarkProbes
    {
        public BenchmarkConditions ReadConditions() => new(false, 45, "Balanced");
        public Task<IdleSample?> SampleIdleAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<IdleSample?>(new(1, 0));
        public Task<double?> StartProgramAsync(BuiltInProgram program, CancellationToken ct) => Task.FromResult<double?>(100);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<double?>(1000);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);
    }
}
