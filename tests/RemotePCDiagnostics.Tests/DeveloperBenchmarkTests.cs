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
            _ => true, _ => true);

        Assert.Null(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.DefenderTempAdd, Target: @"C:\Users\alice\AppData\Local\Temp\rpcd-devbench-0123456789abcdef"), paths));
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

    // ---- Fakes ----

    private sealed class FakeLauncher(Func<string, IReadOnlyList<string>, ProcessResult> run) : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(run(fileName, arguments));
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
