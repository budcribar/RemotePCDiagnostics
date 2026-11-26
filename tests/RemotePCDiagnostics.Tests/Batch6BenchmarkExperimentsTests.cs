using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class Batch6BenchmarkExperimentsTests
{
    private sealed class MemBenchStore : IBenchmarkStore
    {
        public BenchmarkState? State;
        public BenchmarkState? Load() => State is null ? null : BenchmarkState.FromJson(State.ToJson());
        public void Save(BenchmarkState s) => State = s;
    }

    private sealed class MinimalProbes : IBenchmarkProbes
    {
        public BenchmarkConditions ReadConditions() => new(false, 48, "Balanced", "Best performance");
        public Task<IdleSample?> SampleIdleAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<IdleSample?>(new(2.0, 10));
        public Task<double?> StartProgramAsync(BuiltInProgram p, CancellationToken ct) => Task.FromResult<double?>(100);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<double?>(8000);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);
    }

    private sealed class FakeJournal : IChangeJournal
    {
        public List<ChangeRecord> Records { get; } = [];
        public IReadOnlyList<ChangeRecord> All => Records;
        public event Action? Changed;
        public void Add(ChangeRecord record) { Records.Add(record); Changed?.Invoke(); }
        public void Remove(Guid id) { Records.RemoveAll(r => r.Id == id); Changed?.Invoke(); }
        public void RemoveLatest(ChangeKind kind, string target)
        {
            var idx = Records.FindLastIndex(r => r.Kind == kind && string.Equals(r.Target, target, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return;
            Records.RemoveAt(idx);
            Changed?.Invoke();
        }
        public void Clear() { Records.Clear(); Changed?.Invoke(); }
    }

    private const string TestDevDriveFolder = @"C:\ProgramData\RemotePCDiagnostics\devdrive";

    private sealed class FakeMachineTweaks : IMachineTweaks
    {
        public DevDriveMountResult NextMount = new(true,
            $@"{TestDevDriveFolder}\{DevDriveRules.PersistentVhdxPrefix}1234567890ab.vhdx",
            "E", @"E:\");
        public List<string> RemovedPaths { get; } = [];

        public void WriteDword(RegistrySetting setting, int value) { }
        public void DeleteDword(RegistrySetting setting) { }
        public bool DeleteKeyIfEmpty(string key) => true;
        public void AddExtensionBlock(BrowserKind browser, string valueName, string extensionId) { }
        public void RemoveExtensionBlock(BrowserKind browser, string valueName, string extensionId) { }
        public Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct) => Task.FromResult(new ActionOutcome(true, "ok"));
        public Task<ActionOutcome> RestorePageFileAsync(string settings, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, "ok"));
        public Task<string?> ReadDefenderAsync(CancellationToken ct) => Task.FromResult<string?>(null);
        public Task<(bool Ok, string? Output)> AddDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct) => Task.FromResult<(bool, string?)>((true, null));
        public Task<bool> RemoveDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct) => Task.FromResult(true);

        public Task<DevDriveMountResult> CreatePersistentDevDriveAsync(int sizeGb, string? grantUserSid, CancellationToken ct) =>
            Task.FromResult(NextMount);

        public Task<bool> RemovePersistentDevDriveAsync(string vhdxPath, CancellationToken ct)
        {
            RemovedPaths.Add(vhdxPath);
            return Task.FromResult(true);
        }
    }

    [Fact]
    public void PersistentDevDrive_rules_accept_valid_path_and_reject_temp_or_arbitrary_paths()
    {
        var folder = TestDevDriveFolder;
        var valid = $@"{folder}\{DevDriveRules.PersistentVhdxPrefix}abcdef123456.vhdx";
        var temp = $@"C:\ProgramData\RemotePCDiagnostics\devdrive-temp\{DevDriveRules.VhdxPrefix}abcdef123456.vhdx";
        var arbitrary = @"C:\Users\alice\my.vhdx";

        Assert.True(DevDriveRules.IsRpcdPersistentDevDriveVhdx(valid, folder));
        Assert.False(DevDriveRules.IsRpcdPersistentDevDriveVhdx(temp, folder));
        Assert.False(DevDriveRules.IsRpcdPersistentDevDriveVhdx(arbitrary, folder));

        Assert.Null(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.PersistentDevDriveCreate, Number: 50)));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.PersistentDevDriveCreate, Number: 10)));
        Assert.NotNull(MachineTweakRules.Refusal(new AdminPipeTweak(AdminPipeTweak.PersistentDevDriveRemove, Target: arbitrary)));
    }

    [Fact]
    public async Task CreatePersistentDevDrive_executes_journals_and_undoes_cleanly()
    {
        var journal = new FakeJournal();
        var tweaks = new FakeMachineTweaks();
        var commands = new SystemCommandRunner(new SystemProcessLauncher());
        var svc = new RemediationService(commands, new SessionContext(SessionMode.Local), journal: journal, machineTweaks: tweaks);

        var res = await svc.ExecuteAsync(new AreaAction(RemediationKind.CreatePersistentDevDrive, "Create Dev Drive", "50", "Persistent Dev Drive"), CancellationToken.None);

        Assert.True(res.Success);
        Assert.Equal(@"E:\", res.CreatedDriveRoot);
        var rec = Assert.Single(journal.Records);
        Assert.Equal(ChangeKind.PersistentDevDrive, rec.Kind);
        Assert.Equal(tweaks.NextMount.VhdxPath, rec.Target);
        Assert.Equal(@"E:\", rec.Previous);

        var undo = new UndoService(journal, commands, machineTweaks: tweaks, persistentDevDriveFolder: TestDevDriveFolder);
        var undoRes = await undo.UndoAllAsync("local", CancellationToken.None);
        Assert.Single(undoRes.Items);
        Assert.True(undoRes.Items[0].Success);
        Assert.Equal(tweaks.NextMount.VhdxPath, Assert.Single(tweaks.RemovedPaths));
        Assert.Empty(journal.Records);
    }

    [Fact]
    public void BenchmarkImprovements_build_goal_adapts_to_dev_environment_and_existing_dev_drive()
    {
        // Hidden when no dev environment is present.
        Assert.Empty(BenchmarkImprovements.ForGoal(BenchmarkGoals.Build, new BenchmarkImprovementContext(HasDevEnvironment: false)));

        var nugetSpec = DevDrivePackageCaches.FindWritable("NUGET_PACKAGES")!;
        var nugetNotOnDev = new PackageCacheInfo(nugetSpec, @"C:\Users\dev\.nuget\packages", false, OnDevDrive: false, SizeBytes: 1024);

        // No Dev Drive yet: CreatePersistentDevDrive is checkable, NuGet move requires Dev Drive with placeholder.
        var noDrive = BenchmarkImprovements.ForGoal(BenchmarkGoals.Build, new BenchmarkImprovementContext(
            HasDevEnvironment: true,
            ExistingDevDriveRoot: null,
            PackageCaches: [nugetNotOnDev],
            AcMaxProcessorStatePercent: 80,
            StorageSenseEnabled: false));

        var create = Assert.Single(noDrive, i => i.Id == BenchmarkImprovements.CreateDevDriveId);
        Assert.False(create.AlreadyApplied);
        var nuget = Assert.Single(noDrive, i => i.Id == "devcache:NUGET_PACKAGES");
        Assert.True(nuget.RequiresDevDrive);
        Assert.Contains(BenchmarkImprovements.NewDevDriveToken, nuget.Action.Target);
        Assert.Contains(noDrive, i => i.Id == "power:ac-max-cpu");
        Assert.Contains(noDrive, i => i.Id == "disk:storage-sense");

        // Existing Dev Drive D:\: Create is omitted completely, NuGet targets D:\ directly without RequiresDevDrive.
        var withDrive = BenchmarkImprovements.ForGoal(BenchmarkGoals.Build, new BenchmarkImprovementContext(
            HasDevEnvironment: true,
            ExistingDevDriveRoot: @"D:\",
            PackageCaches: [nugetNotOnDev]));

        Assert.DoesNotContain(withDrive, i => i.Id == BenchmarkImprovements.CreateDevDriveId);
        var nugetDirect = Assert.Single(withDrive, i => i.Id == "devcache:NUGET_PACKAGES");
        Assert.False(nugetDirect.RequiresDevDrive);
        Assert.Equal(@"NUGET_PACKAGES|D:\", nugetDirect.Action.Target);
    }

    [Fact]
    public async Task RunExperimentAsync_runs_Before_then_ordered_improvements_with_DevDrive_chaining_then_After()
    {
        var store = new MemBenchStore
        {
            State = new BenchmarkState(new BenchmarkSettings
            {
                Goal = BenchmarkGoals.Build,
                Enabled = [BenchmarkKind.DiskLatency],
                Runs = 1,
                IdleSample = TimeSpan.Zero,
                CpuSingleRun = TimeSpan.FromMilliseconds(50),
                CpuMultiRun = TimeSpan.FromMilliseconds(50),
                DiskRun = TimeSpan.Zero,
                ResourceSampleInterval = TimeSpan.Zero,
            }),
        };
        var svc = new BenchmarkService(new BenchmarkRunner(new MinimalProbes(), resolve: (_, _) => Task.CompletedTask), store);

        var nugetSpec = DevDrivePackageCaches.FindWritable("NUGET_PACKAGES")!;
        var nugetInfo = new PackageCacheInfo(nugetSpec, @"C:\Users\dev\.nuget\packages", false, OnDevDrive: false, SizeBytes: 1024);
        var all = BenchmarkImprovements.ForGoal(BenchmarkGoals.Build, new BenchmarkImprovementContext(
            HasDevEnvironment: true,
            ExistingDevDriveRoot: null,
            PackageCaches: [nugetInfo]));

        // Pass NuGet BEFORE CreateDevDrive to verify OrderForExecution puts CreatePersistentDevDrive first!
        var selected = new[]
        {
            all.Single(i => i.Id == "devcache:NUGET_PACKAGES"),
            all.Single(i => i.Id == BenchmarkImprovements.CreateDevDriveId),
        };

        var executed = new List<AreaAction>();
        var result = await svc.RunExperimentAsync(selected, (action, _) =>
        {
            executed.Add(action);
            if (action.Kind == RemediationKind.CreatePersistentDevDrive)
                return Task.FromResult(new RemediationResult(true, "Mounted E:\\", CreatedDriveRoot: @"E:\"));
            return Task.FromResult(new RemediationResult(true, $"Applied {action.Target}"));
        });

        Assert.True(result.Completed);
        Assert.NotNull(result.Before);
        Assert.NotNull(result.After);
        Assert.Equal(BenchmarkGoals.Build, result.Before!.Goal);
        Assert.Equal(BenchmarkGoals.Build, result.After!.Goal);

        Assert.Equal(2, executed.Count);
        Assert.Equal(RemediationKind.CreatePersistentDevDrive, executed[0].Kind);
        Assert.Equal(RemediationKind.MovePackageCacheToDevDrive, executed[1].Kind);
        Assert.Equal(@"NUGET_PACKAGES|E:\", executed[1].Target);
        Assert.All(result.Outcomes, o => Assert.True(o.Succeeded));
    }

    [Fact]
    public async Task RunExperimentAsync_skips_dependent_cache_move_when_DevDrive_creation_fails()
    {
        var store = new MemBenchStore
        {
            State = new BenchmarkState(new BenchmarkSettings
            {
                Goal = BenchmarkGoals.Build,
                Enabled = [BenchmarkKind.DiskLatency],
                Runs = 1,
                DiskRun = TimeSpan.Zero,
            }),
        };
        var svc = new BenchmarkService(new BenchmarkRunner(new MinimalProbes(), resolve: (_, _) => Task.CompletedTask), store);

        var nugetSpec = DevDrivePackageCaches.FindWritable("NUGET_PACKAGES")!;
        var all = BenchmarkImprovements.ForGoal(BenchmarkGoals.Build, new BenchmarkImprovementContext(
            HasDevEnvironment: true,
            ExistingDevDriveRoot: null,
            PackageCaches: [new PackageCacheInfo(nugetSpec, @"C:\Users\dev\.nuget\packages", false, false, 1024)]));

        var selected = new[]
        {
            all.Single(i => i.Id == BenchmarkImprovements.CreateDevDriveId),
            all.Single(i => i.Id == "devcache:NUGET_PACKAGES"),
        };

        var result = await svc.RunExperimentAsync(selected, (action, _) =>
            Task.FromResult(new RemediationResult(false, "Not enough free disk space.")));

        Assert.False(result.Completed);
        Assert.Null(result.After);
        Assert.Equal(2, result.Outcomes.Count);
        Assert.False(result.Outcomes[0].Succeeded);
        Assert.False(result.Outcomes[0].Skipped);
        Assert.False(result.Outcomes[1].Succeeded);
        Assert.True(result.Outcomes[1].Skipped);
        Assert.Contains("Dev Drive failed", result.Outcomes[1].Message);
    }

    [Fact]
    public void AgentDotNetSdkInstaller_parses_official_metadata_and_blocks_untrusted_hosts()
    {
        const string sampleJson = """
        {
          "releases": [
            {
              "sdks": [
                {
                  "version": "10.0.404",
                  "files": [
                    { "name": "dotnet-sdk-win-x64.exe", "rid": "win-x64", "url": "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-win-x64.exe", "hash": "AAA" },
                    { "name": "dotnet-sdk-win-x64.zip", "rid": "win-x64", "url": "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-win-x64.zip", "hash": "DEADBEEF" },
                    { "name": "dotnet-sdk-win-arm64.zip", "rid": "win-arm64", "url": "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.404/dotnet-sdk-10.0.404-win-arm64.zip", "hash": "CAFEBABE" }
                  ]
                }
              ]
            }
          ]
        }
        """;

        var x64 = AgentDotNetSdkInstaller.TryParseReleaseZipFromMetadata(sampleJson, "win-x64");
        Assert.NotNull(x64);
        Assert.Equal("10.0.404", x64!.SdkVersion);
        Assert.Equal("DEADBEEF", x64.Sha512);

        var arm64 = AgentDotNetSdkInstaller.TryParseReleaseZipFromMetadata(sampleJson, "win-arm64");
        Assert.NotNull(arm64);
        Assert.Equal("CAFEBABE", arm64!.Sha512);

        const string untrustedJson = """
        { "releases": [ { "sdk": { "version": "10.0.404", "files": [ { "name": "sdk.zip", "rid": "win-x64", "url": "https://evil.example.com/sdk.zip", "hash": "1234" } ] } } ] }
        """;
        Assert.Null(AgentDotNetSdkInstaller.TryParseReleaseZipFromMetadata(untrustedJson, "win-x64"));

        // AgentScripts allowlists only 10 and 11.
        var plan10 = AgentScripts.Plan(AgentScripts.Of(AgentScripts.InstallDotNetSdk, "10"), null, out var refusal10);
        Assert.Null(refusal10);
        Assert.Equal(new InstallDotNetSdkAction(10), plan10!.Native);
        Assert.Null(AgentScripts.Plan(AgentScripts.Of(AgentScripts.InstallDotNetSdk, "8"), null, out _));
    }

    [Fact]
    public void DeveloperBuildResult_logs_toolchain_version_and_Spread_trims_single_outlier_for_five_runs()
    {
        var csharp = new DeveloperBuildResult(DeveloperLanguage.CSharp, "pin", "sha", "10.0.404", 10, 0.7, 2.5, [2.5], 2.2, [2.1, 2.2, 2.2, 2.3, 3.4]);
        Assert.StartsWith(".NET SDK 10.0.404 · ", csharp.FormatDetail());

        var rust = new DeveloperBuildResult(DeveloperLanguage.Rust, "pin", "sha", "1.88.0", 1, 0.5, 4.0, [4.0], 3.0, [3.0]);
        Assert.StartsWith("Rust 1.88.0 · ", rust.FormatDetail());

        // 5 samples with one big spike (3.4): trimmed spread uses [2.2 .. 2.3] / 2.2 ≈ 4.5% instead of 59%!
        var m = new BenchmarkMeasurement(BenchmarkKind.DeveloperCSharp, [2.1, 2.2, 2.2, 2.3, 3.4]);
        Assert.True(m.Spread < 0.10, $"Expected trimmed spread < 10%, got {m.Spread:P1}");
    }

    private sealed class SdkCapturingProbes : IBenchmarkProbes
    {
        public List<int?> SeenSdkMajors { get; } = [];
        public List<string?> SeenBuildWorkRoots { get; } = [];
        public List<string?> SeenCustomSolutions { get; } = [];
        public BenchmarkConditions ReadConditions() => new(false, 48, "Balanced", "Best performance");
        public Task<IdleSample?> SampleIdleAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<IdleSample?>(new(2.0, 10));
        public Task<double?> StartProgramAsync(BuiltInProgram p, CancellationToken ct) => Task.FromResult<double?>(100);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<double?>(8000);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);
        public Task<DeveloperBuildResult?> RunDeveloperCSharpAsync(
            bool includeAntivirusComparison, IProgress<string>? progress, CancellationToken ct, int? targetDotNetSdkMajor = null, string? buildWorkRoot = null, string? customSolutionPath = null)
        {
            SeenSdkMajors.Add(targetDotNetSdkMajor);
            SeenBuildWorkRoots.Add(buildWorkRoot);
            SeenCustomSolutions.Add(customSolutionPath);
            var secs = targetDotNetSdkMajor is null && buildWorkRoot is null ? 5.0 : 4.2;
            var major = targetDotNetSdkMajor ?? 10;
            return Task.FromResult<DeveloperBuildResult?>(new DeveloperBuildResult(
                DeveloperLanguage.CSharp, "csharp-v2", "sha", $"{major}.0.100", major, 0.5, secs, [secs], secs, [secs]));
        }
    }

    [Fact]
    public async Task DotNetSdk_choice_auto_installs_when_missing_and_pins_after_pass()
    {
        Assert.True(RemediationService.IsAllowedDotNetSdkPackage("Microsoft.DotNet.SDK.10"));
        Assert.True(RemediationService.IsAllowedDotNetSdkPackage("Microsoft.DotNet.SDK.11"));
        Assert.False(RemediationService.IsAllowedDotNetSdkPackage("Microsoft.DotNet.SDK.8"));
        Assert.False(RemediationService.IsAllowedDotNetSdkPackage("Some.Random.Package"));

        var parsed = DeveloperToolchainDetector.ParseInstalledDotNetSdkMajors(
            "9.0.304 [C:\\Program Files\\dotnet\\sdk]\n10.0.404 [C:\\Program Files\\dotnet\\sdk]\n11.0.100-preview.1 [C:\\Program Files\\dotnet\\sdk]\n");
        Assert.Equal(new[] { 9, 10, 11 }, parsed);

        // .NET 10/11 are handled by the mutually exclusive SDK selector, not as checkboxes in ForGoal.
        var buildList = BenchmarkImprovements.ForGoal(BenchmarkGoals.Build, new BenchmarkImprovementContext(
            HasDevEnvironment: true, DotNetSdkMajorVersion: 9));
        Assert.DoesNotContain(buildList, i => i.Id == BenchmarkImprovements.InstallDotNet10SdkId);
        Assert.DoesNotContain(buildList, i => i.Id == BenchmarkImprovements.InstallDotNet11SdkId);

        // Missing .NET 11 -> auto-installs via InstallDotNetSdk and pins After pass to 11.
        var probes = new SdkCapturingProbes();
        var store = new MemBenchStore
        {
            State = new BenchmarkState(new BenchmarkSettings
            {
                Goal = BenchmarkGoals.Build,
                Enabled = [BenchmarkKind.DeveloperCSharp],
                Runs = 1,
                DiskRun = TimeSpan.Zero,
            }),
        };
        var svc = new BenchmarkService(new BenchmarkRunner(probes, resolve: (_, _) => Task.CompletedTask), store);
        var executed = new List<AreaAction>();
        var resInstall = await svc.RunExperimentAsync(
            [],
            (action, _) =>
            {
                executed.Add(action);
                return Task.FromResult(new RemediationResult(true, "Installed .NET 11 SDK"));
            },
            targetDotNetSdkMajor: 11,
            installedDotNetSdkMajorsOverride: [10]);

        Assert.True(resInstall.Completed);
        var installAction = Assert.Single(executed);
        Assert.Equal(RemediationKind.InstallDotNetSdk, installAction.Kind);
        Assert.Equal("Microsoft.DotNet.SDK.11", installAction.Target);
        Assert.Equal(new int?[] { null, 11 }, probes.SeenSdkMajors);

        // Already installed .NET 10 -> skips installation and pins After pass to 10.
        probes.SeenSdkMajors.Clear();
        executed.Clear();
        var resAlready = await svc.RunExperimentAsync(
            [],
            (action, _) =>
            {
                executed.Add(action);
                return Task.FromResult(new RemediationResult(true, "Should not run"));
            },
            targetDotNetSdkMajor: 10,
            installedDotNetSdkMajorsOverride: [10, 11]);

        Assert.True(resAlready.Completed);
        Assert.Empty(executed);
        Assert.Single(resAlready.Outcomes);
        Assert.True(resAlready.Outcomes[0].Succeeded);
        Assert.Contains("Already installed", resAlready.Outcomes[0].Message);
        Assert.Equal(new int?[] { null, 10 }, probes.SeenSdkMajors);

        // Using an existing Dev Drive D:\ runs Before on standard drive and After on D:\ without creating a drive.
        probes.SeenSdkMajors.Clear();
        probes.SeenBuildWorkRoots.Clear();
        executed.Clear();
        var resDevDrive = await svc.RunExperimentAsync(
            [],
            (action, _) =>
            {
                executed.Add(action);
                return Task.FromResult(new RemediationResult(true, "Should not create drive"));
            },
            afterBuildWorkRoot: @"D:\");

        Assert.True(resDevDrive.Completed);
        Assert.Empty(executed);
        Assert.Equal(new string?[] { null, @"D:\" }, probes.SeenBuildWorkRoots);
        var outcome = Assert.Single(resDevDrive.Outcomes);
        Assert.True(outcome.Succeeded);
        Assert.Contains(@"D:\", outcome.Message);
    }

    [Fact]
    public async Task SavedBaselines_and_RunComparisonAsync_lifecycle_works()
    {
        var probes = new SdkCapturingProbes();
        var store = new MemBenchStore
        {
            State = new BenchmarkState(new BenchmarkSettings
            {
                Goal = BenchmarkGoals.Build,
                Enabled = [BenchmarkKind.DeveloperCSharp],
                Runs = 1,
                DiskRun = TimeSpan.Zero,
            }),
        };
        var svc = new BenchmarkService(new BenchmarkRunner(probes, resolve: (_, _) => Task.CompletedTask), store);

        // 1. Capture baseline -> unsaved (ActiveBaseline is null)
        var baseRun = await svc.RunAsync(BenchmarkPhase.Before);
        Assert.NotNull(baseRun);
        Assert.Null(svc.ActiveBaseline);
        Assert.Empty(svc.SavedBaselines);

        // 2. Save baseline with custom name
        var saved = svc.SaveCurrentBaseline("Stock C:\\ · .NET 10");
        Assert.NotNull(saved);
        Assert.Equal("Stock C:\\ · .NET 10", saved!.Name);
        Assert.Single(svc.SavedBaselines);
        Assert.Equal(saved.Id, svc.ActiveBaselineId);

        // 3. RunComparisonAsync runs ONLY After (never re-runs Before!) against saved baseline and forwards custom solution path
        probes.SeenBuildWorkRoots.Clear();
        probes.SeenCustomSolutions.Clear();
        var cmp = await svc.RunComparisonAsync([], afterBuildWorkRoot: @"D:\", afterCustomSolutionPath: @"C:\src\MyApp\MyApp.sln");
        Assert.True(cmp.Completed);
        Assert.NotNull(svc.After);
        Assert.Equal(new string?[] { @"D:\" }, probes.SeenBuildWorkRoots);
        Assert.Equal(new string?[] { @"C:\src\MyApp\MyApp.sln" }, probes.SeenCustomSolutions);

        // 4. Promote After to a new saved baseline
        var promoted = svc.SaveAfterAsBaseline("Dev Drive D:\\ · .NET 10");
        Assert.NotNull(promoted);
        Assert.Equal(2, svc.SavedBaselines.Count);
        Assert.Null(svc.After);
        Assert.Equal(promoted!.Id, svc.ActiveBaselineId);

        // 5. Switch back to the first saved baseline & delete the promoted one
        Assert.True(svc.LoadSavedBaseline(saved.Id));
        Assert.Equal(saved.Id, svc.ActiveBaselineId);
        Assert.True(svc.DeleteSavedBaseline(promoted.Id));
        Assert.Single(svc.SavedBaselines);

        // 6. Clear preserves SavedBaselines
        svc.Clear();
        Assert.Null(svc.Before);
        Assert.Single(svc.SavedBaselines);
    }
}
