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

        Assert.True(result.Completed);
        Assert.Equal(2, result.Outcomes.Count);
        Assert.False(result.Outcomes[0].Succeeded);
        Assert.False(result.Outcomes[0].Skipped);
        Assert.False(result.Outcomes[1].Succeeded);
        Assert.True(result.Outcomes[1].Skipped);
        Assert.Contains("Dev Drive failed", result.Outcomes[1].Message);
    }

    private sealed class SdkCapturingProbes : IBenchmarkProbes
    {
        public List<int?> SeenSdkMajors { get; } = [];
        public BenchmarkConditions ReadConditions() => new(false, 48, "Balanced", "Best performance");
        public Task<IdleSample?> SampleIdleAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<IdleSample?>(new(2.0, 10));
        public Task<double?> StartProgramAsync(BuiltInProgram p, CancellationToken ct) => Task.FromResult<double?>(100);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<double?>(8000);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);
        public Task<DeveloperBuildResult?> RunDeveloperCSharpAsync(
            bool includeAntivirusComparison, IProgress<string>? progress, CancellationToken ct, int? targetDotNetSdkMajor = null)
        {
            SeenSdkMajors.Add(targetDotNetSdkMajor);
            var secs = targetDotNetSdkMajor is null ? 5.0 : 4.2;
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
    }
}
