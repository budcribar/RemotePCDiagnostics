using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Checks;

namespace RemotePCDiagnostics.Tests;

public class Batch5GoalsAndProfilesTests
{
    private static readonly string[] AllCheckIds =
    [
        ModuleSlugs.DeveloperSetup,
        ModuleSlugs.Osquery,
        ModuleSlugs.DriveHealth,
        ModuleSlugs.BatteryPower,
        ModuleSlugs.DeviceDrivers,
        ModuleSlugs.Crashes,
        ModuleSlugs.Network,
        ModuleSlugs.WindowsMaintenance,
        ModuleSlugs.Services,
        ModuleSlugs.SecurityEssentials,
        ModuleSlugs.ResourceHogs,
    ];

    [Fact]
    public void CheckProfiles_are_additive_union_across_multiple_selected_profiles()
    {
        var gamerOnly = CheckProfiles.ResolveEnabledCheckIds([CheckProfiles.Gamer], AllCheckIds);
        var devOnly = CheckProfiles.ResolveEnabledCheckIds([CheckProfiles.Developer], AllCheckIds);
        var gamerAndDev = CheckProfiles.ResolveEnabledCheckIds([CheckProfiles.Gamer, CheckProfiles.Developer], AllCheckIds);

        Assert.Contains(ModuleSlugs.BatteryPower, gamerOnly);
        Assert.Contains(ModuleSlugs.DeviceDrivers, gamerOnly);
        Assert.Contains(ModuleSlugs.Crashes, gamerOnly);
        Assert.Contains(ModuleSlugs.Network, gamerOnly);
        Assert.DoesNotContain(ModuleSlugs.DeveloperSetup, gamerOnly);

        Assert.Contains(ModuleSlugs.DeveloperSetup, devOnly);
        Assert.Contains(ModuleSlugs.Osquery, devOnly);
        Assert.Contains(ModuleSlugs.DriveHealth, devOnly);

        // Union contains every check from both Gamer and Developer.
        foreach (var id in gamerOnly) Assert.Contains(id, gamerAndDev);
        foreach (var id in devOnly) Assert.Contains(id, gamerAndDev);
        Assert.Equal(gamerOnly.Union(devOnly, StringComparer.OrdinalIgnoreCase).Count(), gamerAndDev.Count);
    }

    [Fact]
    public void CheckProfiles_intersects_with_available_checks_and_ignores_unknown_profiles()
    {
        var limitedAvailable = new[] { ModuleSlugs.Network, ModuleSlugs.WindowsMaintenance };
        var resolved = CheckProfiles.ResolveEnabledCheckIds([CheckProfiles.Office, "nonexistent-profile"], limitedAvailable);

        Assert.Equal(2, resolved.Count);
        Assert.Contains(ModuleSlugs.Network, resolved);
        Assert.Contains(ModuleSlugs.WindowsMaintenance, resolved);
        Assert.DoesNotContain(ModuleSlugs.Services, resolved);
    }

    [Fact]
    public void BenchmarkGoals_hides_build_goal_when_no_dev_environment_is_available()
    {
        var noDevAvailable = Benchmarks.DefaultEnabled;
        var withDevAvailable = Benchmarks.DefaultEnabled.Append(BenchmarkKind.DeveloperCSharp).ToList();

        Assert.False(BenchmarkGoals.IsGoalAvailable(BenchmarkGoals.Build, noDevAvailable));
        Assert.Empty(BenchmarkGoals.KindsFor(BenchmarkGoals.Build, noDevAvailable));

        Assert.True(BenchmarkGoals.IsGoalAvailable(BenchmarkGoals.Build, withDevAvailable));
        var buildKinds = BenchmarkGoals.KindsFor(BenchmarkGoals.Build, withDevAvailable);
        Assert.Equal([BenchmarkKind.DiskLatency, BenchmarkKind.DeveloperCSharp], buildKinds);

        Assert.True(BenchmarkGoals.IsGoalAvailable(BenchmarkGoals.Browsing, noDevAvailable));
        Assert.Equal([BenchmarkKind.DnsLookup, BenchmarkKind.Speedometer], BenchmarkGoals.KindsFor(BenchmarkGoals.Browsing, noDevAvailable));

        Assert.True(BenchmarkGoals.IsGoalAvailable(BenchmarkGoals.TuneUp, noDevAvailable));
        Assert.Equal(Benchmarks.DefaultEnabled, BenchmarkGoals.KindsFor(BenchmarkGoals.TuneUp, noDevAvailable));
    }

    private sealed class MinimalProbes : IBenchmarkProbes
    {
        public BenchmarkConditions ReadConditions() => new(false, 48, "Balanced", "Best performance");
        public Task<IdleSample?> SampleIdleAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<IdleSample?>(new(2.0, 10));
        public Task<double?> StartProgramAsync(BuiltInProgram p, CancellationToken ct) => Task.FromResult<double?>(100);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<double?>(8000);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);
    }

    [Fact]
    public async Task Changing_presets_after_a_run_does_not_alter_completed_run_goal_or_upload()
    {
        var browsingSettings = new BenchmarkSettings
        {
            Goal = BenchmarkGoals.Browsing,
            Enabled = [BenchmarkKind.DnsLookup],
            Runs = 1,
            IdleSample = TimeSpan.Zero,
            CpuSingleRun = TimeSpan.FromMilliseconds(50),
            CpuMultiRun = TimeSpan.FromMilliseconds(50),
            DiskRun = TimeSpan.Zero,
            ResourceSampleInterval = TimeSpan.Zero,
        };

        var runner = new BenchmarkRunner(
            new MinimalProbes(),
            resolve: (_, _) => Task.CompletedTask);
        var completedRun = await runner.RunAsync(BenchmarkPhase.Before, browsingSettings, null, null, default);

        Assert.True(completedRun.Completed);
        Assert.Equal(BenchmarkGoals.Browsing, completedRun.Goal);
        Assert.Equal([BenchmarkKind.DnsLookup], completedRun.EnabledKinds);

        // Simulate user switching presets to Full tune-up before uploading or restarting.
        var tuneUpSettings = browsingSettings with
        {
            Goal = BenchmarkGoals.TuneUp,
            Enabled = [.. Benchmarks.DefaultEnabled],
        };
        var state = new BenchmarkState(tuneUpSettings, Before: completedRun);

        // Round-trip through JSON persistence (simulating restart before upload).
        var reloaded = BenchmarkState.FromJson(state.ToJson());
        Assert.NotNull(reloaded);
        Assert.Equal(BenchmarkGoals.TuneUp, reloaded!.Settings.Goal);
        Assert.Equal(BenchmarkGoals.Browsing, reloaded.Before!.Goal);
        Assert.Equal([BenchmarkKind.DnsLookup], reloaded.Before.EnabledKinds);

        // Upload built from the completed run preserves the run's original goal and measurements.
        var upload = BenchmarkUpload.Build(reloaded.Before, "pc-1", "DEVBOX", new BenchmarkHardware(Processor: "Test CPU"), "2.0.0");
        Assert.NotNull(upload);
        Assert.Equal(BenchmarkGoals.Browsing, upload!.Goal);
        Assert.Equal("DnsLookup", Assert.Single(upload.Results).Kind);
    }
}
