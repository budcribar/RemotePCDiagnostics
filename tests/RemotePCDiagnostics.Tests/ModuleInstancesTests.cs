using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Tests;

public class ModuleInstancesTests
{
    private sealed class FakeDrives(Func<ModuleDetection> detect, Func<ModuleInstance, DiagnosticStatus>? status = null) : IPerDeviceModule
    {
        public Guid Id => TestIds.For(Name);
        public string Name => "drives";
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public List<string> Ran { get; } = [];
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken ct = default) => throw new InvalidOperationException("per instance only");
        public Task<ModuleDetection> DetectAsync(CancellationToken ct = default) => Task.FromResult(detect());
        public Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken ct = default)
        {
            lock (Ran) Ran.Add(instance.Key);
            var s = status?.Invoke(instance) ?? DiagnosticStatus.Ok;
            return Task.FromResult(new DiagnosticResult(Name, s, $"{instance.Label}: {s}", DateTimeOffset.Now));
        }
    }

    private static readonly ModuleInstance DiskA = new(InstanceKeys.From("SERIAL-A"), "Samsung 990 Pro 2 TB, Disk 0");
    private static readonly ModuleInstance DiskB = new(InstanceKeys.From("SERIAL-B"), "WD Blue 1 TB, Disk 1");
    private static readonly ModuleInstance Usb = new(InstanceKeys.From("USB-1"), "USB stick") { NotApplicableReason = "removable" };

    private static async Task WaitForDetection(DiagnosticsService diag)
    {
        for (var i = 0; i < 200 && (diag.IsDetectingHardware || diag.DetectionOf(TestIds.For("drives")) is null); i++) await Task.Delay(10);
    }

    [Fact]
    public void Instance_keys_are_short_stable_and_ignore_case_and_spaces()
    {
        Assert.Equal(16, InstanceKeys.From("abc").Length);
        Assert.Equal(InstanceKeys.From(" Serial-123 "), InstanceKeys.From("SERIAL-123"));
        Assert.NotEqual(InstanceKeys.From("SERIAL-123"), InstanceKeys.From("SERIAL-124"));
    }

    [Fact]
    public async Task A_module_that_does_not_apply_is_hidden_but_stays_known()
    {
        var diag = new DiagnosticsService(new ResultStore(), [new FakeDrives(() => ModuleDetection.NotApplicable("no drives"))]);
        await WaitForDetection(diag);
        Assert.Empty(diag.Modules);
        Assert.Equal(ModuleState.NotPresent, diag.Catalog.StateOf(TestIds.For("drives")));
        Assert.Equal("no drives", diag.DetectionOf(TestIds.For("drives"))!.NotApplicableReason);
    }

    [Fact]
    public async Task Each_instance_runs_and_is_logged_on_its_own_and_the_module_shows_the_worst()
    {
        var store = new ResultStore();
        var sink = new RecordingSink();
        _ = new ResultEventLogger(store, sink);
        var drives = new FakeDrives(() => ModuleDetection.For([DiskA, DiskB, Usb]), i => i == DiskB ? DiagnosticStatus.Warning : DiagnosticStatus.Ok);
        var diag = new DiagnosticsService(store, [drives]);
        await WaitForDetection(diag);
        Assert.Single(diag.Modules);
        Assert.Equal(2, diag.InstancesOf(drives).Count);

        var r = await diag.RunAsync("drives");
        Assert.Equal([DiskA.Key, DiskB.Key], drives.Ran); // the USB stick doesn't apply
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal(2, Assert.IsType<InstanceResults>(r.Payload).Results.Count);
        Assert.Contains("1 of 2 need attention", r.Message);
        Assert.Equal(DiagnosticStatus.Warning, store.GetInstance("drives", DiskB.Key)!.Status);
        Assert.Equal(2, store.InstancesOf("drives").Count);
        Assert.Null(store.Get("drives").InstanceKey);

        var events = sink.Entries.Where(e => e.EventId == LogEventIds.TestResult).ToList();
        Assert.Equal(2, events.Count); // one per instance; the module's summary isn't logged again
        var parsed = events.Select(e => HistoryEventParser.Parse(e.Message, DateTimeOffset.Now)!).ToList();
        Assert.Contains(parsed, p => p.InstanceId == DiskB.Key && p.Instance == DiskB.Label && p.Outcome == "Warning" && p.DurationSeconds is not null);
        Assert.Contains(parsed, p => p.InstanceId == DiskA.Key && p.Outcome == "OK");
    }

    [Fact]
    public async Task Redetect_picks_up_a_new_device()
    {
        var present = new List<ModuleInstance>();
        var drives = new FakeDrives(() => ModuleDetection.For(present));
        var diag = new DiagnosticsService(new ResultStore(), [drives]);
        await WaitForDetection(diag);
        Assert.Empty(diag.Modules);
        present.Add(DiskA);
        await diag.RedetectAsync();
        Assert.Single(diag.Modules);
        Assert.Equal(ModuleState.Available, diag.Catalog.StateOf(drives.Id));
    }

    [Fact]
    public async Task A_module_that_cannot_run_records_couldnt_run_with_the_reason()
    {
        var store = new ResultStore();
        var diag = new DiagnosticsService(store, [new FakeModule("tool", _ => Task.FromResult(FakeModule.Ok("tool")), available: false)]);
        var r = await diag.RunAsync("tool");
        Assert.IsType<CouldNotRun>(r.Payload);
        Assert.Equal(CouldNotRun.OutcomeText, ResultEventLogger.Outcome(r));
        Assert.Equal(RowKind.CouldNotRun, CheckRows.KindOf(r));
        Assert.False(ModuleOrdering.Passed(r));
    }

    [Fact]
    public void Results_written_as_unavailable_read_back_as_couldnt_run()
    {
        var e = HistoryEventParser.Parse("Test result: x\nModule id: 6e35be79-0000-0000-0000-000000000000\nOutcome: Unavailable\nSummary: s\nFinished: 2026-01-01T00:00:00Z\nFormat: 3", DateTimeOffset.Now);
        Assert.Equal(CouldNotRun.OutcomeText, e!.Outcome);
    }
}
