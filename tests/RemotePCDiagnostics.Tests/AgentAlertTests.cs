using RemotePCDiagnostics.Core.Alerts;

namespace RemotePCDiagnostics.Tests;

public class AgentAlertBookTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 25, 3, 0, 0, TimeSpan.Zero);

    private sealed class Clock { public DateTimeOffset Now = T0; }

    private static (AgentAlertBook Book, Clock Clock) NewBook(string? path = null)
    {
        var clock = new Clock();
        return (new AgentAlertBook(path, () => clock.Now, () => "1.2.3"), clock);
    }

    private static AlertSignal Crash(string app = "chrome.exe", int repeats = 3) =>
        new(AlertKinds.AppCrash, AlertLevel.Info, app, app, $"{app} crashed.", null, new AlertEventRef("Application", "Application Error", 1000, 1),
            new AlertEscalation(repeats, TimeSpan.FromDays(1), AlertLevel.Warning));

    [Fact]
    public void A_repeat_of_an_open_alert_counts_on_it_with_a_new_seq()
    {
        var (book, clock) = NewBook();
        var first = book.Raise(Crash(), AlertSettings.Default)!;
        clock.Now += TimeSpan.FromMinutes(5);
        var second = book.Raise(Crash(), AlertSettings.Default)!;

        Assert.Equal(first.AlertId, second.AlertId);
        Assert.Equal(2, second.Count);
        Assert.True(second.Seq > first.Seq);
        Assert.Equal(AlertLevel.Info, second.Level);
        Assert.Equal(["Crashes"], second.RelatedChecks);
        Assert.Single(book.Alerts);
    }

    [Fact]
    public void The_same_app_crashing_three_times_in_a_day_becomes_a_warning()
    {
        var (book, clock) = NewBook();
        book.Raise(Crash(), AlertSettings.Default);
        clock.Now += TimeSpan.FromHours(2);
        Assert.Equal(AlertLevel.Info, book.Raise(Crash(), AlertSettings.Default)!.Level);
        clock.Now += TimeSpan.FromHours(2);
        Assert.Equal(AlertLevel.Warning, book.Raise(Crash(), AlertSettings.Default)!.Level);
    }

    [Fact]
    public void Kinds_the_setting_turns_off_raise_nothing()
    {
        var (book, _) = NewBook();
        var settings = AlertSettings.From(2, true, [AlertKinds.AppCrash], 0, 0, 0, 0, 0);
        Assert.Null(book.Raise(Crash(), settings));
        Assert.Null(book.Raise(Crash(), AlertSettings.From(3, false, [], 0, 0, 0, 0, 0)));
        Assert.Empty(book.Alerts);
    }

    [Fact]
    public void After_Admin_handles_an_alert_a_repeat_within_the_hour_counts_on_it_and_later_opens_a_new_one()
    {
        var (book, clock) = NewBook();
        var first = book.Raise(Crash(), AlertSettings.Default)!;
        Assert.True(book.SetStatus(first.AlertId, AlertStatus.Handled));
        clock.Now += TimeSpan.FromMinutes(30);
        var again = book.Raise(Crash(), AlertSettings.Default)!;
        Assert.Equal((first.AlertId, AlertStatus.Handled, 2), (again.AlertId, again.Status, again.Count));

        clock.Now += TimeSpan.FromHours(1);
        var later = book.Raise(Crash(), AlertSettings.Default)!;
        Assert.NotEqual(first.AlertId, later.AlertId);
        Assert.Equal(AlertStatus.Open, later.Status);
    }

    [Fact]
    public void Past_twenty_new_alerts_in_a_day_one_too_many_alert_counts_the_rest()
    {
        var (book, clock) = NewBook();
        for (var i = 0; i < AgentAlertBook.MaxNewPerDay; i++)
        {
            book.Raise(Crash("app" + i + ".exe"), AlertSettings.Default);
            clock.Now += TimeSpan.FromMinutes(1);
        }
        var over = book.Raise(Crash("one-more.exe"), AlertSettings.Default)!;
        var overAgain = book.Raise(Crash("and-another.exe"), AlertSettings.Default)!;

        Assert.Equal(AlertKinds.TooMany, over.Kind);
        Assert.Equal((over.AlertId, 2), (overAgain.AlertId, overAgain.Count));
        Assert.Equal(AgentAlertBook.MaxNewPerDay + 1, book.Alerts.Count);
    }

    [Fact]
    public void Only_changes_since_the_last_acknowledgement_are_uploaded()
    {
        var (book, clock) = NewBook();
        var a = book.Raise(Crash("a.exe"), AlertSettings.Default)!;
        var b = book.Raise(Crash("b.exe"), AlertSettings.Default)!;
        Assert.Equal([a.Seq, b.Seq], book.NextBatch().Select(x => x.Seq));

        Assert.Equal(2, book.Acknowledge(b.Seq));
        Assert.Empty(book.NextBatch());

        clock.Now += TimeSpan.FromMinutes(1);
        var a2 = book.Raise(Crash("a.exe"), AlertSettings.Default)!;
        Assert.Equal([a2.AlertId], book.NextBatch().Select(x => x.AlertId)); // only the alert that changed, at its newest
        Assert.Equal(0, book.Acknowledge(b.Seq)); // an old acknowledgement changes nothing
    }

    [Fact]
    public void Level_alerts_clear_and_quiet_event_alerts_clear_after_seven_days()
    {
        var (book, clock) = NewBook();
        var disk = book.Raise(new AlertSignal(AlertKinds.LowDisk, AlertLevel.Warning, "C:", "C:", "low"), AlertSettings.Default)!;
        var crash = book.Raise(Crash(), AlertSettings.Default)!;

        Assert.Null(book.Clear(AlertKinds.LowDisk, "D:"));
        Assert.Equal(AlertStatus.Cleared, book.Clear(AlertKinds.LowDisk, "c:")!.Status);

        clock.Now += TimeSpan.FromDays(6);
        Assert.Equal(0, book.ExpireQuiet());
        clock.Now += TimeSpan.FromDays(1);
        Assert.Equal(1, book.ExpireQuiet());
        Assert.Empty(book.Open);
        Assert.Contains(book.NextBatch(), x => x.AlertId == crash.AlertId && x.Status == AlertStatus.Cleared);
        Assert.Contains(book.NextBatch(), x => x.AlertId == disk.AlertId);
    }

    [Fact]
    public void Closed_alerts_Admin_has_are_dropped_after_thirty_days()
    {
        var (book, clock) = NewBook();
        var a = book.Raise(Crash(), AlertSettings.Default)!;
        book.SetStatus(a.AlertId, AlertStatus.Handled);
        clock.Now += TimeSpan.FromDays(31);
        var b = book.Raise(Crash("other.exe"), AlertSettings.Default)!;
        book.Acknowledge(b.Seq);
        Assert.Equal([b.AlertId], book.Alerts.Select(x => x.AlertId));
    }

    [Fact]
    public void The_book_survives_a_restart_and_never_reuses_a_seq()
    {
        var path = Path.Combine(Path.GetTempPath(), "rpcd-alerts-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var (book, _) = NewBook(path);
            var a = book.Raise(Crash(), AlertSettings.Default)!;
            book.Acknowledge(a.Seq);
            var b = book.Raise(Crash("b.exe"), AlertSettings.Default)!;

            var (again, _) = NewBook(path);
            Assert.Equal(2, again.Alerts.Count);
            Assert.Equal([b.Seq], again.NextBatch().Select(x => x.Seq));
            Assert.True(again.Raise(Crash("c.exe"), AlertSettings.Default)!.Seq > b.Seq);

            File.WriteAllText(path, "{ not json");
            var (fresh, _) = NewBook(path);
            Assert.Empty(fresh.Alerts);
            Assert.True(File.Exists(path + ".bad"));
        }
        finally
        {
            foreach (var f in new[] { path, path + ".tmp", path + ".bad" }) try { File.Delete(f); } catch { }
        }
    }
}

public class AlertRulesTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 25, 3, 0, 0, TimeSpan.Zero);

    private static AlertEvent Event(string channel, string provider, int id, params string[] props) =>
        new(channel, provider, id, 42, T0, props, "First line of the message.\r\nMore text.");

    [Fact]
    public void The_query_asks_for_the_channel_ids_at_warning_or_worse_after_the_last_record()
    {
        var q = AlertRules.Query(AlertRules.ApplicationChannel, 1234, TimeSpan.FromDays(1));
        Assert.Equal("*[System[(EventID=1000 or EventID=1002) and (Level=1 or Level=2 or Level=3) and EventRecordID>1234 and TimeCreated[timediff(@SystemTime) <= 86400000]]]", q);
    }

    [Theory]
    [InlineData("System", "disk", 7, AlertKinds.DiskErrors, AlertLevel.Warning)]
    [InlineData("System", "disk", 52, AlertKinds.SmartFailure, AlertLevel.Critical)]
    [InlineData("System", "Ntfs", 55, AlertKinds.FsCorruption, AlertLevel.Critical)]
    [InlineData("System", "Microsoft-Windows-Kernel-Power", 41, AlertKinds.UnexpectedShutdown, AlertLevel.Warning)]
    [InlineData("System", "Microsoft-Windows-WER-SystemErrorReporting", 1001, AlertKinds.Bluescreen, AlertLevel.Critical)]
    [InlineData("System", "Microsoft-Windows-WindowsUpdateClient", 20, AlertKinds.UpdateFailed, AlertLevel.Warning)]
    [InlineData("System", "Microsoft-Windows-Resource-Exhaustion-Detector", 2004, AlertKinds.LowMemory, AlertLevel.Warning)]
    [InlineData("Application", "Application Error", 1000, AlertKinds.AppCrash, AlertLevel.Info)]
    [InlineData("Application", "Application Hang", 1002, AlertKinds.AppCrash, AlertLevel.Info)]
    public void Events_map_to_their_alert(string channel, string provider, int id, string kind, AlertLevel level)
    {
        var signals = AlertRules.FromEvent(Event(channel, provider, id, "0x0000009f (0x3, 0x1)", "2026-11 Cumulative Update", "{guid}"), AlertSettings.Default, null, out _);
        var s = Assert.Single(signals);
        Assert.Equal((kind, level), (s.Kind, s.Level));
        Assert.Equal(id, s.Source!.EventId);
    }

    [Fact]
    public void Same_ids_from_another_provider_raise_nothing()
    {
        Assert.Empty(AlertRules.FromEvent(Event("System", "SomeDriver", 7, "x"), AlertSettings.Default, null, out _));
        Assert.Empty(AlertRules.FromEvent(Event("Application", "Application Error", 1000), AlertSettings.Default, null, out _)); // no app name
    }

    [Fact]
    public void Instances_come_from_the_event_data()
    {
        var bsod = Assert.Single(AlertRules.FromEvent(Event("System", "Microsoft-Windows-WER-SystemErrorReporting", 1001, "0x0000009f (0x3, 0x1)"), AlertSettings.Default, null, out _));
        Assert.Equal("0x0000009f", bsod.InstanceId);
        var ntfs = Assert.Single(AlertRules.FromEvent(Event("System", "Ntfs", 55, "\\Device\\HarddiskVolume3", "D:"), AlertSettings.Default, null, out _));
        Assert.Equal("D:", ntfs.InstanceId);
        var crash = Assert.Single(AlertRules.FromEvent(Event("Application", "Application Error", 1000, "Chrome.EXE"), AlertSettings.Default, null, out _));
        Assert.Equal(("chrome.exe", "Chrome.EXE"), (crash.InstanceId, crash.InstanceLabel));
        Assert.Equal("First line of the message.", crash.Summary);
    }

    [Fact]
    public void The_low_disk_event_asks_for_a_reading_instead_of_an_alert()
    {
        Assert.Empty(AlertRules.FromEvent(Event("System", "srv", 2013, "C:"), AlertSettings.Default, null, out var readNow));
        Assert.True(readNow);
    }

    [Fact]
    public void A_shutdown_on_battery_with_charge_left_is_a_failing_battery_too()
    {
        var shutdown = Event("System", "Microsoft-Windows-Kernel-Power", 41);
        var onBattery = new PowerReading(T0 - TimeSpan.FromMinutes(10), OnBattery: true, Percent: 45, Charging: false, HasBattery: true);
        var kinds = AlertRules.FromEvent(shutdown, AlertSettings.Default, onBattery, out _).Select(s => s.Kind);
        Assert.Equal([AlertKinds.UnexpectedShutdown, AlertKinds.BatteryFailing], kinds);

        Assert.Single(AlertRules.FromEvent(shutdown, AlertSettings.Default, onBattery with { Percent = 8 }, out _));
        Assert.Equal(2, AlertRules.FromEvent(shutdown, AlertSettings.Default, onBattery with { TimeUtc = T0 - TimeSpan.FromHours(9) }, out _).Count); // off all night
        Assert.Single(AlertRules.FromEvent(shutdown, AlertSettings.Default, onBattery with { TimeUtc = T0 - TimeSpan.FromDays(8) }, out _));
        var whileAsleep = Event("System", "Microsoft-Windows-Kernel-Power", 41, "0", "0", "0", "0", "0", "true", "0");
        Assert.Single(AlertRules.FromEvent(whileAsleep, AlertSettings.Default, onBattery, out _));
        var powerButton = Event("System", "Microsoft-Windows-Kernel-Power", 41, "0", "0", "0", "0", "0", "false", "133456789");
        Assert.Single(AlertRules.FromEvent(powerButton, AlertSettings.Default, onBattery, out _));
        Assert.Single(AlertRules.FromEvent(shutdown, AlertSettings.Default, onBattery with { OnBattery = false }, out _));
    }

    [Theory]
    [InlineData(4.0, 500.0, LevelDecision.Raise, AlertLevel.Warning)]   // under 5 GB
    [InlineData(1.5, 500.0, LevelDecision.Raise, AlertLevel.Critical)]  // under 2 GB
    [InlineData(15.0, 200.0, LevelDecision.Raise, AlertLevel.Warning)]  // 7.5% and under 20 GB
    [InlineData(150.0, 2000.0, LevelDecision.None, AlertLevel.Info)]    // 7.5% of a big drive: plenty left
    [InlineData(50.0, 200.0, LevelDecision.None, AlertLevel.Info)]
    public void Disk_thresholds(double freeGb, double totalGb, LevelDecision expected, AlertLevel level)
    {
        var (decision, signal) = AlertRules.Disk(new DiskReading("C:", freeGb, totalGb), AlertSettings.Default, open: false);
        Assert.Equal(expected, decision);
        if (expected == LevelDecision.Raise) Assert.Equal(level, signal!.Level);
    }

    [Fact]
    public void Disk_clears_only_past_the_margin()
    {
        Assert.Equal(LevelDecision.None, AlertRules.Disk(new DiskReading("C:", 5.5, 50), AlertSettings.Default, open: true).Decision); // no longer low, not past the margin
        Assert.Equal(LevelDecision.Clear, AlertRules.Disk(new DiskReading("C:", 30, 500), AlertSettings.Default, open: true).Decision);
        Assert.Equal(LevelDecision.None, AlertRules.Disk(new DiskReading("C:", 30, 500), AlertSettings.Default, open: false).Decision);
        Assert.Equal(LevelDecision.None, AlertRules.Disk(new DiskReading("R:", 0.1, 0.5), AlertSettings.Default, open: false).Decision); // recovery partition
    }

    [Fact]
    public void Memory_needs_two_high_readings_and_clears_five_points_under()
    {
        Assert.Equal(LevelDecision.None, AlertRules.Memory(95, previousHigh: false, AlertSettings.Default, open: false).Decision);
        Assert.Equal(LevelDecision.Raise, AlertRules.Memory(95, previousHigh: true, AlertSettings.Default, open: false).Decision);
        Assert.Equal(LevelDecision.None, AlertRules.Memory(87, previousHigh: true, AlertSettings.Default, open: true).Decision);
        Assert.Equal(LevelDecision.Clear, AlertRules.Memory(80, previousHigh: true, AlertSettings.Default, open: true).Decision);
    }

    [Fact]
    public void A_battery_that_stays_low_while_plugged_in_and_not_charging_is_failing()
    {
        var earlier = new PowerReading(T0, OnBattery: false, Percent: 30, Charging: false, HasBattery: true);
        var now = earlier with { TimeUtc = T0 + TimeSpan.FromMinutes(30) };
        Assert.NotNull(AlertRules.NotCharging(now, earlier));
        Assert.Null(AlertRules.NotCharging(now with { Percent = 60 }, earlier with { Percent = 60 })); // could be a charge limit
        Assert.Null(AlertRules.NotCharging(now with { Percent = 31 }, earlier));                      // it went up
        Assert.Null(AlertRules.NotCharging(now with { Charging = true }, earlier));
        Assert.Null(AlertRules.NotCharging(now with { TimeUtc = T0 + TimeSpan.FromMinutes(15) }, earlier));
    }

    [Fact]
    public void Settings_from_Admin_use_defaults_for_zero_and_clamp_the_rest()
    {
        var s = AlertSettings.From(5, true, ["app_crash", " ", "APP_CRASH"], 0, 200, double.NaN, 1, 1000);
        Assert.Equal((5L, true), (s.Revision, s.Enabled));
        Assert.Equal(["app_crash"], s.DisabledKinds);
        Assert.Equal((AlertSettings.DefaultLowDiskFreeGb, 50.0, AlertSettings.DefaultMemoryCommitPercent, 2, 168),
            (s.LowDiskFreeGb, s.LowDiskFreePercent, s.MemoryCommitPercent, s.AppCrashRepeats, s.AppCrashWindowHours));
        Assert.False(s.Allows(AlertKinds.AppCrash));
        Assert.True(s.Allows(AlertKinds.LowDisk));
    }
}

public sealed class AgentAlertsUploadTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "rpcd-agent-alerts-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = new(2026, 11, 25, 3, 0, 0, TimeSpan.Zero);

    public void Dispose() { try { Directory.Delete(_folder, recursive: true); } catch { } }

    private RemotePCDiagnostics.Agent.AgentAlerts New()
    {
        Directory.CreateDirectory(_folder);
        return new RemotePCDiagnostics.Agent.AgentAlerts(_folder, () => "1.2.3", () => _now);
    }

    private static AlertSignal Disk(string drive) => new(AlertKinds.LowDisk, AlertLevel.Critical, drive, drive, "low", [new AlertFactItem("free_gb", "1.5")]);

    [Fact]
    public async Task Changes_are_sent_and_kept_until_Admin_acknowledges()
    {
        var alerts = New();
        alerts.Book.Raise(Disk("C:"), alerts.Settings);
        var sent = new List<PeakSWC.RemoteWebView.Agent.AlertBatch>();
        alerts.Attach((m, _) =>
        {
            sent.Add(m.Alerts);
            alerts.Acknowledge(m.Alerts.Alerts.Max(a => a.Seq));
            return Task.CompletedTask;
        });
        await alerts.UploadAsync(CancellationToken.None);

        var alert = Assert.Single(Assert.Single(sent).Alerts);
        Assert.Equal(("low_disk", PeakSWC.RemoteWebView.Agent.AlertSeverity.AlertCritical, PeakSWC.RemoteWebView.Agent.AlertState.AlertOpen, "C:"),
            (alert.Kind, alert.Severity, alert.State, alert.InstanceId));
        Assert.Equal(["DriveHealth", "DiskSpace"], alert.RelatedChecks);
        Assert.Equal("1.5", Assert.Single(alert.Facts).Value);
        Assert.Equal(0, alerts.Book.Waiting);
    }

    [Fact]
    public async Task Without_an_acknowledgement_the_alert_stays_and_the_upload_backs_off()
    {
        var alerts = New();
        alerts.Book.Raise(Disk("C:"), alerts.Settings);
        var sends = 0;
        alerts.Attach((_, _) => { sends++; throw new IOException("stream gone"); });
        await alerts.UploadAsync(CancellationToken.None);
        await alerts.UploadAsync(CancellationToken.None);
        Assert.Equal(1, sends);
        _now += RemotePCDiagnostics.Agent.AgentAlerts.MinUploadBackoff + TimeSpan.FromSeconds(1);
        await alerts.UploadAsync(CancellationToken.None);
        Assert.Equal(2, sends);
        Assert.Equal(1, alerts.Book.Waiting);
    }

    [Fact]
    public void Admin_settings_are_saved_and_older_revisions_ignored_and_state_reaches_the_book()
    {
        var alerts = New();
        Assert.True(alerts.ApplySettings(new PeakSWC.RemoteWebView.Agent.AlertSettingsCommand { Revision = 3, Enabled = true, DisabledKinds = { "app_crash" } }));
        Assert.False(alerts.ApplySettings(new PeakSWC.RemoteWebView.Agent.AlertSettingsCommand { Revision = 2, Enabled = false }));
        Assert.Equal(3, New().SettingsRevision); // read back from the file

        var a = alerts.Book.Raise(Disk("C:"), alerts.Settings)!;
        alerts.ApplyState(new PeakSWC.RemoteWebView.Agent.AlertStateCommand { AlertId = a.AlertId, State = PeakSWC.RemoteWebView.Agent.AlertState.AlertHandled });
        Assert.Equal(AlertStatus.Handled, Assert.Single(alerts.Book.Alerts).Status);
    }
}
