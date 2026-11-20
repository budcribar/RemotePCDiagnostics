using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Sleep, wake &amp; standby drain. The S3 fixtures (powercfg /a, /lastwake, /devicequery, the System log events and the battery report)
/// were captured on a Lenovo 82R4 laptop on 2026-11-19; the Modern Standby, wake timer and power request samples follow the same
/// powercfg formats.
/// </summary>
public class SleepWakeTests
{
    // ---- captured on an S3 laptop (reason lines are tab-indented there) ----
    private const string S3States =
        "The following sleep states are available on this system:\r\n" +
        "    Standby (S3)\r\n    Hibernate\r\n    Fast Startup\r\n\r\n" +
        "The following sleep states are not available on this system:\r\n" +
        "    Standby (S1)\r\n\tThe system firmware does not support this standby state.\r\n\r\n" +
        "    Standby (S2)\r\n\tThe system firmware does not support this standby state.\r\n\r\n" +
        "    Standby (S0 Low Power Idle)\r\n\tThe system firmware does not support this standby state.\r\n\r\n" +
        "    Hybrid Sleep\r\n\tThe hypervisor does not support this standby state.\r\n";

    private const string ModernStandbyStates =
        "The following sleep states are available on this system:\r\n" +
        "    Standby (S0 Low Power Idle) Network Connected\r\n    Hibernate\r\n    Fast Startup\r\n\r\n" +
        "The following sleep states are not available on this system:\r\n" +
        "    Standby (S3)\r\n        This standby state is disabled when S0 low power idle is supported.\r\n\r\n" +
        "    Hybrid Sleep\r\n        Standby (S3) is not available.\r\n        The hypervisor does not support this standby state.\r\n";

    private const string LastWake =
        "Wake History Count - 1\r\nWake History [0]\r\n  Wake Source Count - 1\r\n  Wake Source [0]\r\n    Type: Device\r\n" +
        "    Instance Path: PCI\\VEN_1022&DEV_1639&SUBSYS_386017AA&REV_00\\4&1185d5e4&0&0441\r\n" +
        "    Friendly Name: AMD USB 3.10 eXtensible Host Controller - 1.10 (Microsoft)\r\n" +
        "    Description: USB xHCI Compliant Host Controller\r\n    Manufacturer: Generic USB xHCI Host Controller\r\n";

    private const string WakeArmed = "HID Keyboard Device\r\nHID-compliant mouse (001)\r\n";

    private const string WakeEventXml =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Power-Troubleshooter' Guid='{cdc05e28-c449-49c6-b9d2-88cf761644df}'/><EventID>1</EventID><Version>3</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-11-19T03:36:08.2981640Z'/><EventRecordID>132639</EventRecordID><Channel>System</Channel><Computer>PC</Computer></System>"
        + "<EventData><Data Name='SleepTime'>2026-11-19T02:16:18.2435582Z</Data><Data Name='WakeTime'>2026-11-19T03:36:07.1929106Z</Data><Data Name='SleepDuration'>466</Data><Data Name='WakeDuration'>692</Data><Data Name='TargetState'>4</Data><Data Name='EffectiveState'>4</Data><Data Name='WakeSourceType'>5</Data><Data Name='WakeSourceTextLength'>58</Data><Data Name='WakeSourceText'>AMD USB 3.10 eXtensible Host Controller - 1.10 (Microsoft)</Data><Data Name='WakeTimerOwnerLength'>0</Data><Data Name='WakeTimerContextLength'>0</Data><Data Name='WakeTimerOwner'></Data><Data Name='WakeTimerContext'></Data></EventData>"
        + "<RenderingInfo Culture='en-US'><Message>The system has returned from a low power state.</Message><Level>Information</Level><Provider>Microsoft-Windows-Power-Troubleshooter</Provider></RenderingInfo></Event>"
        + "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/><EventID>107</EventID><Version>1</Version><Level>4</Level><TimeCreated SystemTime='2026-11-19T02:16:19.9924362Z'/><Channel>System</Channel></System><EventData><Data Name='TargetState'>4</Data><Data Name='EffectiveState'>4</Data><Data Name='WakeFromState'>4</Data></EventData><RenderingInfo Culture='en-US'><Message>The system has resumed from sleep.</Message></RenderingInfo></Event>"
        + "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/><EventID>42</EventID><Version>3</Version><Level>4</Level><TimeCreated SystemTime='2026-11-19T02:16:18.7057866Z'/><Channel>System</Channel></System><EventData><Data Name='TargetState'>4</Data><Data Name='EffectiveState'>4</Data><Data Name='Reason'>7</Data><Data Name='Flags'>0</Data><Data Name='TransitionsToOn'>1</Data></EventData><RenderingInfo Culture='en-US'><Message>The system is entering sleep.</Message></RenderingInfo></Event>";

    /// <summary>The captured report's RecentUsage (all on wall power), trimmed, plus <paramref name="extra"/> entries.</summary>
    private static string BatteryReport(string extra = "") =>
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><BatteryReport xmlns=\"http://schemas.microsoft.com/battery/2012\">"
        + "<SystemInformation><ComputerName>PC</ComputerName><PlatformRole>Mobile</PlatformRole><ConnectedStandby>0</ConnectedStandby></SystemInformation>"
        + "<Batteries><Battery><Id>L21D3PF0</Id><Chemistry>LiP</Chemistry><DesignCapacity>42000</DesignCapacity><FullChargeCapacity>39670</FullChargeCapacity><CycleCount>15</CycleCount></Battery></Batteries>"
        + "<RecentUsage>"
        + "<UsageEntry Timestamp=\"2026-11-13T00:25:59Z\" LocalTimestamp=\"2026-11-12T17:25:59\" Duration=\"1373634386760\" Ac=\"1\" EntryType=\"Active\" ChargeCapacity=\"39070\" Discharge=\"-600\" FullChargeCapacity=\"39670\" IsNextOnBattery=\"0\" />"
        + "<UsageEntry Timestamp=\"2026-11-19T02:16:18Z\" LocalTimestamp=\"2026-11-18T19:16:18\" Duration=\"48235367482\" Ac=\"1\" EntryType=\"Suspend\" ChargeCapacity=\"39670\" Discharge=\"0\" FullChargeCapacity=\"39670\" IsNextOnBattery=\"0\" />"
        + "<UsageEntry Timestamp=\"2026-11-19T03:36:42Z\" LocalTimestamp=\"2026-11-18T20:36:42\" Duration=\"725486181214\" Ac=\"1\" EntryType=\"Active\" ChargeCapacity=\"39670\" Discharge=\"0\" FullChargeCapacity=\"39670\" IsNextOnBattery=\"0\" />"
        + extra
        + "<UsageEntry Timestamp=\"2026-11-19T23:45:50Z\" LocalTimestamp=\"2026-11-19T16:45:50\" Duration=\"0\" Ac=\"1\" EntryType=\"ReportGenerated\" ChargeCapacity=\"39670\" Discharge=\"0\" FullChargeCapacity=\"39670\" IsNextOnBattery=\"0\" />"
        + "</RecentUsage><EnergyDrains /></BatteryReport>";

    private static string Usage(string start, TimeSpan d, string type, int discharge, string ac = "0") =>
        $"<UsageEntry Timestamp=\"{start}\" LocalTimestamp=\"{start.TrimEnd('Z')}\" Duration=\"{d.Ticks}\" Ac=\"{ac}\" EntryType=\"{type}\" ChargeCapacity=\"30000\" Discharge=\"{discharge}\" FullChargeCapacity=\"40000\" IsNextOnBattery=\"0\" />";

    private const string Requests =
        "DISPLAY:\r\nNone.\r\n\r\nSYSTEM:\r\n[DRIVER] Realtek High Definition Audio(SST) (HDAUDIO\\FUNC_01&VEN_10EC&DEV_0257)\r\nAn audio stream is currently in use.\r\n\r\n" +
        "AWAYMODE:\r\nNone.\r\n\r\nEXECUTION:\r\n[PROCESS] \\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe\r\nPlaying audio\r\n\r\n" +
        "PERFBOOST:\r\nNone.\r\n\r\nACTIVELOCKSCREEN:\r\nNone.\r\n";

    private const string NoRequests = "DISPLAY:\r\nNone.\r\n\r\nSYSTEM:\r\nNone.\r\n\r\nAWAYMODE:\r\nNone.\r\n\r\nEXECUTION:\r\nNone.\r\n\r\nPERFBOOST:\r\nNone.\r\n\r\nACTIVELOCKSCREEN:\r\nNone.\r\n";

    private const string Timers =
        "Timer set by [SERVICE] \\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe (SystemEventsBroker) expires at 3:15:11 AM on 11/20/2026.\r\n" +
        "  Reason: Windows will execute 'NT TASK\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot' scheduled task that requested waking the computer.\r\n\r\n";

    // ---- parsers ----

    [Fact]
    public void SleepStates_S3_laptop_with_tab_indented_reasons()
    {
        var s = SleepWakeParsers.ParseSleepStates(S3States)!;
        Assert.Equal(["Standby (S3)", "Hibernate", "Fast Startup"], s.Available);
        Assert.Equal(["Standby (S1)", "Standby (S2)", "Standby (S0 Low Power Idle)", "Hybrid Sleep"], s.Unavailable.Select(u => u.State));
        Assert.Equal("The hypervisor does not support this standby state.", s.Unavailable[^1].Reason);
        Assert.True(s.S3);
        Assert.False(s.ModernStandby);
        Assert.True(s.Hibernate);
    }

    [Fact]
    public void SleepStates_modern_standby_with_space_indented_reasons()
    {
        var s = SleepWakeParsers.ParseSleepStates(ModernStandbyStates)!;
        Assert.True(s.ModernStandby);
        Assert.False(s.S3);
        Assert.Equal(["Standby (S3)", "Hybrid Sleep"], s.Unavailable.Select(u => u.State));
        Assert.Equal("Standby (S3) is not available. The hypervisor does not support this standby state.", s.Unavailable[1].Reason);
        Assert.Null(SleepWakeParsers.ParseSleepStates(""));
    }

    [Fact]
    public void LastWake_reads_the_wake_source()
    {
        var w = Assert.Single(SleepWakeParsers.ParseLastWake(LastWake));
        Assert.Equal("Device", w.Type);
        Assert.Equal("AMD USB 3.10 eXtensible Host Controller - 1.10 (Microsoft)", w.Name);
        Assert.StartsWith("PCI\\VEN_1022", w.InstancePath);
        Assert.Empty(SleepWakeParsers.ParseLastWake("Wake History Count - 0\r\n"));
    }

    [Fact]
    public void WakeArmed_lists_each_device_and_NONE_is_empty()
    {
        Assert.Equal(["HID Keyboard Device", "HID-compliant mouse (001)"], DeviceWake.ParseArmed(WakeArmed));
        Assert.Empty(DeviceWake.ParseArmed("NONE\r\n"));
        Assert.Empty(DeviceWake.ParseArmed(""));
    }

    [Fact]
    public void WakeTimers_and_requests()
    {
        var t = Assert.Single(SleepWakeParsers.ParseWakeTimers(Timers));
        Assert.Equal("3:15:11 AM on 11/20/2026", t.Expires);
        Assert.StartsWith("[SERVICE] \\Device", t.Owner);
        Assert.StartsWith("Windows will execute", t.Reason);
        Assert.Empty(SleepWakeParsers.ParseWakeTimers("There are no active wake timers in the system.\r\n"));

        var r = SleepWakeParsers.ParseRequests(Requests)!;
        Assert.Equal(2, r.Count);
        Assert.Equal(("SYSTEM", "DRIVER", "An audio stream is currently in use."), (r[0].Category, r[0].RequesterType, r[0].Detail));
        Assert.True(r[0].BlocksSleep);
        Assert.Equal("chrome.exe", SleepWakeParsers.ShortRequester(r[1].Requester));
        Assert.False(r[1].BlocksSleep);
        Assert.Empty(SleepWakeParsers.ParseRequests(NoRequests)!);
        Assert.Null(SleepWakeParsers.ParseRequests("This command requires administrator privileges and must be executed from an elevated command prompt."));
    }

    [Fact]
    public void Wake_event_from_the_system_log()
    {
        var events = WindowsEventLog.Parse(WakeEventXml, "System");
        var w = WakeEvent.From(events.Single(e => e.EventId == 1))!;
        Assert.Equal("AMD USB 3.10 eXtensible Host Controller - 1.10 (Microsoft)", w.Source);
        Assert.Equal(4788.95, w.Slept.TotalSeconds, 0.01);
        Assert.False(w.Unexpected);
        Assert.True(new WakeEvent(w.SleepTime, w.WakeTime, "Intel(R) Ethernet Controller I225-V", "").ByNetwork);
        Assert.True(new WakeEvent(w.SleepTime, w.WakeTime, "", "[SERVICE] svchost.exe").ByTimer);
    }

    [Fact]
    public void Battery_report_on_wall_power_has_no_sleep_to_rate()
    {
        var sessions = StandbyDrain.Parse(BatteryReport())!;
        Assert.Empty(sessions);
        Assert.False(StandbyDrain.ConnectedStandby(BatteryReport()));
        Assert.Null(StandbyDrain.AveragePercentPerHour(sessions));
        Assert.Null(StandbyDrain.Parse("<html/>"));
        Assert.Null(StandbyDrain.Parse("not xml"));
    }

    [Fact]
    public void Battery_report_rates_sleep_on_battery()
    {
        var xml = BatteryReport(
            Usage("2026-11-18T06:00:00Z", TimeSpan.FromHours(8), "Suspend", 4000)            // 10% in 8 h = 1.25%/h
            + Usage("2026-11-18T15:00:00Z", TimeSpan.FromMinutes(10), "Suspend", 400)       // too short to rate
            + Usage("2026-11-18T16:00:00Z", TimeSpan.FromHours(2), "Active", 8000)          // awake: ignored
            + Usage("2026-11-18T20:00:00Z", TimeSpan.FromHours(2), "ConnectedStandby", 4000) // 10% in 2 h = 5%/h
            + Usage("2026-11-18T23:00:00Z", TimeSpan.FromHours(2), "Suspend", 0, ac: "1"));  // plugged in: ignored
        var s = StandbyDrain.Parse(xml)!;
        Assert.Equal(3, s.Count);
        Assert.Equal(1.25, s[0].PercentPerHour, 3);
        Assert.Equal(5, s[2].PercentPerHour, 3);
        Assert.Equal(2, StandbyDrain.Rated(s).Count);
        Assert.Equal(20.0 / 10, StandbyDrain.AveragePercentPerHour(s)!.Value, 3); // 20% over 10 h
        Assert.Equal(AreaLevel.Warning, StandbyDrain.LevelOf(2));
        Assert.Equal(AreaLevel.Error, StandbyDrain.LevelOf(5));
        Assert.Equal(AreaLevel.Ok, StandbyDrain.LevelOf(1.25));
    }

    // ---- report ----

    private static SleepWakeFacts Facts(string? events = WakeEventXml, string? battery = null, string? requests = Requests, string? timers = Timers, string armed = WakeArmed) => new(
        SleepWakeParsers.ParseSleepStates(S3States), SleepWakeParsers.ParseRequests(requests), timers is null ? null : SleepWakeParsers.ParseWakeTimers(timers),
        DeviceWake.ParseArmed(armed), SleepWakeParsers.ParseLastWake(LastWake), events is null ? null : WindowsEventLog.Parse(events, "System"),
        StandbyDrain.Parse(battery ?? BatteryReport()));

    [Fact]
    public void Report_on_the_captured_laptop()
    {
        var r = SleepWakeModule.Build(Facts(), new DateTimeOffset(2026, 11, 19, 12, 0, 0, TimeSpan.Zero));
        Assert.Equal(["states", "drain", "wakes", "devices", "timers", "blockers"], r.Cards.Select(c => c.Id));
        var states = r.Cards.Single(c => c.Id == "states");
        Assert.Equal(("Sleep (S3)", AreaLevel.Ok), (states.Headline, states.Level));
        Assert.Equal(AreaLevel.Neutral, r.Cards.Single(c => c.Id == "drain").Level);

        var wakes = r.Cards.Single(c => c.Id == "wakes");
        Assert.Equal(AreaLevel.Ok, wakes.Level);
        Assert.Single(wakes.Rows);
        Assert.Contains("AMD USB 3.10", wakes.Meta);

        var devices = r.Cards.Single(c => c.Id == "devices");
        Assert.Equal(2, devices.Rows.Count);
        var action = Assert.Single(devices.Rows[0].Actions!);
        Assert.Equal((RemediationKind.DisableDeviceWake, "HID Keyboard Device"), (action.Kind, action.Target));

        var blockers = r.Cards.Single(c => c.Id == "blockers");
        Assert.Equal(AreaLevel.Warning, blockers.Level);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
    }

    [Fact]
    public void Unexpected_wakes_failed_resume_and_heavy_drain_are_flagged()
    {
        var networkWake = WakeEventXml.Replace("AMD USB 3.10 eXtensible Host Controller - 1.10 (Microsoft)", "Intel(R) Wi-Fi 6 AX201 160MHz");
        var failedResume = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Kernel-Power'/><EventID>41</EventID><Level>1</Level><TimeCreated SystemTime='2026-11-18T09:00:00Z'/><Channel>System</Channel></System><EventData><Data Name='BugcheckCode'>0</Data><Data Name='SleepInProgress'>4</Data></EventData></Event>";
        var battery = BatteryReport(Usage("2026-11-18T06:00:00Z", TimeSpan.FromHours(8), "Suspend", 16000)); // 40% in 8 h
        var r = SleepWakeModule.Build(Facts(networkWake + failedResume, battery, NoRequests, armed: "Intel(R) Wi-Fi 6 AX201 160MHz\r\nHID Keyboard Device\r\n"), DateTimeOffset.Now);

        var wakes = r.Cards.Single(c => c.Id == "wakes");
        Assert.Equal(AreaLevel.Error, wakes.Level);
        Assert.Contains(wakes.Rows, x => x.Level == AreaLevel.Warning && x.Values[2].Contains("Wi-Fi"));
        var devices = r.Cards.Single(c => c.Id == "devices");
        Assert.Equal(AreaLevel.Warning, devices.Rows[0].Level);
        Assert.Equal(AreaLevel.Neutral, devices.Rows[1].Level);
        var drain = r.Cards.Single(c => c.Id == "drain");
        Assert.Equal(AreaLevel.Error, drain.Level);
        Assert.StartsWith("5.0% of the battery per hour asleep", drain.Headline);
        Assert.Equal(AreaLevel.Ok, r.Cards.Single(c => c.Id == "blockers").Level);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
    }

    [Fact]
    public void Reads_that_need_administrator_rights_show_as_unread_not_as_problems()
    {
        var r = SleepWakeModule.Build(Facts(requests: null, timers: null), DateTimeOffset.Now);
        Assert.NotNull(r.Cards.Single(c => c.Id == "blockers").ErrorText);
        Assert.NotNull(r.Cards.Single(c => c.Id == "timers").ErrorText);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
    }

    [Fact]
    public void Wakes_named_after_the_usb_controller_are_offered_to_the_keyboard_and_mouse()
    {
        var r = SleepWakeModule.Build(Facts(), DateTimeOffset.Now);
        var devices = r.Cards.Single(c => c.Id == "devices");
        Assert.All(devices.Rows, row => Assert.Equal("Maybe: the USB controller it's on woke the PC 1 time", row.Values[2]));
        Assert.Contains("Windows names the USB controller", devices.Note);
        Assert.True(SleepWakeModule.IsUsbController("AMD USB 3.10 eXtensible Host Controller - 1.10 (Microsoft)"));
        Assert.True(SleepWakeModule.IsUsbController("USB Root Hub (USB 3.0)"));
        Assert.False(SleepWakeModule.IsUsbController("HID Keyboard Device"));
        // A network adapter isn't a USB input device, even when a USB controller woke the PC.
        var withNic = SleepWakeModule.Build(Facts(armed: "Intel(R) Ethernet Controller I225-V\r\n"), DateTimeOffset.Now);
        Assert.Equal("No recent wakes", withNic.Cards.Single(c => c.Id == "devices").Rows[0].Values[2]);
    }

    [Fact]
    public void Sleeps_the_event_log_missed_come_from_the_battery_report()
    {
        // The captured report's 02:16Z suspend ends 34 s after the logged 03:36:07Z wake: the same sleep, listed once.
        var battery = BatteryReport(Usage("2026-11-17T22:12:00Z", TimeSpan.FromSeconds(322), "Suspend", 0, ac: "1"));
        var f = Facts() with { Sleeps = StandbyDrain.ParseSleeps(battery) };
        Assert.Equal(2, f.Sleeps!.Count);
        var wakes = SleepWakeModule.Build(f, new DateTimeOffset(2026, 11, 19, 12, 0, 0, TimeSpan.Zero)).Cards.Single(c => c.Id == "wakes");
        Assert.Equal(2, wakes.Rows.Count);
        Assert.Contains("AMD USB", wakes.Rows[0].Values[2]);
        Assert.Equal(("5 min", "Not recorded in the event log (from the battery report)"), (wakes.Rows[1].Values[1], wakes.Rows[1].Values[2]));
        Assert.Equal("2 wakes, none by a timer or the network", wakes.Headline);
        Assert.Equal(AreaLevel.Ok, wakes.Level);
    }

    [Fact]
    public void Bare_app_reasons_are_explained()
    {
        Assert.Equal("Asked Windows to keep the screen on (the app says \"Electron\")",
            SleepWakeModule.Why(new PowerRequest("DISPLAY", "PROCESS", "\\Device\\HarddiskVolume3\\Antigravity.exe", "Electron")));
        Assert.Equal("Asked Windows not to sleep", SleepWakeModule.Why(new PowerRequest("SYSTEM", "DRIVER", "x", "")));
        Assert.Equal("An audio stream is currently in use.", SleepWakeModule.Why(new PowerRequest("SYSTEM", "DRIVER", "x", "An audio stream is currently in use.")));
    }

    // ---- end to end with a scripted powercfg ----

    [Fact]
    public async Task Module_runs_powercfg_and_reads_the_battery_report_file()
    {
        var battery = BatteryReport(Usage("2026-11-18T06:00:00Z", TimeSpan.FromHours(8), "Suspend", 4000));
        string? reportPath = null;
        var launcher = new ScriptedLauncher((file, args) =>
        {
            if (file.Equals("wevtutil.exe", StringComparison.OrdinalIgnoreCase)) return ScriptedLauncher.Ok(WakeEventXml);
            Assert.Equal("powercfg.exe", file, ignoreCase: true);
            switch (args[0])
            {
                case "/a": return ScriptedLauncher.Ok(S3States);
                case "/requests": return new(1, "This command requires administrator privileges and must be executed from an elevated command prompt.", "");
                case "/waketimers": return ScriptedLauncher.Ok("There are no active wake timers in the system.\r\n");
                case "/devicequery": return ScriptedLauncher.Ok(WakeArmed);
                case "/lastwake": return ScriptedLauncher.Ok(LastWake);
                case "/batteryreport":
                    reportPath = args[args.ToList().IndexOf("/output") + 1];
                    File.WriteAllText(reportPath, battery);
                    return ScriptedLauncher.Ok($"Battery life report saved to file path {reportPath}.");
            }
            return ScriptedLauncher.Fail();
        });
        var module = new SleepWakeModule(new SystemCommandRunner(launcher, isProcessElevated: () => true));
        var report = Assert.IsType<AreaReport>((await module.RefreshAsync(null)).Payload);
        Assert.Equal(AreaLevel.Ok, report.Cards.Single(c => c.Id == "drain").Level);
        Assert.Equal("1.3% of the battery per hour asleep", report.Cards.Single(c => c.Id == "drain").Headline);
        Assert.NotNull(report.Cards.Single(c => c.Id == "blockers").ErrorText);
        Assert.Equal(AreaLevel.Ok, report.Cards.Single(c => c.Id == "timers").Level);
        Assert.NotNull(reportPath);
        Assert.False(File.Exists(reportPath)); // the temporary report is removed
        Assert.Contains("S3 sleep", report.Summary);
    }

    // ---- the fix and its undo ----

    private static (ScriptedLauncher Launcher, List<string> Armed) Powercfg(params string[] armed)
    {
        var list = armed.ToList();
        var launcher = new ScriptedLauncher((file, args) =>
        {
            switch (args[0])
            {
                case "/devicequery": return ScriptedLauncher.Ok(list.Count == 0 ? "NONE\r\n" : string.Join("\r\n", list) + "\r\n");
                case "/devicedisablewake": list.RemoveAll(d => d == args[1]); return ScriptedLauncher.Ok("");
                case "/deviceenablewake": list.Add(args[1]); return ScriptedLauncher.Ok("");
            }
            return ScriptedLauncher.Fail();
        });
        return (launcher, list);
    }

    [Fact]
    public async Task Disable_device_wake_is_journaled_and_undone()
    {
        var (launcher, armed) = Powercfg("HID Keyboard Device", "Intel(R) Ethernet Controller I225-V");
        var j = new MemoryChangeJournal();
        var commands = new SystemCommandRunner(launcher, isProcessElevated: () => true);
        var svc = new RemediationService(commands, new SessionContext(SessionMode.Remote), journal: j);
        // The card's casing doesn't matter; Windows' spelling of the name is what runs and what's journaled.
        var r = await svc.ExecuteAsync(new(RemediationKind.DisableDeviceWake, "Stop it waking the PC", "intel(r) ethernet controller i225-v", "Ethernet"));
        Assert.True(r.Success, r.Message);
        Assert.Equal(["HID Keyboard Device"], armed);
        var c = Assert.Single(j.All);
        Assert.Equal((ChangeKind.DeviceWake, "Intel(R) Ethernet Controller I225-V", "armed"), (c.Kind, c.Target, c.Previous));

        var undo = await new UndoService(j, commands).UndoAllAsync("tech");
        Assert.Equal(1, undo.Succeeded);
        Assert.Contains("Intel(R) Ethernet Controller I225-V", armed);
        Assert.Contains(launcher.Calls, x => x.Args.SequenceEqual(["/deviceenablewake", "Intel(R) Ethernet Controller I225-V"]));
    }

    [Fact]
    public async Task Disable_device_wake_only_touches_a_device_windows_lists_as_wake_armed()
    {
        var (launcher, _) = Powercfg("HID Keyboard Device");
        var j = new MemoryChangeJournal();
        var svc = new RemediationService(new SystemCommandRunner(launcher, isProcessElevated: () => true), journal: j);
        var r = await svc.ExecuteAsync(new(RemediationKind.DisableDeviceWake, "Stop", "Some Other Device"));
        Assert.True(r.Success);
        Assert.Contains("already", r.Message);
        Assert.DoesNotContain(launcher.Calls, x => x.Args[0] == "/devicedisablewake");
        Assert.Empty(j.All);

        Assert.False(svc.Plan(new(RemediationKind.DisableDeviceWake, "Stop", "bad\"name")).Allowed);
        Assert.False(DeviceWake.IsSafeName("two\r\nlines"));
        Assert.True(DeviceWake.IsSafeName("HID-compliant mouse (001)"));
    }

    [Fact]
    public void Workflow_lists_device_wake_fixes_unticked_and_undoable()
    {
        var report = SleepWakeModule.Build(Facts(), DateTimeOffset.Now);
        var fixes = FixCatalog.Build([new DiagnosticResult(SleepWakeModule.ModuleName, report.Status, report.Summary, DateTimeOffset.Now, report)], Array.Empty<MemorySuggestion>());
        var wake = fixes.Where(f => f.Remediation?.Kind == RemediationKind.DisableDeviceWake).ToList();
        Assert.Equal(2, wake.Count);
        Assert.All(wake, f => Assert.False(f.DefaultOn));
        Assert.All(wake, f => Assert.False(f.Slow));
        Assert.All(wake, f => Assert.Equal(UndoSupport.Full, f.Undo));
        Assert.All(wake, f => Assert.Equal("Performance & power", f.Area));
        Assert.Equal("rem:disabledevicewake:hid keyboard device", wake[0].Id);
    }
}
