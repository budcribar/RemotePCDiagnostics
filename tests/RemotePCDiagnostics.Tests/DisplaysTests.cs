using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Display;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Modules.DisplayOutputCheck;
using RemotePCDiagnostics.Modules.Displays;

namespace RemotePCDiagnostics.Tests;

public class DisplaysTests
{
    private const string Gpu = "00000000000127A1";
    private const string Igpu = "0000000000011F00";

    // ---------------------------------------------------------------- EDID

    /// <summary>A 128-byte EDID 1.4 block for a Dell monitor, 2560×1440 at 60 Hz preferred, with a name and a serial descriptor.</summary>
    internal static byte[] DellEdid(bool breakChecksum = false, int extensions = 0)
    {
        var e = new byte[128 * (1 + extensions)];
        byte[] header = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        header.CopyTo(e, 0);
        // "DEL": D=4, E=5, L=12 -> 0 00100 00101 01100 = 0x10AC
        e[8] = 0x10; e[9] = 0xAC;
        e[10] = 0xB1; e[11] = 0xA0; // product 0xA0B1
        e[12] = 0x4C; e[13] = 0x30; e[14] = 0x31; e[15] = 0x32;
        e[17] = 30; // 2020
        e[18] = 1; e[19] = 4;
        e[20] = 0xA5; // digital
        e[21] = 60; e[22] = 34;
        // Detailed timing 2560×1440@59.95: pixel clock 241.5 MHz, h blank 160, v blank 41.
        var clock = 24150;
        e[54] = (byte)(clock & 0xFF); e[55] = (byte)(clock >> 8);
        e[56] = 2560 & 0xFF; e[57] = 160; e[58] = (2560 >> 8) << 4;
        e[59] = 1440 & 0xFF; e[60] = 41; e[61] = (1440 >> 8) << 4;
        Descriptor(e, 72, 0xFC, "DELL U2720Q");
        Descriptor(e, 90, 0xFF, "ABC1234");
        Descriptor(e, 108, 0xFD, "");
        e[126] = (byte)extensions;
        for (var b = 0; b <= extensions; b++)
        {
            if (b > 0) e[b * 128] = 0x02;
            var sum = 0;
            for (var i = 0; i < 127; i++) sum += e[b * 128 + i];
            e[b * 128 + 127] = (byte)((256 - sum % 256) % 256);
        }
        if (breakChecksum) e[127] ^= 0x55;
        return e;
    }

    private static void Descriptor(byte[] e, int at, byte tag, string text)
    {
        e[at + 3] = tag;
        var bytes = System.Text.Encoding.ASCII.GetBytes(text + "\n");
        for (var i = 0; i < 13; i++) e[at + 5 + i] = i < bytes.Length ? bytes[i] : (byte)0x20;
    }

    [Fact]
    public void Edid_is_parsed_with_its_name_serial_size_and_native_mode()
    {
        var e = Edid.Parse(DellEdid(extensions: 1))!;
        Assert.True(e.Valid);
        Assert.Equal(("DEL", 0xA0B1, "DELL U2720Q", "ABC1234"), (e.Manufacturer, e.ProductCode, e.Name, e.Serial));
        Assert.Equal((2560, 1440), (e.PreferredWidth, e.PreferredHeight));
        Assert.InRange(e.PreferredRefreshHz!.Value, 59.9, 60.0);
        Assert.Equal((2, "1.4", 2020, 27.2), (e.Blocks, e.Version, e.Year, e.DiagonalInches));
        Assert.Equal("Dell", Edid.MakerName(e.Manufacturer));
        Assert.Null(e.Problem);
    }

    [Fact]
    public void Damaged_edid_is_reported()
    {
        var bad = Edid.Parse(DellEdid(breakChecksum: true))!;
        Assert.True(bad.HeaderValid);
        Assert.False(bad.ChecksumValid);
        Assert.Contains("checksum", bad.Problem);

        var junk = new byte[128];
        Assert.False(Edid.Parse(junk)!.HeaderValid);
        Assert.False(Edid.Parse([1, 2, 3])!.Valid); // too short
        Assert.Null(Edid.Parse(null));
        Assert.Null(Edid.PnpId(0));
    }

    // ---------------------------------------------------------------- the report

    private static DisplayOutput Laptop(bool primary = true) => new(Igpu, 1, int.MinValue, true, true, "Intel(R) Iris(R) Xe Graphics",
        MonitorName: null, EdidManufacturer: "BOE", EdidProductCode: 0x0A1D, Edid: null,
        Width: 1920, Height: 1200, RefreshHz: 60, PreferredWidth: 1920, PreferredHeight: 1200, MaxWidth: 1920, MaxHeight: 1200, MaxRefreshHz: 60,
        Primary: primary, X: 0, Y: 0, ScalePercent: 150, HdrSupported: false);

    private static DisplayOutput Monitor(string adapter = Gpu, uint target = 4, int tech = 10, byte[]? edid = null, bool noEdid = false,
        int w = 2560, int h = 1440, double hz = 60, double maxHz = 60, bool active = true, int rotation = 0) =>
        new(adapter, target, tech, true, active, "NVIDIA GeForce RTX 3060", ConnectorInstance: 1, MonitorName: "DELL U2720Q",
            MonitorInstanceId: @"DISPLAY\DELA0B1\5&2c03a83e&0&UID4353", EdidManufacturer: "DEL", EdidProductCode: 0xA0B1,
            Edid: noEdid ? null : Edid.Parse(edid ?? DellEdid()),
            Width: active ? w : null, Height: active ? h : null, RefreshHz: active ? hz : null, PreferredWidth: 2560, PreferredHeight: 1440,
            MaxWidth: 3840, MaxHeight: 2160, MaxRefreshHz: active ? maxHz : null, Rotation: rotation, X: active ? 1920 : null, Y: active ? 0 : null,
            ScalePercent: active ? 100 : null, HdrSupported: true, HdrEnabled: false, BitsPerColor: 8);

    private static DisplayOutput Empty(string adapter, uint target, int tech) => new(adapter, target, tech, false, false, adapter == Gpu ? "NVIDIA GeForce RTX 3060" : "Intel(R) Iris(R) Xe Graphics");

    private static DisplaySnapshot Desk(params DisplayOutput[] extra) =>
        new([Laptop(), Empty(Igpu, 2, 5), Empty(Gpu, 3, 5), .. extra.Length > 0 ? extra : [Monitor()]]);

    private static AreaCard Card(AreaReport r, string id) => r.Cards.Single(c => c.Id == id);

    private static AreaReport Build(DisplaySnapshot s, IReadOnlyList<WinEvent>? events = null, DisplayFirmwareReading? firmware = null) =>
        DisplayAnalysis.Build(s, events ?? [], firmware);

    [Fact]
    public void Healthy_desk_passes_and_lists_every_display_and_output()
    {
        var r = Build(Desk());
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        var displays = Card(r, "displays");
        Assert.Equal("2 displays, all working", displays.Headline);
        Assert.Contains("Primary: Built-in screen at 1920×1200 60 Hz, 150% scaling", displays.Meta);
        var dell = displays.Rows.Single(x => x.Values[0] == "DELL U2720Q");
        Assert.Equal(["DELL U2720Q", "DisplayPort (or USB-C)", "2560×1440", "60 Hz", "100%", "Off (supported)", "NVIDIA GeForce RTX 3060", "Working"], dell.Values);
        Assert.Contains("Serial: ABC1234", dell.Detail);
        Assert.Contains("Size: 27.2 in", dell.Detail);
        var outputs = Card(r, "outputs");
        Assert.Equal("4 video outputs on 2 graphics adapters, 2 in use", outputs.Headline);
        Assert.Equal("interactive?test=displayoutputs", outputs.OpenPage!.Path);
        Assert.Contains(outputs.Rows, x => x.Values[1] == "HDMI" && x.Values[3] == "Nothing connected");
        Assert.Equal(AreaLevel.Ok, Card(r, "edid").Level);
        Assert.Equal("2 displays", r.Summary);
    }

    [Fact]
    public void Missing_or_damaged_edid_on_an_external_monitor_is_a_warning()
    {
        var none = Build(Desk(Monitor(noEdid: true)));
        Assert.Equal(DiagnosticStatus.Warning, none.Status);
        Assert.Equal("1 monitor with a missing or damaged EDID", Card(none, "edid").Headline);
        Assert.Contains("no EDID", Card(none, "displays").Rows.Single(x => x.Values[0] == "DELL U2720Q").Values[7]);

        var damaged = Build(Desk(Monitor(edid: DellEdid(breakChecksum: true))));
        Assert.Contains("checksum", Card(damaged, "edid").Rows.Single(x => x.Level == AreaLevel.Warning).Values[4]);
        // A built-in screen without an EDID in the registry isn't flagged.
        Assert.Equal(AreaLevel.Neutral, Card(none, "edid").Rows.Single(x => x.Values[0] == "Built-in screen").Level);
    }

    [Fact]
    public void Below_native_resolution_or_refresh_is_a_warning()
    {
        var low = Build(Desk(Monitor(w: 1920, h: 1080)));
        var row = Card(low, "displays").Rows.Single(x => x.Values[0] == "DELL U2720Q");
        Assert.Equal(AreaLevel.Warning, row.Level);
        Assert.Equal("1920×1080 (native 2560×1440)", row.Values[2]);
        Assert.Equal("Running at 1920×1080, below its native 2560×1440", row.Values[7]);

        var slow = Card(Build(Desk(Monitor(hz: 60, maxHz: 144))), "displays").Rows.Single(x => x.Values[0] == "DELL U2720Q");
        Assert.Equal(("60 Hz (up to 144 Hz)", "Running at 60 Hz, it can do 144 Hz"), (slow.Values[3], slow.Values[7]));

        // Rotated to portrait is the same mode, not below it; 59.94 against 60 is not slower.
        Assert.Equal(DiagnosticStatus.Ok, Build(Desk(Monitor(w: 1440, h: 2560, rotation: 90, hz: 59.94, maxHz: 60))).Status);
    }

    [Fact]
    public void Monitor_seen_but_not_in_use_is_a_warning()
    {
        var r = Build(Desk(Monitor(active: false)));
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal("1 monitor connected but not in use", Card(r, "outputs").Headline);
        Assert.Equal("Not in use", Card(r, "displays").Rows.Single(x => x.Values[0] == "DELL U2720Q").Values[2]);
        Assert.Equal("1 of 2 displays in use · 1 display issue · 1 monitor not in use", r.Summary);
    }

    [Fact]
    public void Clamshell_inactive_internal_display_does_not_warn()
    {
        var lidClosed = Laptop(primary: false) with { Active = false, Width = null, Height = null, RefreshHz = null, X = null, Y = null, ScalePercent = null };
        var external = Monitor() with { Primary = true, X = 0, Y = 0 };
        var r = Build(new DisplaySnapshot([lidClosed, Empty(Igpu, 2, 5), external]));
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(AreaLevel.Ok, Card(r, "displays").Level);
        Assert.Equal(AreaLevel.Ok, Card(r, "outputs").Level);

        // When no other display is active, an inactive internal screen still warns.
        var alone = Build(new DisplaySnapshot([lidClosed, Empty(Igpu, 2, 5)]));
        Assert.Equal(DiagnosticStatus.Warning, alone.Status);
        Assert.Equal(AreaLevel.Warning, Card(alone, "displays").Level);
        Assert.Equal(AreaLevel.Warning, Card(alone, "outputs").Level);
    }

    [Fact]
    public void Native_prefers_driver_preferred_mode_over_base_edid()
    {
        var fiveK = Monitor(w: 5120, h: 2880) with { PreferredWidth = 5120, PreferredHeight = 2880 };
        Assert.Equal((5120, 2880), Displays.Native(fiveK));
        Assert.False(Displays.BelowNative(fiveK));

        var edidOnly = Monitor() with { PreferredWidth = null, PreferredHeight = null };
        Assert.Equal((2560, 1440), Displays.Native(edidOnly));
    }

    [Fact]
    public void Headless_pc_still_reports_its_outputs()
    {
        var r = Build(new DisplaySnapshot([Empty(Gpu, 1, 5), Empty(Gpu, 2, 10), new(Gpu, 9, 17, false, false, "NVIDIA GeForce RTX 3060")]));
        Assert.Equal("No display connected", Card(r, "displays").Headline);
        Assert.Equal(2, Card(r, "outputs").Rows.Count); // an empty virtual output isn't a port
        Assert.DoesNotContain(r.Cards, c => c.Id == "edid");

        var failed = DisplayAnalysis.Build(DisplaySnapshot.Unavailable("no desktop"), null, null);
        Assert.Equal(DiagnosticStatus.Error, failed.Status);
    }

    private static WinEvent Tdr(DateTimeOffset at, string service = "nvlddmkm") =>
        new(at, "System", "Display", 4101, 3, $"Display driver {service} stopped responding and has successfully recovered.", [service], new Dictionary<string, string>());

    [Fact]
    public void Display_driver_resets_are_tied_to_the_adapter_and_its_displays()
    {
        var t = DateTimeOffset.UtcNow;
        var one = Card(Build(Desk(), [Tdr(t.AddDays(-2))]), "resets");
        Assert.Equal(AreaLevel.Neutral, one.Level);
        var row = Assert.Single(one.Rows);
        Assert.Equal(("NVIDIA GeForce RTX 3060", "DELL U2720Q"), (row.Values[2], row.Values[3]));

        var repeated = Build(Desk(), [Tdr(t.AddDays(-2)), Tdr(t.AddDays(-1))]);
        Assert.Equal(AreaLevel.Warning, Card(repeated, "resets").Level);
        Assert.Equal(DiagnosticStatus.Warning, repeated.Status);
        // Events within a few minutes of each other are one reset.
        Assert.Single(Card(Build(Desk(), [Tdr(t.AddMinutes(-2)), Tdr(t.AddMinutes(-1))]), "resets").Rows);
        Assert.Equal(AreaLevel.Error, Card(DisplayAnalysis.Build(Desk(), null, null), "resets").Level);
    }

    // ---------------------------------------------------------------- BIOS

    private static WmiRow Row(params (string Key, object Value)[] values) =>
        new(values.ToDictionary(v => v.Key, v => JsonSerializer.SerializeToElement(v.Value)));

    [Theory]
    [InlineData("HDMI Port", true)]
    [InlineData("DisplayPort Alt Mode", true)]
    [InlineData("Rear VGA Port", true)]
    [InlineData("VideoPortEnable", true)]
    [InlineData("Video Memory Size", false)]
    [InlineData("HDMI Audio", false)]
    [InlineData("Boot from DisplayPort device", false)]
    [InlineData("USB Port", false)]
    [InlineData("", false)]
    public void Bios_video_output_settings_are_recognised(string name, bool expected) =>
        Assert.Equal(expected, DisplayFirmwarePorts.IsOutputSetting(name));

    [Fact]
    public async Task Bios_video_outputs_turned_off_are_named()
    {
        var wmi = new FakeWmi((ns, q) =>
        {
            Assert.Equal(DisplayFirmwarePorts.HpNamespace, ns);
            Assert.Null(WmiQueryPolicy.Problem(ns, q)); // the Agent will run it
            return new(ns, q, [Row(("Name", "HDMI Port"), ("CurrentValue", "Disable")), Row(("Name", "DisplayPort Alt Mode"), ("CurrentValue", "Enable")),
                Row(("Name", "Video Memory Size"), ("CurrentValue", "Disable"))]);
        });
        var f = await DisplayFirmwarePorts.ReadAsync(wmi, new FakeRegistry("HP"), default);
        Assert.Equal(["HDMI Port"], f.Disabled.Select(s => s.Name));
        var card = Card(Build(Desk(), firmware: f), "firmware");
        Assert.Equal(("Video outputs disabled in BIOS: HDMI Port", AreaLevel.Warning), (card.Headline, card.Level));

        var lenovo = await DisplayFirmwarePorts.ReadAsync(new FakeWmi((ns, q) => new(ns, q,
            [Row(("CurrentSetting", "DisplayPortAltMode,Disable;[Optional:Enable,Disable]")), Row(("CurrentSetting", "WakeOnLAN,Enable"))])), new FakeRegistry("LENOVO"), default);
        Assert.Equal(["DisplayPortAltMode"], lenovo.Disabled.Select(s => s.Name));

        var dell = await DisplayFirmwarePorts.ReadAsync(new FakeWmi((ns, q) =>
        {
            Assert.Null(WmiQueryPolicy.Problem(ns, q));
            return new(ns, q, [Row(("AttributeName", "VideoPortEnable"), ("DisplayName", ""), ("CurrentValue", new[] { "Disabled" }))]);
        }), new FakeRegistry("Dell Inc."), default);
        Assert.Equal(["VideoPortEnable"], dell.Disabled.Select(s => s.Name));
    }

    [Fact]
    public async Task No_agent_or_another_maker_is_not_a_failure()
    {
        var noAgent = await DisplayFirmwarePorts.ReadAsync(new FakeWmi((ns, q) => WmiQueryResult.Failed(ns, q, AgentWmiSource.NotConnected)), new FakeRegistry("HP"), default);
        Assert.True(noAgent.NeedsAgent);
        var r = Build(Desk(), firmware: noAgent);
        Assert.Equal(("Needs the Agent", AreaLevel.Neutral), (Card(r, "firmware").Headline, Card(r, "firmware").Level));
        Assert.Equal(DiagnosticStatus.Ok, r.Status);

        var other = await DisplayFirmwarePorts.ReadAsync(new FakeWmi((_, _) => throw new InvalidOperationException("not asked")), new FakeRegistry("ASUSTeK COMPUTER INC."), default);
        Assert.Contains("only HP, Lenovo and Dell", other.Reason);
    }

    // ---------------------------------------------------------------- the module, host query, recording

    [Fact]
    public async Task Module_reads_the_displays_the_log_and_the_bios()
    {
        var host = new FakeHost([Tdr(DateTimeOffset.UtcNow.AddDays(-1)), Tdr(DateTimeOffset.UtcNow.AddDays(-3))]);
        var module = new DisplaysModule(new FakeDisplays(Desk()), new SystemCommandRunner(new NoProcesses()), new FakeWmi((ns, q) => new(ns, q, [])),
            new FakeRegistry("HP"), host);
        var result = await module.RefreshAsync(null);
        var report = Assert.IsType<AreaReport>(result.Payload);
        Assert.Equal(DiagnosticStatus.Warning, result.Status);
        Assert.Equal(2, Card(report, "resets").EventCount);
        Assert.Equal("System", host.Log);
        var d = BuiltInModules.Descriptors.Single(x => x.Id == ModuleIds.Displays);
        Assert.Equal((ModuleKind.Check, ModuleGroups.Hardware, ModuleSlugs.Displays), (d.Kind, d.Group, module.Name));
        Assert.Equal("interactive", BuiltInModules.Descriptors.Single(x => x.Id == ModuleIds.DisplayOutputCheck).Page);
    }

    [Fact]
    public async Task Snapshot_crosses_the_host_query_and_a_recording_unchanged()
    {
        var s = Desk();
        var back = JsonSerializer.SerializeToElement(s, Core.Plugins.HostCapabilities.Json).Deserialize<DisplaySnapshot>(Core.Plugins.HostCapabilities.Json)!;
        Assert.Equal(Build(s).Summary, Build(back).Summary);
        Assert.Equal("ABC1234", back.Outputs.Single(o => o.TargetId == 4).Edid!.Serial);
        Assert.Contains(Core.Plugins.HostCapabilities.DisplayState, Core.Plugins.HostCapabilities.All);
        Assert.NotNull((await new HostDisplaySource(new FakeHost([])).ReadAsync()).Error); // a host without it says so

        var call = RecordedCall.FromDisplay(s);
        var replayed = await new RecordingReplay(new MachineRecording { Calls = [call] }).Display.ReadAsync();
        Assert.Equal(Build(s).Summary, Build(replayed).Summary);
        Assert.Equal("Not in the recording.", (await new RecordingReplay(new MachineRecording { Calls = [] }).Display.ReadAsync()).Error);
        Assert.NotNull(DisplaySnapshot.FromJson("{garbage").Error);
    }

    [Fact]
    public void Scrubber_replaces_the_monitor_serial()
    {
        var scrubbed = new RecordingScrubber("PC1", ["bud"]).Scrub(RecordedCall.FromDisplay(Desk()));
        Assert.DoesNotContain("ABC1234", scrubbed.StdOut);
        Assert.Equal(DiagnosticStatus.Ok, Build(DisplaySnapshot.FromJson(scrubbed.StdOut)).Status);
    }

    [Fact]
    public async Task Faults_reach_the_display_reads()
    {
        var plan = new FaultPlan([new FaultRule { Source = RecordedCall.DisplayKind, Fault = Faults.Error }]);
        var faulted = await new FaultingSources(plan).Display(new FakeDisplays(Desk())).ReadAsync();
        Assert.NotNull(faulted.Error);
        Assert.Equal(DiagnosticStatus.Error, DisplayAnalysis.Build(faulted, null, null).Status);
    }

    // ---------------------------------------------------------------- the interactive output check

    private static DisplaySnapshot Before => Desk(Empty(Gpu, 4, 10));

    [Fact]
    public void Arrivals_are_followed_until_they_become_active_and_unplugs_are_counted()
    {
        var t = DateTimeOffset.UnixEpoch;
        var a = DisplayOutputCheck.Next([], Before, Desk(Monitor(active: false)), t);
        var arrived = Assert.Single(a);
        Assert.Equal(("DELL U2720Q", "DisplayPort (or USB-C)", false), (arrived.Monitor, arrived.Connector, arrived.Active));
        a = DisplayOutputCheck.Next(a, Desk(Monitor(active: false)), Desk(), t.AddSeconds(1));
        Assert.Equal((true, "2560×1440"), (a[0].Active, a[0].Mode)); // Windows extended the desktop onto it
        a = DisplayOutputCheck.Next(a, Desk(), Before, t.AddSeconds(2));
        a = DisplayOutputCheck.Next(a, Before, Desk(), t.AddSeconds(3));
        a = DisplayOutputCheck.Next(a, Desk(), Before, t.AddSeconds(4));
        Assert.True(Assert.Single(a).Flapping);
        Assert.Empty(DisplayOutputCheck.Next([], Desk(), Desk(), t)); // a monitor there from the start isn't an arrival
    }

    [Fact]
    public void Unplugging_port_1_to_test_port_2_preserves_active_state()
    {
        var t = DateTimeOffset.UnixEpoch;
        var empty = new DisplaySnapshot([Laptop(), Empty(Gpu, 4, 10), Empty(Gpu, 5, 5)]);
        var onPort1 = new DisplaySnapshot([Laptop(), Monitor(Gpu, 4, 10), Empty(Gpu, 5, 5)]);
        var onPort2 = new DisplaySnapshot([Laptop(), Empty(Gpu, 4, 10), Monitor(Gpu, 5, 5)]);

        var a = DisplayOutputCheck.Next([], empty, onPort1, t);
        a = DisplayOutputCheck.Next(a, onPort1, empty, t.AddSeconds(1));
        a = DisplayOutputCheck.Next(a, empty, onPort2, t.AddSeconds(2));

        Assert.Equal(2, a.Count);
        Assert.True(a[0].Active);
        Assert.Equal("2560×1440", a[0].Mode);
        Assert.Equal(60, a[0].RefreshHz);
        Assert.Equal(1, a[0].Unplugged);
        Assert.False(a[0].Flapping);
        Assert.True(a[1].Active);
        Assert.Equal("2560×1440", a[1].Mode);
    }

    private static DisplayArrival Arrived(string key, bool? picture = null, string? edid = null, bool low = false) =>
        new(DateTimeOffset.UnixEpoch, key, "Monitor", "HDMI", "GPU", true, "1920×1080", 60, edid, low, picture);

    [Fact]
    public void Output_check_verdicts()
    {
        DisplayOutputCheckReport R(params DisplayArrival[] a) => new(a, [], false);
        Assert.Equal(DiagnosticStatus.Warning, DisplayOutputCheck.Outcome(R(Arrived("a"))).Status); // waiting for answers
        Assert.Contains("Did the picture appear", DisplayOutputCheck.Outcome(R(Arrived("a"))).Message);
        Assert.Equal(DiagnosticStatus.Ok, DisplayOutputCheck.Outcome(R(Arrived("a", true), Arrived("b", true))).Status);
        Assert.Equal(DiagnosticStatus.Error, DisplayOutputCheck.Outcome(R(Arrived("a", true), Arrived("b", false))).Status);
        Assert.Equal(DiagnosticStatus.Warning, DisplayOutputCheck.Outcome(R(Arrived("a", true, edid: "bad"))).Status);
        Assert.Equal(DiagnosticStatus.Warning, DisplayOutputCheck.Outcome(R(Arrived("a", true, low: true))).Status);
        Assert.Equal(DiagnosticStatus.Warning, DisplayOutputCheck.Outcome(R()).Status); // nothing tried isn't a pass
        var never = DisplayOutputCheck.WithNoSignal(R(Arrived("a", true)), "left HDMI", DateTimeOffset.UnixEpoch);
        Assert.Equal(DiagnosticStatus.Error, DisplayOutputCheck.Outcome(never).Status);
        Assert.Contains("never saw the monitor", DisplayOutputCheck.Outcome(never).Message);

        var answered = DisplayOutputCheck.Answer(DisplayOutputCheck.ToResult(R(Arrived("a"))), "a", true)!;
        Assert.Equal(DiagnosticStatus.Ok, answered.Status);
        Assert.Null(DisplayOutputCheck.Answer(DiagnosticResult.NotRun(ModuleSlugs.DisplayOutputCheck), "a", true));
        Assert.Equal(DiagnosticStatus.Error, DisplayOutputCheck.NoSignal(answered, "")!.Status);
    }

    [Fact]
    public async Task Output_check_follows_arrivals_live_and_takes_answers_until_finish()
    {
        var module = new DisplayOutputCheckModule(new SequenceDisplays(Before, Before, Desk()), poll: TimeSpan.FromMilliseconds(5));
        var changed = new TaskCompletionSource();
        module.Changed += (_, _) => changed.TrySetResult();
        var run = module.RefreshAsync(null);
        await changed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(module.Live.Watching);
        var key = Assert.Single(module.Live.Arrivals).Key;
        module.Answer(key, true);
        Assert.True(module.Live.Arrivals[0].PictureAppeared);
        module.Finish();
        var result = await run.WaitAsync(TimeSpan.FromSeconds(10));
        var rep = Assert.IsType<DisplayOutputCheckReport>(result.Payload);
        Assert.False(rep.Watching);
        Assert.Equal(DiagnosticStatus.Ok, result.Status);

        var cancelled = new DisplayOutputCheckModule(new SequenceDisplays(Before), poll: TimeSpan.FromMilliseconds(5));
        var running = cancelled.RefreshAsync(null);
        await Task.Delay(30);
        cancelled.Cancel();
        Assert.True((await running.WaitAsync(TimeSpan.FromSeconds(10))).Cancelled);

        var unreadable = await new DisplayOutputCheckModule(new FakeDisplays(DisplaySnapshot.Unavailable("no desktop"))).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, unreadable.Status);
    }

    [Fact]
    public void Interactive_export_lists_the_output_check()
    {
        var page = new InteractiveExport.PageState("displayoutputs", ["displayoutputs"], false, false, false, false);
        var live = new DisplayOutputCheckReport([Arrived("k1", edid: "No EDID"), Arrived("k2", true)], [new(DateTimeOffset.UnixEpoch, "rear VGA")], true);
        var json = InteractiveExport.ToJson(page, new Core.Workflow.PhysicalBenchQaSnapshot(),
            new(DiagnosticResult.NotRun(ModuleSlugs.Webcam), false), new(DiagnosticResult.NotRun(ModuleSlugs.SpeakerToMic), false),
            new(DiagnosticResult.NotRun(ModuleSlugs.MicToSpeaker), false), null, null,
            new(new(new DiagnosticResult(ModuleSlugs.DisplayOutputCheck, DiagnosticStatus.Running, "", DateTimeOffset.UnixEpoch), false), live));
        using var doc = JsonDocument.Parse(json);
        var t = doc.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "displayoutputs");
        Assert.Equal("in-progress", t.GetProperty("state").GetString());
        var measured = t.GetProperty("measured");
        Assert.Equal(1, measured.GetProperty("unanswered").GetInt32());
        Assert.Equal("rear VGA", measured.GetProperty("noSignal")[0].GetString());
        Assert.Equal("No EDID", measured.GetProperty("ports")[0].GetProperty("edidProblem").GetString());
        Assert.True(measured.GetProperty("ports")[1].GetProperty("pictureAppeared").GetBoolean());
    }

    [Fact]
    public void Interactive_export_waits_until_all_ports_are_answered()
    {
        var page = new InteractiveExport.PageState("displayoutputs", ["displayoutputs"], false, false, false, false);
        var partial = DisplayOutputCheck.ToResult(new DisplayOutputCheckReport([Arrived("k1", true), Arrived("k2", null)], [], false));
        var partialJson = InteractiveExport.ToJson(page, new Core.Workflow.PhysicalBenchQaSnapshot(),
            new(DiagnosticResult.NotRun(ModuleSlugs.Webcam), false), new(DiagnosticResult.NotRun(ModuleSlugs.SpeakerToMic), false),
            new(DiagnosticResult.NotRun(ModuleSlugs.MicToSpeaker), false), null, null,
            new(new(partial, PersonEntered: true), DisplayOutputCheckReport.Empty));
        using (var doc = JsonDocument.Parse(partialJson))
        {
            var t = doc.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "displayoutputs");
            Assert.Equal("waiting-for-person-verdict", t.GetProperty("state").GetString());
            Assert.False(t.TryGetProperty("personOutcome", out _));
            Assert.Equal(1, t.GetProperty("measured").GetProperty("unanswered").GetInt32());
        }

        var complete = DisplayOutputCheck.Answer(partial, "k2", true)!;
        var completeJson = InteractiveExport.ToJson(page, new Core.Workflow.PhysicalBenchQaSnapshot(),
            new(DiagnosticResult.NotRun(ModuleSlugs.Webcam), false), new(DiagnosticResult.NotRun(ModuleSlugs.SpeakerToMic), false),
            new(DiagnosticResult.NotRun(ModuleSlugs.MicToSpeaker), false), null, null,
            new(new(complete, PersonEntered: true), DisplayOutputCheckReport.Empty));
        using (var doc = JsonDocument.Parse(completeJson))
        {
            var t = doc.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "displayoutputs");
            Assert.Equal("done", t.GetProperty("state").GetString());
            Assert.Equal("passed", t.GetProperty("personOutcome").GetString());
            Assert.Equal(0, t.GetProperty("measured").GetProperty("unanswered").GetInt32());
        }
    }

    // ---------------------------------------------------------------- fakes

    private sealed class FakeDisplays(DisplaySnapshot s) : IDisplaySource
    {
        public Task<DisplaySnapshot> ReadAsync(CancellationToken ct = default) => Task.FromResult(s);
    }

    /// <summary>Gives each snapshot in turn, then the last one again.</summary>
    private sealed class SequenceDisplays(params DisplaySnapshot[] all) : IDisplaySource
    {
        private int _next;
        public Task<DisplaySnapshot> ReadAsync(CancellationToken ct = default) => Task.FromResult(all[Math.Min(Interlocked.Increment(ref _next) - 1, all.Length - 1)]);
    }

    private sealed class FakeWmi(Func<string, string, WmiQueryResult> answer) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) => Task.FromResult(answer(wmiNamespace, wql));
    }

    private sealed class FakeRegistry(string manufacturer) : IRegistrySource
    {
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default) =>
            Task.FromResult(new WmiQueryResult(read.Location, read.Describe(), [Row(("SystemManufacturer", manufacturer))]));
    }

    private sealed class NoProcesses : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new ProcessResult(1, "", "no processes in tests"));
    }

    private sealed class FakeHost(IReadOnlyList<WinEvent> events) : Core.Plugins.IHostQueries
    {
        public string? Log { get; private set; }
        public Task<ModuleAvailability> SensorsAvailabilityAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<Core.Sensors.SensorSnapshot> ReadSensorsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<DriveList?> ReadDrivesAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyDictionary<char, RetrimRecord>> ReadRetrimsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<WinEvent>?> QueryEventsAsync(string log, string xpath, int max, CancellationToken ct = default)
        {
            Log = log;
            return Task.FromResult<IReadOnlyList<WinEvent>?>(events);
        }
        public Task<IReadOnlyCollection<string>> ReadEventReviewsAsync(CancellationToken ct = default) => throw new NotSupportedException();
    }
}
