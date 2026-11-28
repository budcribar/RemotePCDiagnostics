using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.DeviceSensors;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.Modules.DeviceSensors;

namespace RemotePCDiagnostics.Tests;

/// <summary>Motion, light &amp; presence sensors (#292): the check's report, Device Manager, recording, and the interactive Sensor test.</summary>
public sealed class DeviceSensorsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static DeviceSensor Accel(double x = 0, double y = 0, double z = -1, DeviceSensorStatus state = DeviceSensorStatus.Ready, string? instance = @"HID\VID_8087&PID_0AC2\7&1&0000") =>
        new("a1", DeviceSensorTypes.Accelerometer3D, "Accelerometer", state, "Intel", "ISH", DeviceSensorConnection.Integrated, instance,
            state == DeviceSensorStatus.Ready ? new DeviceSensorReading(x, y, z) : null);

    private static DeviceSensor Light(double lux, DeviceSensorStatus state = DeviceSensorStatus.Ready) =>
        new("l1", DeviceSensorTypes.AmbientLight, "Ambient light sensor", state, "Intel", null, DeviceSensorConnection.Integrated, null, new DeviceSensorReading(Lux: lux));

    private static DeviceSensor Presence(bool present, double mm) =>
        new("p1", DeviceSensorTypes.HumanPresence, "Presence sensor", DeviceSensorStatus.Ready, "Elliptic", null, DeviceSensorConnection.Integrated, null,
            new DeviceSensorReading(Detected: present, DistanceMm: mm));

    private static DeviceSensor Hinge(double deg) =>
        new("h1", DeviceSensorTypes.HingeAngle, null, DeviceSensorStatus.Ready, null, null, DeviceSensorConnection.Integrated, null, new DeviceSensorReading(AngleDegrees: deg));

    private static DeviceSensorSnapshot Snap(params DeviceSensor[] s) => new(s);

    private static readonly SensorDeviceReading NoDevices = new([]);

    private static AreaCard Card(AreaReport r, string id) => r.Cards.Single(c => c.Id == id);

    // ---- Report

    [Fact]
    public void All_ready_sensors_pass_with_their_readings_and_link_to_the_sensor_test()
    {
        var r = DeviceSensorAnalysis.Build(Snap(Accel(0.01, -0.02, -0.99), Light(312), Presence(true, 450), Hinge(110)), NoDevices);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        var card = Card(r, "sensors");
        Assert.Equal("4 sensors, all ready", card.Headline);
        Assert.Equal("interactive?test=devicesensors", card.OpenPage?.Path);
        Assert.Contains(card.Rows, row => row.Values[5] == "X 0.01 g, Y -0.02 g, Z -0.99 g");
        Assert.Contains(card.Rows, row => row.Values[5] == "312 lux");
        Assert.Contains(card.Rows, row => row.Values[5] == "Someone present, 450 mm");
        Assert.Contains(card.Rows, row => row.Values[1] == "Hinge angle" && row.Values[5] == "110°");
        Assert.False(r.NotOnThisPc);
    }

    [Fact]
    public void A_sensor_in_error_fails_and_access_denied_warns()
    {
        var err = DeviceSensorAnalysis.Build(Snap(Accel(state: DeviceSensorStatus.Error), Light(100)), NoDevices);
        Assert.Equal(DiagnosticStatus.Error, err.Status);
        Assert.Equal("1 sensor with an error", Card(err, "sensors").Headline);
        Assert.Equal(AreaLevel.Error, Card(err, "sensors").Rows[0].Level);

        var denied = new DeviceSensor("g1", new Guid("ED4CA589-327A-4FF9-A560-91DA4B48275E"), "GPS", DeviceSensorStatus.AccessDenied);
        var warn = DeviceSensorAnalysis.Build(Snap(denied, Light(100)), NoDevices);
        Assert.Equal(DiagnosticStatus.Warning, warn.Status);
        Assert.Contains("Privacy & security > Location", Card(warn, "sensors").Rows[0].Values[6]);
    }

    [Fact]
    public void A_driver_problem_code_flags_the_sensor_and_the_device()
    {
        var devices = new SensorDeviceReading([
            new SensorDevice("HID Sensor Collection V2", "Sensor", @"HID\VID_8087&PID_0AC2\7&1&0000", 0),
            new SensorDevice("Intel(R) Integrated Sensor Solution", "System", @"PCI\VEN_8086&DEV_51FC\3&11583659&0&90", 10),
            new SensorDevice("ACPI Lid", "System", @"ACPI\PNP0C0D\2&DABA3FF&0", 0),
        ]);
        var r = DeviceSensorAnalysis.Build(Snap(Accel()), devices);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        var dev = Card(r, "devices");
        Assert.Equal("1 sensor device with a driver problem", dev.Headline);
        Assert.Equal(ModuleSlugs.DeviceDrivers, dev.RunCheck?.CheckId);
        Assert.Equal("Cannot start (Code 10)", dev.Rows[0].Values[3]);
        Assert.Contains(dev.Rows, row => row.Values[1] == "Lid switch" && row.Values[3] == "Working");

        // The sensor's own device has a problem: its row says so.
        var bad = new SensorDeviceReading([new SensorDevice("HID Sensor Collection V2", "Sensor", @"HID\VID_8087&PID_0AC2\7&1&0000", 43)]);
        var row = Card(DeviceSensorAnalysis.Build(Snap(Accel()), bad), "sensors").Rows[0];
        Assert.Equal(AreaLevel.Error, row.Level);
        Assert.StartsWith("Driver problem: ", row.Values[6]);
    }

    [Fact]
    public void No_sensors_at_all_is_not_on_this_pc()
    {
        var r = DeviceSensorAnalysis.Build(Snap(), new SensorDeviceReading([new SensorDevice("ACPI Lid", "System", @"ACPI\PNP0C0D\2&X&0", 0)]));
        Assert.True(r.NotOnThisPc);
        Assert.Equal("No motion, light or presence sensors on this PC (lid switch working)", r.Summary);
    }

    [Fact]
    public void Without_the_agent_device_manager_says_needs_the_agent_and_the_sensors_still_show()
    {
        var r = DeviceSensorAnalysis.Build(Snap(Accel()), new SensorDeviceReading([], "Needs the Agent: Device Manager is read through the Agent.", NeedsAgent: true));
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("Needs the Agent", Card(r, "devices").Headline);
        Assert.Equal(AreaLevel.Neutral, Card(r, "devices").Level);
    }

    [Fact]
    public void Unreadable_sensors_and_devices_fail_the_check()
    {
        var r = DeviceSensorAnalysis.Build(DeviceSensorSnapshot.Unavailable("boom"), new SensorDeviceReading([], "Device Manager couldn't be read: x"));
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Contains("boom", r.Summary);
    }

    [Theory]
    [InlineData(@"\\?\HID#VID_8087&PID_0AC2&Col03#7&1a2b&0&0002#{c317c286-c468-4288-9975-d4c4587c442c}\{X}", @"HID\VID_8087&PID_0AC2&COL03\7&1A2B&0&0002")]
    [InlineData(@"\\?\ACPI#ACPI0008#1#{97f115c8-599a-4153-8894-d2d12899918a}", @"ACPI\ACPI0008\1")]
    [InlineData("not a path", null)]
    [InlineData(null, null)]
    public void Device_path_maps_to_the_device_instance(string? path, string? expected) =>
        Assert.Equal(expected, DeviceSensorTypes.InstanceIdFromPath(path));

    [Fact]
    public async Task The_module_reads_sensors_and_device_manager()
    {
        var wmi = new FakeWmi((ns, q) =>
        {
            Assert.Equal(@"root\cimv2", ns);
            Assert.Contains("PNPClass = 'Sensor'", q);
            return new WmiQueryResult(ns, q, [WmiRow.From(new Dictionary<string, object?>
            {
                ["Name"] = "HID Sensor Collection V2", ["PNPClass"] = "Sensor", ["DeviceID"] = @"HID\X\1", ["ConfigManagerErrorCode"] = 0,
            })]);
        });
        var result = await new DeviceSensorsModule(new FixedSource(Snap(Accel(), Light(40))), wmi).RefreshAsync(null, Ct);
        Assert.Equal(DiagnosticStatus.Ok, result.Status);
        var rep = Assert.IsType<AreaReport>(result.Payload);
        Assert.Equal(["sensors", "devices"], rep.Cards.Select(c => c.Id));
    }

    [Fact]
    public async Task The_module_without_the_agent_still_lists_the_sensors()
    {
        var wmi = new FakeWmi((ns, q) => WmiQueryResult.Failed(ns, q, AgentWmiSource.NotConnected));
        var result = await new DeviceSensorsModule(new FixedSource(Snap(Accel())), wmi).RefreshAsync(null, Ct);
        Assert.Equal(DiagnosticStatus.Ok, result.Status);
        Assert.Equal("Needs the Agent", Card((AreaReport)result.Payload!, "devices").Headline);
    }

    // ---- Recording

    [Fact]
    public async Task A_recorded_sensor_read_replays_the_same_answer()
    {
        var recorder = new CallRecorder();
        var live = Snap(Accel(0.1, 0.2, -0.9), Presence(false, 1200), Hinge(95));
        await new RecordingDeviceSensorSource(new FixedSource(live), recorder).ReadAsync(Ct);
        var call = Assert.Single(recorder.Snapshot());
        Assert.Equal(RecordedCall.DeviceSensorsKind, call.Kind);
        var replayed = await new RecordingReplay(recorder.Snapshot()).DeviceSensors.ReadAsync(Ct);
        Assert.Null(replayed.Error);
        Assert.Equal(live.Sensors.Select(s => (s.Kind, s.State, s.Reading)), replayed.Sensors.Select(s => (s.Kind, s.State, s.Reading)));
        Assert.Equal("Not in the recording.", (await new RecordingReplay([]).DeviceSensors.ReadAsync(Ct)).Error);
    }

    [Fact]
    public async Task Faults_on_the_sensor_answer_never_crash_the_check()
    {
        var recorder = new CallRecorder();
        await new RecordingDeviceSensorSource(new FixedSource(Snap(Accel(), Light(80))), recorder).ReadAsync(Ct);
        foreach (var fault in Faults.WholeAnswer)
        {
            var plan = new FaultPlan([new FaultRule { Source = "*", Fault = fault, Ms = 1 }]);
            var source = new FaultingSources(plan).DeviceSensors(new RecordingReplay(recorder.Snapshot()).DeviceSensors);
            var r = await new DeviceSensorsModule(source, new FakeWmi((ns, q) => new WmiQueryResult(ns, q, []))).RefreshAsync(null, Ct);
            Assert.False(string.IsNullOrWhiteSpace(r.Message), $"{fault}: no summary");
            Assert.NotEmpty(plan.Hits);
        }
    }

    // ---- Interactive Sensor test

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = new(2026, 11, 27, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
        public void Advance(double seconds) => Now = Now.AddSeconds(seconds);
    }

    private static async Task<(DeviceSensorTestService Test, Clock Clock)> Started(DeviceSensorSnapshot first)
    {
        var clock = new Clock();
        var t = new DeviceSensorTestService(new FixedSource(first), clock, autoPoll: false);
        await t.StartAsync(Ct);
        return (t, clock);
    }

    [Fact]
    public async Task Tilt_passes_once_every_axis_has_moved_then_light_then_presence()
    {
        var (t, clock) = await Started(Snap(Accel(0, 0, -1), Light(300), Presence(true, 500)));
        Assert.Equal(SensorTestStep.Tilt, t.Current.Current);
        t.Observe(Snap(Accel(0.5, 0, -1), Light(300), Presence(true, 500)));
        Assert.Equal(["Y", "Z"], DeviceSensorTestService.StillAxes(t.Current));
        t.Observe(Snap(Accel(0.5, 0.6, -0.5), Light(300), Presence(true, 500)));
        Assert.Equal(SensorTestStep.Light, t.Current.Current);
        Assert.Equal(SensorStepState.Passed, t.Current.Steps[0].State);

        clock.Advance(2);
        t.Observe(Snap(Accel(), Light(320), Presence(true, 500)));
        t.Observe(Snap(Accel(), Light(170), Presence(true, 500)));
        Assert.Equal(SensorTestStep.Light, t.Current.Current); // 170 is more than half of 320
        t.Observe(Snap(Accel(), Light(12), Presence(true, 500)));
        Assert.Equal(SensorTestStep.Presence, t.Current.Current);

        t.Observe(Snap(Accel(), Light(300), Presence(false, 1500)));
        Assert.False(t.Current.Present);
        Assert.Equal(1500, t.Current.DistanceMm);
        t.ConfirmPresence(true);
        Assert.Equal(SensorTestVerdict.Passed, t.Current.Verdict);
        Assert.Equal("3 of 3 sensors passed", DeviceSensorTestService.Summary(t.Current));
    }

    [Fact]
    public async Task Tilt_fails_after_twenty_seconds_naming_the_still_axes()
    {
        var (t, clock) = await Started(Snap(Accel(0, 0, -1)));
        t.Observe(Snap(Accel(0.4, 0, -1)));
        clock.Advance(DeviceSensorTestService.TiltSeconds);
        t.Observe(Snap(Accel(0.4, 0, -1)));
        var tilt = t.Current.Steps.Single(s => s.Step == SensorTestStep.Tilt);
        Assert.Equal(SensorStepState.Failed, tilt.State);
        Assert.Equal("No change on Y, Z in 20 s.", tilt.Reason);
        Assert.Equal(SensorTestVerdict.Failed, t.Current.Verdict);
    }

    [Fact]
    public async Task A_dark_room_fails_light_with_a_hint_instead_of_passing()
    {
        var (t, clock) = await Started(Snap(Light(3)));
        Assert.Equal(SensorTestStep.Light, t.Current.Current);
        t.Observe(Snap(Light(0.5)));
        Assert.Equal(SensorTestStep.Light, t.Current.Current);
        clock.Advance(DeviceSensorTestService.LightSeconds);
        t.Observe(Snap(Light(0.5)));
        Assert.StartsWith("Too dark to tell", t.Current.Steps.Single(s => s.Step == SensorTestStep.Light).Reason);
    }

    [Fact]
    public async Task Missing_sensors_are_not_supported_and_a_pc_with_none_skips()
    {
        var (t, _) = await Started(Snap());
        Assert.Equal(SensorTestVerdict.Skipped, t.Current.Verdict);
        Assert.All(t.Current.Steps, s => Assert.Equal(SensorStepState.NotSupported, s.State));
        Assert.Equal("This PC has no sensors the test can check", DeviceSensorTestService.Summary(t.Current));
    }

    [Fact]
    public async Task A_sensor_in_error_fails_its_step_without_waiting()
    {
        var (t, _) = await Started(Snap(Accel(state: DeviceSensorStatus.Error), Light(200)));
        Assert.Equal(SensorStepState.Failed, t.Current.Steps[0].State);
        Assert.Equal(SensorTestStep.Light, t.Current.Current);
    }

    [Fact]
    public async Task Skip_doesnt_work_presence_timeout_and_cancel()
    {
        var (t, clock) = await Started(Snap(Accel(), Light(200), Presence(true, 400)));
        t.Skip();
        Assert.Equal(SensorStepState.Skipped, t.Current.Steps[0].State);
        t.DoesNotWork();
        Assert.Equal(SensorStepState.Failed, t.Current.Steps[1].State);
        clock.Advance(DeviceSensorTestService.PresenceSeconds);
        t.Observe(null);
        Assert.Equal("No answer.", t.Current.Steps[2].Reason);
        Assert.Equal(SensorTestVerdict.Failed, t.Current.Verdict);

        var (u, _) = await Started(Snap(Accel()));
        u.Cancel();
        Assert.Equal(SensorTestVerdict.Cancelled, u.Current.Verdict);
        Assert.Equal(SensorStepState.Skipped, u.Current.Steps[0].State);
    }

    [Fact]
    public async Task The_poll_loop_feeds_readings_until_the_test_ends()
    {
        var source = new SequenceSource(Snap(Accel(0, 0, -1)), Snap(Accel(0.5, 0.5, -0.4)));
        using var t = new DeviceSensorTestService(source, poll: TimeSpan.FromMilliseconds(5));
        await t.StartAsync(Ct);
        for (var i = 0; i < 200 && t.IsRunning; i++) await Task.Delay(10, Ct);
        Assert.Equal(SensorTestVerdict.Passed, t.Current.Verdict);
    }

    [Fact]
    public async Task Start_with_a_source_error_skips_and_surfaces_the_read_error()
    {
        var (t, _) = await Started(DeviceSensorSnapshot.Unavailable("Sensor API unavailable"));
        Assert.Equal(SensorTestVerdict.Skipped, t.Current.Verdict);
        Assert.Equal("Sensor API unavailable", t.Current.ReadError);
        Assert.All(t.Current.Steps, s =>
        {
            Assert.Equal(SensorStepState.NotSupported, s.State);
            Assert.Contains("Sensor API unavailable", s.Reason);
        });
        Assert.Equal("The sensors couldn't be read: Sensor API unavailable", DeviceSensorTestService.Summary(t.Current));
    }

    [Fact]
    public async Task Confirm_presence_yes_passes_and_no_fails()
    {
        var (yes, _) = await Started(Snap(Presence(true, 450)));
        Assert.Equal(SensorTestStep.Presence, yes.Current.Current);
        yes.ConfirmPresence(true);
        Assert.True(yes.Current.PresenceConfirmed);
        Assert.Equal(SensorTestVerdict.Passed, yes.Current.Verdict);
        Assert.Equal(SensorStepState.Passed, yes.Current.Steps.Single(s => s.Step == SensorTestStep.Presence).State);
        Assert.Equal("The person saw it follow them.", yes.Current.Steps.Single(s => s.Step == SensorTestStep.Presence).Reason);

        var (no, _) = await Started(Snap(Presence(false, 1200)));
        Assert.Equal(SensorTestStep.Presence, no.Current.Current);
        no.ConfirmPresence(false);
        Assert.False(no.Current.PresenceConfirmed);
        Assert.Equal(SensorTestVerdict.Failed, no.Current.Verdict);
        Assert.Equal(SensorStepState.Failed, no.Current.Steps.Single(s => s.Step == SensorTestStep.Presence).State);
        Assert.Equal("The person said it didn't follow them.", no.Current.Steps.Single(s => s.Step == SensorTestStep.Presence).Reason);
    }

    [Fact]
    public void Duplicate_device_ids_in_device_manager_do_not_crash_build()
    {
        var devices = new SensorDeviceReading([
            new SensorDevice("HID Sensor Collection V2", "Sensor", @"HID\VID_8087&PID_0AC2\7&1&0000", 0),
            new SensorDevice("HID Sensor Collection V2", "Sensor", @"hid\vid_8087&pid_0ac2\7&1&0000", 0),
        ]);
        var r = DeviceSensorAnalysis.Build(Snap(Accel()), devices);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
    }

    // ---- interactive-data

    [Fact]
    public async Task Interactive_data_exports_the_sensor_test_steps_and_measurements()
    {
        var (t, _) = await Started(Snap(Accel(0, 0, -1), Light(300)));
        t.Observe(Snap(Accel(0.5, 0.1, -1), Light(300), Hinge(120)));
        var page = new InteractiveExport.PageState("devicesensors", ["devicesensors"], false, false, false, false);
        var at = DateTimeOffset.Now;
        InteractiveExport.ModuleState NotRun(string slug) => new(new DiagnosticResult(slug, DiagnosticStatus.NotRun, "", at), false);
        using var doc = JsonDocument.Parse(InteractiveExport.ToJson(page, new PhysicalBenchQaSnapshot(), NotRun("Webcam"), NotRun("SpeakerToMic"),
            NotRun("MicToSpeaker"), sensors: t.Current));
        var s = doc.RootElement.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "devicesensors");
        Assert.True(s.GetProperty("open").GetBoolean());
        Assert.Equal("running", s.GetProperty("state").GetString());
        Assert.Equal("tilt", s.GetProperty("currentStep").GetString());
        var m = s.GetProperty("measured");
        Assert.Equal(0.5, m.GetProperty("tiltRangeG").GetProperty("x").GetDouble());
        Assert.Equal(["Y", "Z"], m.GetProperty("stillAxes").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(120, m.GetProperty("hingeDegrees").GetDouble());
        Assert.Equal("not-supported", s.GetProperty("steps")[2].GetProperty("state").GetString());
        Assert.Contains("Tilt", s.GetProperty("instructions").GetString());
        Assert.False(string.IsNullOrEmpty(s.GetProperty("reportIf").GetString()));
    }

    [Fact]
    public void Snapshot_json_round_trips_and_garbage_is_an_error()
    {
        var snap = Snap(Accel(0.1, 0.2, 0.3), Light(5.5), Presence(true, 10), Hinge(180));
        var back = DeviceSensorSnapshot.FromJson(snap.ToJson());
        Assert.Equal(snap.Sensors.Select(s => s.Reading), back.Sensors.Select(s => s.Reading));
        Assert.Equal(snap.Sensors.Select(s => s.Kind), back.Sensors.Select(s => s.Kind));
        Assert.NotNull(DeviceSensorSnapshot.FromJson("{nope").Error);
    }

    private sealed class FixedSource(DeviceSensorSnapshot s) : IDeviceSensorSource
    {
        public Task<DeviceSensorSnapshot> ReadAsync(CancellationToken ct = default) => Task.FromResult(s);
    }

    private sealed class SequenceSource(params DeviceSensorSnapshot[] answers) : IDeviceSensorSource
    {
        private int _i;
        public Task<DeviceSensorSnapshot> ReadAsync(CancellationToken ct = default) =>
            Task.FromResult(answers[Math.Min(Interlocked.Increment(ref _i) - 1, answers.Length - 1)]);
    }

    private sealed class FakeWmi(Func<string, string, WmiQueryResult> answer) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) => Task.FromResult(answer(wmiNamespace, wql));
    }
}
