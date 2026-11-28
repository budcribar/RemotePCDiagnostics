using System.Buffers.Binary;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Tests;

/// <summary>Drive self-test (RPCD #279): the drives' pages decoded, the Agent's request allow-list and power restore, and the check
/// replayed from recorded Agent answers (ATA pass, NVMe pass, NVMe failure with LBA, USB bridge, cancel, no Agent).</summary>
public class DriveSelfTestTests
{
    // ---------------------------------------------------------------- the drives' pages, built as the specs lay them out

    internal static string AtaSmart(int execStatus = 0x00, int shortMinutes = 2, int extendedMinutes = 85, bool supported = true)
    {
        var d = new byte[512];
        d[363] = (byte)execStatus;
        d[367] = (byte)(supported ? 0x11 : 0x01);
        d[372] = (byte)shortMinutes;
        if (extendedMinutes > 254)
        {
            d[373] = 0xFF;
            BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(375), (ushort)extendedMinutes);
        }
        else d[373] = (byte)extendedMinutes;
        return Convert.ToHexString(d);
    }

    /// <summary>An ATA self-test log with <paramref name="entries"/> oldest first (test number, status byte, hours, LBA).</summary>
    internal static string AtaLog(params (int Test, int Status, int Hours, uint Lba)[] entries)
    {
        var d = new byte[512];
        d[0] = 1;
        for (var i = 0; i < entries.Length; i++)
        {
            var slot = i % 21;
            var o = 2 + slot * 24;
            d[o] = (byte)entries[i].Test;
            d[o + 1] = (byte)entries[i].Status;
            BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(o + 2), (ushort)entries[i].Hours);
            BinaryPrimitives.WriteUInt32LittleEndian(d.AsSpan(o + 5), entries[i].Lba);
        }
        d[508] = (byte)(entries.Length == 0 ? 0 : (entries.Length - 1) % 21 + 1);
        return Convert.ToHexString(d);
    }

    /// <summary>An NVMe Device Self-test log: the current operation and its percent, then results newest first (code, result, hours, LBA).</summary>
    internal static string NvmeLog(int currentOp = 0, int percent = 0, params (int Code, int Result, long Hours, ulong? Lba, int Segment)[] results)
    {
        var d = new byte[564];
        d[0] = (byte)currentOp;
        d[1] = (byte)percent;
        for (var i = 0; i < 20; i++)
        {
            var o = 4 + i * 28;
            if (i >= results.Length) { d[o] = 0x0F; continue; }
            var r = results[i];
            d[o] = (byte)((r.Code << 4) | r.Result);
            d[o + 1] = (byte)r.Segment;
            d[o + 2] = (byte)(r.Lba is null ? 0 : 0x02);
            BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(o + 4), (ulong)r.Hours);
            if (r.Lba is { } lba) BinaryPrimitives.WriteUInt64LittleEndian(d.AsSpan(o + 16), lba);
        }
        return Convert.ToHexString(d);
    }

    internal static SelfTestDriveAnswer Ata(int disk, string smart, string log, string model = "WDC WD10EZEX-08WN4A0") =>
        new() { Disk = disk, Model = model, Bus = "Sata", Protocol = "ata", SmartData = smart, SelfTestLog = log };

    internal static SelfTestDriveAnswer Nvme(int disk, string log, int extendedMinutes = 12, string model = "Samsung SSD 990 PRO 2TB") =>
        new() { Disk = disk, Model = model, Bus = "Nvme", Protocol = "nvme", NvmeOacs = 0x17, NvmeExtendedMinutes = extendedMinutes, SelfTestLog = log };

    internal static SelfTestDriveAnswer Usb(int disk) => new() { Disk = disk, Model = "Samsung Portable SSD T7", Bus = "Usb" };

    // ---------------------------------------------------------------- decoding

    [Fact]
    public void Ata_smart_data_gives_support_estimates_and_the_running_test()
    {
        var idle = SelfTestDecoder.Decode(Ata(0, AtaSmart(shortMinutes: 1, extendedMinutes: 300), AtaLog()));
        Assert.True(idle.Supported);
        Assert.Equal(SelfTestProtocol.Ata, idle.Protocol);
        Assert.Equal(1, idle.ShortMinutes);
        Assert.Equal(300, idle.ExtendedMinutes); // 0xFF in byte 373: the word at 375 holds it
        Assert.False(idle.IsRunning);

        var running = SelfTestDecoder.Decode(Ata(0, AtaSmart(execStatus: 0xF7), AtaLog()));
        Assert.True(running.IsRunning);
        Assert.Equal(30, running.PercentDone); // 70% remaining

        var none = SelfTestDecoder.Decode(Ata(0, AtaSmart(supported: false), AtaLog()));
        Assert.False(none.Supported);
        Assert.Contains("doesn't support", none.Unsupported);
    }

    [Fact]
    public void Ata_log_reads_newest_first_across_the_wrap_and_keeps_the_failing_lba()
    {
        var entries = Enumerable.Range(1, 23).Select(i => (Test: 1, Status: 0x00, Hours: 1000 + i, Lba: 0u)).ToList();
        entries[^1] = (2, 0x73, 1023, 0x0123456u); // read element failure, 30% remaining
        var log = SelfTestDecoder.AtaLog(Convert.FromHexString(AtaLog([.. entries])));
        Assert.Equal(20, log.Count);
        Assert.Equal(SelfTestOutcome.FailedRead, log[0].Outcome);
        Assert.Equal(SelfTestKind.Extended, log[0].Kind);
        Assert.Equal(0x0123456ul, log[0].FailingLba);
        Assert.Equal(1023, log[0].PowerOnHours);
        Assert.Equal(1022, log[1].PowerOnHours);
        Assert.Null(log[1].FailingLba);
    }

    [Theory]
    [InlineData(0, SelfTestOutcome.Passed)]
    [InlineData(1, SelfTestOutcome.AbortedByHost)]
    [InlineData(2, SelfTestOutcome.InterruptedByReset)]
    [InlineData(3, SelfTestOutcome.FatalError)]
    [InlineData(4, SelfTestOutcome.FailedUnknownElement)]
    [InlineData(5, SelfTestOutcome.FailedElectrical)]
    [InlineData(6, SelfTestOutcome.FailedServo)]
    [InlineData(7, SelfTestOutcome.FailedRead)]
    [InlineData(8, SelfTestOutcome.FailedHandlingDamage)]
    [InlineData(15, SelfTestOutcome.InProgress)]
    [InlineData(11, SelfTestOutcome.Unknown)]
    public void Ata_status_codes_decode(int code, SelfTestOutcome expected) => Assert.Equal(expected, SelfTestDecoder.AtaOutcome(code));

    [Fact]
    public void Nvme_log_reads_the_running_test_results_and_failed_segment_lba()
    {
        var state = SelfTestDecoder.Decode(Nvme(1, NvmeLog(2, 45, (1, 0, 900, null, 0), (2, 7, 850, 0xABCDEFul, 4))));
        Assert.True(state.Supported);
        Assert.Equal(2, state.ShortMinutes);
        Assert.Equal(12, state.ExtendedMinutes);
        Assert.Equal(SelfTestKind.Extended, state.Running);
        Assert.Equal(45, state.PercentDone);
        Assert.Equal(2, state.Log.Count);
        Assert.Equal(SelfTestOutcome.Passed, state.Log[0].Outcome);
        Assert.Equal(SelfTestOutcome.FailedSegment, state.Log[1].Outcome);
        Assert.Equal(0xABCDEFul, state.Log[1].FailingLba);
        Assert.Equal(4, state.Log[1].Segment);

        var noSelfTest = SelfTestDecoder.Decode(Nvme(1, NvmeLog()) with { NvmeOacs = 0x07 });
        Assert.False(noSelfTest.Supported);
    }

    [Theory]
    [InlineData("Usb", "USB bridge")]
    [InlineData("Raid", "RAID")]
    [InlineData("Virtual", "virtual disk")]
    [InlineData("Spaces", "Storage Spaces")]
    public void Drives_on_buses_without_pass_through_say_why(string bus, string reason)
    {
        var s = SelfTestDecoder.Decode(new SelfTestDriveAnswer { Disk = 2, Bus = bus, Model = "X" });
        Assert.False(s.Supported);
        Assert.Contains(reason, s.Unsupported);
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("zz", "")]
    [InlineData("00", "")]
    public void Broken_pages_are_unsupported_not_crashes(string smart, string log)
    {
        var s = SelfTestDecoder.Decode(Ata(0, smart, log));
        Assert.False(s.Supported);
        Assert.Empty(s.Log);
    }

    // ---------------------------------------------------------------- the Agent's allow-list

    [Theory]
    [InlineData(true, "list")]
    [InlineData(true, "status", "0")]
    [InlineData(true, "abort", "3")]
    [InlineData(true, "start", "1", "short")]
    [InlineData(true, "start", "63", "extended")]
    [InlineData(false, "list", "0")]
    [InlineData(false, "start", "1")]
    [InlineData(false, "start", "1", "conveyance")]
    [InlineData(false, "start", "64", "short")]
    [InlineData(false, "start", "-1", "short")]
    [InlineData(false, "status", "C:")]
    [InlineData(false, "status", "0", "1")]
    [InlineData(false, "erase", "0")]
    [InlineData(false)]
    public void Only_the_requests_the_app_sends_are_planned(bool allowed, params string[] args)
    {
        var plan = AgentScripts.Plan(AgentScripts.Of(AgentScripts.DriveSelfTest, args), null, out var refusal);
        Assert.Equal(allowed, plan?.Native is DriveSelfTestAction);
        if (!allowed) Assert.NotNull(refusal);
    }

    // ---------------------------------------------------------------- power settings: held during a test, restored exactly

    private sealed class FakePower : ISelfTestPowerSystem
    {
        public Guid Scheme = Guid.Parse("381b4222-f694-41f0-9685-ff5bb260df2e");
        public readonly Dictionary<(Guid, Guid, bool), uint> Values = new();
        public bool Awake;
        public bool FailWrites;
        public int Applied;

        public FakePower()
        {
            Values[(SelfTestPowerGuard.DiskIdle, Scheme, true)] = 1200;
            Values[(SelfTestPowerGuard.DiskIdle, Scheme, false)] = 600;
            Values[(SelfTestPowerGuard.AhciLinkPower, Scheme, true)] = 3;
            Values[(SelfTestPowerGuard.AhciLinkPower, Scheme, false)] = 4;
        }

        public Guid? ActiveScheme() => Scheme;
        public uint? Read(Guid scheme, Guid subgroup, Guid setting, bool ac) => Values.TryGetValue((setting, scheme, ac), out var v) ? v : null;
        public bool Write(Guid scheme, Guid subgroup, Guid setting, bool ac, uint value)
        {
            if (FailWrites) return false;
            Values[(setting, scheme, ac)] = value;
            return true;
        }
        public void Apply(Guid scheme) => Applied++;
        public void HoldAwake(bool hold) => Awake = hold;
    }

    private static string JournalPath() => Path.Combine(Path.GetTempPath(), "rpcd-selftest-" + Guid.NewGuid().ToString("N"), SelfTestPowerGuard.JournalFile);

    [Fact]
    public void Hold_sets_never_and_active_then_release_restores_the_exact_values()
    {
        var power = new FakePower();
        var before = new Dictionary<(Guid, Guid, bool), uint>(power.Values);
        var path = JournalPath();
        var guard = new SelfTestPowerGuard(power, path);

        Assert.Null(guard.Hold());
        Assert.True(power.Awake);
        Assert.True(File.Exists(path));
        Assert.All(power.Values.Values, v => Assert.Equal(0u, v));
        Assert.Null(guard.Hold()); // a second drive's test: nothing journaled twice
        Assert.Equal(4, guard.Load()!.Values.Count);
        Assert.Equal(1200u, guard.Load()!.Values.Single(v => v.Setting == SelfTestPowerGuard.DiskIdle && v.Ac).Value);

        guard.Release();
        Assert.False(power.Awake);
        Assert.False(File.Exists(path));
        Assert.Equal(before, power.Values);
        Assert.False(guard.Holding);
    }

    [Fact]
    public void After_a_crash_a_new_guard_restores_from_the_journal()
    {
        var power = new FakePower();
        var before = new Dictionary<(Guid, Guid, bool), uint>(power.Values);
        var path = JournalPath();
        new SelfTestPowerGuard(power, path).Hold();

        // The Agent was ended (or the PC restarted) mid-test: a fresh Agent finds the journal.
        var restarted = new SelfTestPowerGuard(power, path);
        Assert.True(restarted.Holding);
        restarted.Release();
        Assert.Equal(before, power.Values);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void A_restore_that_fails_keeps_the_journal_to_try_again()
    {
        var power = new FakePower();
        var path = JournalPath();
        var guard = new SelfTestPowerGuard(power, path);
        guard.Hold();
        power.FailWrites = true;
        guard.Release();
        Assert.True(File.Exists(path));
        power.FailWrites = false;
        guard.Release();
        Assert.False(File.Exists(path));
        Assert.Equal(1200u, power.Values[(SelfTestPowerGuard.DiskIdle, power.Scheme, true)]);
    }

    // ---------------------------------------------------------------- the Agent's action, on fake drives

    private sealed class FakeDevices : ISelfTestDevices
    {
        public readonly Dictionary<int, SelfTestDriveAnswer> Drives = new();
        public readonly List<string> Sent = [];
        public readonly List<int> Reads = [];
        public int DisksCalls;
        public bool DelayRunningOnStart;
        public string? StartError;

        public IReadOnlyList<int> Disks() { DisksCalls++; return [.. Drives.Keys.Order()]; }
        public SelfTestDriveAnswer Read(int disk) { Reads.Add(disk); return Drives.TryGetValue(disk, out var d) ? d : new() { Disk = disk, Error = "missing" }; }
        public string? Start(int disk, SelfTestProtocol protocol, SelfTestKind kind)
        {
            Sent.Add($"start {disk} {protocol} {kind}");
            if (StartError is not null) return StartError;
            if (!DelayRunningOnStart) Drives[disk] = Drives[disk] with { SelfTestLog = NvmeLog((int)kind, 0) };
            return null;
        }
        public string? Abort(int disk, SelfTestProtocol protocol)
        {
            Sent.Add($"abort {disk} {protocol}");
            Drives[disk] = Drives[disk] with { SelfTestLog = NvmeLog(0, 0, (1, 1, 10, null, 0)) };
            return null;
        }
    }

    [Fact]
    public void Agent_start_holds_the_pc_awake_and_the_first_idle_answer_lets_go()
    {
        var devices = new FakeDevices();
        devices.Drives[0] = Nvme(0, NvmeLog());
        var power = new FakePower();
        var agent = new AgentDriveSelfTest(devices, new SelfTestPowerGuard(power, JournalPath()));

        var start = agent.Run(new DriveSelfTestAction("start", 0, SelfTestKind.Short));
        Assert.Equal(0, start.ExitCode);
        Assert.True(SelfTestAnswer.Parse(start.StdOut)!.KeepingAwake);
        Assert.True(power.Awake);
        Assert.Equal(0u, power.Values[(SelfTestPowerGuard.DiskIdle, power.Scheme, true)]);

        // A second start on the same drive is refused while it tests.
        Assert.Equal(1, agent.Run(new DriveSelfTestAction("start", 0, SelfTestKind.Short)).ExitCode);

        devices.Drives[0] = devices.Drives[0] with { SelfTestLog = NvmeLog(0, 0, (1, 0, 11, null, 0)) };
        var status = agent.Run(new DriveSelfTestAction("status", 0, null));
        Assert.False(SelfTestAnswer.Parse(status.StdOut)!.KeepingAwake);
        Assert.False(power.Awake);
        Assert.Equal(1200u, power.Values[(SelfTestPowerGuard.DiskIdle, power.Scheme, true)]);
    }

    [Fact]
    public void Agent_start_does_not_release_power_guard_when_drive_has_not_flipped_running_yet()
    {
        var devices = new FakeDevices { DelayRunningOnStart = true };
        devices.Drives[0] = Nvme(0, NvmeLog());
        var power = new FakePower();
        var agent = new AgentDriveSelfTest(devices, new SelfTestPowerGuard(power, JournalPath()));

        var start = agent.Run(new DriveSelfTestAction("start", 0, SelfTestKind.Short));
        Assert.Equal(0, start.ExitCode);
        var answer = SelfTestAnswer.Parse(start.StdOut)!;
        Assert.False(SelfTestDecoder.Decode(answer.Drives.Single()).IsRunning);
        Assert.True(answer.KeepingAwake);
        Assert.True(power.Awake);
        Assert.Equal(0u, power.Values[(SelfTestPowerGuard.DiskIdle, power.Scheme, true)]);

        // Once a subsequent status poll sees the drive idle, the power guard releases.
        var status = agent.Run(new DriveSelfTestAction("status", 0, null));
        Assert.False(SelfTestAnswer.Parse(status.StdOut)!.KeepingAwake);
        Assert.False(power.Awake);
        Assert.Equal(1200u, power.Values[(SelfTestPowerGuard.DiskIdle, power.Scheme, true)]);
    }

    [Fact]
    public void Agent_status_does_not_rescan_all_disks_while_drive_is_running()
    {
        var devices = new FakeDevices();
        devices.Drives[0] = Nvme(0, NvmeLog());
        devices.Drives[1] = Nvme(1, NvmeLog());
        var power = new FakePower();
        var agent = new AgentDriveSelfTest(devices, new SelfTestPowerGuard(power, JournalPath()));

        Assert.Equal(0, agent.Run(new DriveSelfTestAction("start", 0, SelfTestKind.Short)).ExitCode);
        devices.DisksCalls = 0;
        devices.Reads.Clear();

        var status = agent.Run(new DriveSelfTestAction("status", 0, null));
        Assert.Equal(0, status.ExitCode);
        Assert.True(SelfTestAnswer.Parse(status.StdOut)!.KeepingAwake);
        Assert.Equal(0, devices.DisksCalls);
        Assert.Equal([0], devices.Reads);
    }

    [Fact]
    public void Agent_abort_sends_the_drive_its_abort_and_restores_power()
    {
        var devices = new FakeDevices();
        devices.Drives[0] = Nvme(0, NvmeLog());
        var power = new FakePower();
        var agent = new AgentDriveSelfTest(devices, new SelfTestPowerGuard(power, JournalPath()));
        agent.Run(new DriveSelfTestAction("start", 0, SelfTestKind.Extended));
        var abort = agent.Run(new DriveSelfTestAction("abort", 0, null));
        Assert.Equal(0, abort.ExitCode);
        Assert.Contains("abort 0 Nvme", devices.Sent);
        Assert.False(power.Awake);
        Assert.Equal(4u, power.Values[(SelfTestPowerGuard.AhciLinkPower, power.Scheme, false)]);
    }

    [Fact]
    public void Agent_refuses_unsupported_drives_and_lets_go_when_a_start_fails()
    {
        var devices = new FakeDevices();
        devices.Drives[0] = Usb(0);
        devices.Drives[1] = Nvme(1, NvmeLog());
        devices.StartError = "error 1";
        var power = new FakePower();
        var agent = new AgentDriveSelfTest(devices, new SelfTestPowerGuard(power, JournalPath()));

        var usb = agent.Run(new DriveSelfTestAction("start", 0, SelfTestKind.Short));
        Assert.Equal(1, usb.ExitCode);
        Assert.Contains("USB", usb.StdErr);
        Assert.DoesNotContain(devices.Sent, s => s.StartsWith("start 0"));

        var failed = agent.Run(new DriveSelfTestAction("start", 1, SelfTestKind.Short));
        Assert.Equal(1, failed.ExitCode);
        Assert.False(power.Awake);
        Assert.Equal(1200u, power.Values[(SelfTestPowerGuard.DiskIdle, power.Scheme, true)]);
    }

    // ---------------------------------------------------------------- the check, replayed from recorded Agent answers

    private static RecordedCall Call(string request, params SelfTestDriveAnswer[] drives) =>
        RecordedCall.FromSelfTest(request.Split(' '), new SelfTestReply(new SelfTestAnswer { Drives = [.. drives] }, null));

    private static RecordedCall Refused(string request, string why, bool noAgent = false) =>
        RecordedCall.FromSelfTest(request.Split(' '), SelfTestReply.Failed(why, noAgent));

    private static (DriveSelfTestModule Module, RecordingReplay Replay) Replayed(IEnumerable<RecordedCall> calls, Func<DriveSelfTestModule, Func<TimeSpan, CancellationToken, Task>>? delay = null)
    {
        // The calls go through a recording first, as RPCD_LOG saves them, so the replay reads what a saved recording holds.
        var saved = calls.Select(c => System.Text.Json.JsonSerializer.Deserialize<RecordedCall>(System.Text.Json.JsonSerializer.Serialize(c, MachineRecording.Json), MachineRecording.Json)!).ToList();
        var replay = new RecordingReplay(saved);
        DriveSelfTestModule? module = null;
        Func<TimeSpan, CancellationToken, Task> wait = (_, ct) => { ct.ThrowIfCancellationRequested(); return Task.CompletedTask; };
        module = new DriveSelfTestModule(replay.SelfTest, delay: (t, ct) => (delay?.Invoke(module!) ?? wait)(t, ct));
        return (module, replay);
    }

    private static async Task<AreaReport> RunAsync(DriveSelfTestModule module)
    {
        var r = await module.RefreshAsync(null);
        return Assert.IsType<AreaReport>(r.Payload);
    }

    [Fact]
    public async Task Ata_short_test_passes()
    {
        var idleLog = AtaLog((1, 0x00, 500, 0));
        var (module, replay) = Replayed([
            Call("list", Ata(0, AtaSmart(), idleLog)),
            Call("start 0 short", Ata(0, AtaSmart(0xF9), idleLog)),
            Call("status 0", Ata(0, AtaSmart(0xF5), idleLog)),
            Call("status 0", Ata(0, AtaSmart(0x00), AtaLog((1, 0x00, 500, 0), (1, 0x00, 512, 0)))),
        ]);
        var report = await RunAsync(module);
        Assert.Empty(replay.Misses);
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        var card = Assert.Single(report.Cards);
        Assert.Equal("disk-0", card.Id);
        Assert.Equal(AreaLevel.Ok, card.Level);
        Assert.Contains("Short self-test passed", card.Headline);
        Assert.Equal("This run", card.Rows[0].Values[0]);
        Assert.Equal("512", card.Rows[0].Values[3]);
        Assert.Contains("short about 2 min", card.Meta);
        Assert.Contains("extended about 1 h 25 min", card.Meta);
    }

    [Fact]
    public async Task Nvme_extended_test_passes_and_reports_progress()
    {
        var (module, replay) = Replayed([
            Call("list", Nvme(0, NvmeLog(0, 0, (1, 0, 100, null, 0)))),
            Call("start 0 extended", Nvme(0, NvmeLog(2, 0, (1, 0, 100, null, 0)))),
            Call("status 0", Nvme(0, NvmeLog(2, 50, (1, 0, 100, null, 0)))),
            Call("status 0", Nvme(0, NvmeLog(0, 0, (2, 0, 101, null, 0), (1, 0, 100, null, 0)))),
        ]);
        module.Mode = SelfTestKind.Extended;
        var updates = new List<DiagnosticResult>();
        module.Updated += (_, r) => updates.Add(r);
        var report = await RunAsync(module);
        Assert.Empty(replay.Misses);
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        Assert.Contains("Extended self-test passed", report.Summary);
        Assert.Contains(updates, u => u.Status == DiagnosticStatus.Running && u.Message.Contains("50% done"));
        Assert.Equal(2, report.Cards[0].Rows.Count);
    }

    [Fact]
    public async Task Nvme_failure_with_lba_fails_and_points_to_drive_health()
    {
        var (module, _) = Replayed([
            Call("list", Nvme(1, NvmeLog())),
            Call("start 1 short", Nvme(1, NvmeLog(1, 0))),
            Call("status 1", Nvme(1, NvmeLog(0, 0, (1, 7, 4321, 987654ul, 3)))),
        ]);
        var report = await RunAsync(module);
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        var card = report.Cards.Single();
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.Contains("segment 3", card.Headline);
        Assert.Contains("LBA 987654", card.Headline);
        Assert.Equal(ModuleSlugs.DriveHealth, card.RunCheck?.CheckId);
        Assert.Contains("Back up", card.Note);
        Assert.Equal("987654", card.Rows[0].Values[4]);
    }

    [Fact]
    public async Task Ata_read_element_failure_shows_the_failing_lba()
    {
        var (module, _) = Replayed([
            Call("list", Ata(0, AtaSmart(), AtaLog())),
            Call("start 0 short", Ata(0, AtaSmart(0xF9), AtaLog())),
            Call("status 0", Ata(0, AtaSmart(0x70), AtaLog((1, 0x70, 77, 123456u)))),
        ]);
        var card = (await RunAsync(module)).Cards.Single();
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.Contains("read element", card.Headline);
        Assert.Contains("LBA 123456", card.Headline);
    }

    [Fact]
    public async Task A_usb_bridge_alone_is_not_supported_and_skipped()
    {
        var (module, replay) = Replayed([Call("list", Usb(0))]);
        var report = await RunAsync(module);
        Assert.Empty(replay.Misses);
        Assert.True(report.NotOnThisPc);
        Assert.Equal(AreaLevel.Neutral, report.Cards.Single().Level);
        Assert.Contains("Not supported", report.Cards.Single().Headline);
        Assert.Contains("USB", report.Summary);
    }

    [Fact]
    public async Task Usb_drive_beside_a_tested_drive_stays_not_supported()
    {
        var (module, _) = Replayed([
            Call("list", Nvme(0, NvmeLog()), Usb(1)),
            Call("start 0 short", Nvme(0, NvmeLog(1, 0))),
            Call("status 0", Nvme(0, NvmeLog(0, 0, (1, 0, 5, null, 0)))),
        ]);
        var report = await RunAsync(module);
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        Assert.Equal(2, report.Cards.Count);
        Assert.Contains("Not supported", report.Cards[1].Headline);
        Assert.DoesNotContain("Not supported", report.Summary);
    }

    [Fact]
    public async Task Cancel_aborts_the_test_on_the_drive()
    {
        var polls = 0;
        var (module, replay) = Replayed([
            Call("list", Nvme(0, NvmeLog())),
            Call("start 0 extended", Nvme(0, NvmeLog(2, 0))),
            Call("status 0", Nvme(0, NvmeLog(2, 10))),
            Call("abort 0", Nvme(0, NvmeLog(0, 0, (2, 1, 9, null, 0)))),
        ], m => (_, ct) =>
        {
            if (++polls == 2) m.Cancel();
            ct.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        });
        module.Mode = SelfTestKind.Extended;
        var result = await module.RefreshAsync(null);
        Assert.True(result.Cancelled);
        Assert.Contains(RecordingReplay.SelfTestKey("abort 0"), replay.Asked);
        Assert.Contains("cancelled", result.Message);
    }

    [Fact]
    public async Task Without_the_agent_it_is_skipped_not_failed()
    {
        var (module, _) = Replayed([Refused("list", "The Agent isn't connected.", noAgent: true)]);
        var report = await RunAsync(module);
        Assert.True(report.NotOnThisPc);
        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.StartsWith("Needs the Agent", report.Summary);

        var store = new DriveSelfTestModule(new RecordingReplay([]).SelfTest, noAgent: () => true);
        Assert.True((await RunAsync(store)).NotOnThisPc);
    }

    [Fact]
    public async Task An_interrupted_test_is_a_warning_to_run_again()
    {
        var (module, _) = Replayed([
            Call("list", Nvme(0, NvmeLog())),
            Call("start 0 short", Nvme(0, NvmeLog(1, 0))),
            Call("status 0", Nvme(0, NvmeLog(0, 0, (1, 2, 5, null, 0)))),
        ]);
        var card = (await RunAsync(module)).Cards.Single();
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Contains("run it again", card.Headline);
    }

    [Fact]
    public async Task A_pass_with_a_past_failure_in_the_log_is_a_warning()
    {
        var (module, _) = Replayed([
            Call("list", Nvme(0, NvmeLog(0, 0, (2, 7, 40, 55ul, 1)))),
            Call("start 0 short", Nvme(0, NvmeLog(1, 0, (2, 7, 40, 55ul, 1)))),
            Call("status 0", Nvme(0, NvmeLog(0, 0, (1, 0, 41, null, 0), (2, 7, 40, 55ul, 1)))),
        ]);
        var card = (await RunAsync(module)).Cards.Single();
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Contains("passed, but", card.Headline);
    }

    [Fact]
    public async Task A_test_already_running_is_followed_not_restarted()
    {
        var (module, replay) = Replayed([
            Call("list", Nvme(0, NvmeLog(2, 80))),
            Call("status 0", Nvme(0, NvmeLog(0, 0, (2, 0, 3, null, 0)))),
        ]);
        var report = await RunAsync(module);
        Assert.Empty(replay.Misses);
        Assert.DoesNotContain(replay.Asked, k => k.StartsWith(RecordingReplay.SelfTestKey("start")));
        Assert.Equal(AreaLevel.Ok, report.Cards.Single().Level);
        Assert.Contains("started earlier", report.Cards.Single().Headline);
    }

    [Fact]
    public async Task Only_the_chosen_drives_are_tested()
    {
        var (module, replay) = Replayed([
            Call("list", Nvme(0, NvmeLog()), Nvme(1, NvmeLog())),
            Call("start 1 short", Nvme(1, NvmeLog(1, 0))),
            Call("status 1", Nvme(1, NvmeLog(0, 0, (1, 0, 5, null, 0)))),
        ]);
        module.Disks = new HashSet<int> { 1 };
        var report = await RunAsync(module);
        Assert.Empty(replay.Misses);
        Assert.Equal("Not tested this time", report.Cards[0].Headline);
        Assert.Equal(AreaLevel.Ok, report.Cards[1].Level);
    }

    [Fact]
    public async Task A_start_refused_on_every_drive_is_couldnt_run()
    {
        var (module, _) = Replayed([
            Call("list", Nvme(0, NvmeLog())),
            Refused("start 0 short", "Windows didn't pass the command to the drive (error 1)"),
        ]);
        var report = await RunAsync(module);
        Assert.NotNull(report.CouldNotRunReason);
        Assert.Contains("error 1", report.CouldNotRunReason);
    }

    [Fact]
    public async Task Full_20_entry_log_completing_within_same_power_on_hour_reports_result()
    {
        var fullLogEntries = Enumerable.Repeat((Code: 1, Result: 0, Hours: 500L, Lba: (ulong?)null, Segment: 0), 20).ToArray();
        var (module, replay) = Replayed([
            Call("list", Nvme(0, NvmeLog(0, 0, fullLogEntries))),
            Call("start 0 short", Nvme(0, NvmeLog(1, 0, fullLogEntries))),
            Call("status 0", Nvme(0, NvmeLog(1, 50, fullLogEntries))),
            Call("status 0", Nvme(0, NvmeLog(0, 0, fullLogEntries))),
        ]);
        var report = await RunAsync(module);
        Assert.Empty(replay.Misses);
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        var card = Assert.Single(report.Cards);
        Assert.Equal(AreaLevel.Ok, card.Level);
        Assert.Contains("Short self-test passed", card.Headline);
        Assert.DoesNotContain("without a result", card.Headline);
        Assert.Equal("This run", card.Rows[0].Values[0]);
    }

    [Fact]
    public async Task Timed_out_run_is_marked_lost_and_sends_abort()
    {
        var clock = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var calls = new[]
        {
            Call("list", Nvme(0, NvmeLog())),
            Call("start 0 short", Nvme(0, NvmeLog(1, 0))),
            Call("status 0", Nvme(0, NvmeLog(1, 10))),
            Call("abort 0", Nvme(0, NvmeLog(0, 0, (1, 1, 1, null, 0)))),
        };
        var saved = calls.Select(c => System.Text.Json.JsonSerializer.Deserialize<RecordedCall>(System.Text.Json.JsonSerializer.Serialize(c, MachineRecording.Json), MachineRecording.Json)!).ToList();
        var replay = new RecordingReplay(saved);
        var module = new DriveSelfTestModule(
            replay.SelfTest,
            delay: (_, ct) =>
            {
                ct.ThrowIfCancellationRequested();
                clock = clock.AddHours(2);
                return Task.CompletedTask;
            },
            now: () => clock);

        var report = await RunAsync(module);
        Assert.Empty(replay.Misses);
        Assert.Contains(RecordingReplay.SelfTestKey("abort 0"), replay.Asked);
        var card = Assert.Single(report.Cards);
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Contains("didn't report finishing", card.Headline);
    }

    [Fact]
    public void Drive_self_test_is_on_demand_and_never_in_run_all()
    {
        var d = BuiltInModules.Descriptors.Single(x => x.Id == ModuleIds.DriveSelfTest);
        Assert.Equal(ModuleKind.OnDemand, d.Kind);
        Assert.Equal(ModuleSlugs.DriveSelfTest, d.Slug);
        var module = new DriveSelfTestModule(new RecordingReplay([]).SelfTest);
        Assert.False(module.IncludeInRunAll);
        Assert.IsAssignableFrom<ICancellableScan>(module);
    }
}
