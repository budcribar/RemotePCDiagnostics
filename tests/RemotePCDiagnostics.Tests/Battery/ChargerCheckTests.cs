using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Tests.Battery;

public sealed class ChargerCheckTests
{
    private static readonly BatteryStatus OnAc = new("BAT1", "LGC", "LiP", "AC Power", 80, 60000, 55000, 120,
        PowerOnline: true, IsCharging: true, IsDischarging: false, ChargeRateMw: 45200);
    private static readonly BatteryStatus OnBattery = OnAc with { State = "Battery Power", PowerOnline = false, IsCharging = false, IsDischarging = true, ChargeRateMw = null, DischargeRateMw = 9000 };
    private static readonly ChargingDevice GoodAdapter = new("Microsoft AC Adapter", "OK", 0);

    private static ChargerReading Reading(IReadOnlyList<ChargingDevice>? adapters = null, IReadOnlyList<ChargingDevice>? usbC = null,
        IReadOnlyList<PowerSourceChange>? changes = null, IReadOnlyList<WinEvent>? limits = null, IReadOnlyList<WinEvent>? slow = null) =>
        new(adapters ?? [GoodAdapter], usbC ?? [], changes ?? [], limits ?? [], slow);

    private static string? Row(AreaCard card, string key) => card.Rows.FirstOrDefault(r => r.Key == key)?.Values[1];

    private static WinEvent Event(DateTimeOffset t, string provider, int id, string message, Dictionary<string, string>? named = null) =>
        new(t, "System", provider, id, 4, message, named?.Values.ToList() ?? [], named ?? []);

    [Fact]
    public void A_desktop_without_a_battery_is_not_applicable()
    {
        var card = ChargerCheck.Card([], Reading());
        Assert.Equal(AreaLevel.Neutral, card.Level);
        Assert.Equal("Not applicable", card.Headline);
        Assert.Equal("Not applicable", Row(card, "state"));
    }

    [Fact]
    public void Plugged_in_and_charging_is_ok_with_the_charge_rate()
    {
        var card = ChargerCheck.Card([OnAc], Reading());
        Assert.Equal(AreaLevel.Ok, card.Level);
        Assert.Equal("OK", Row(card, "state"));
        Assert.Equal("Yes", Row(card, "connected"));
        Assert.Equal("Yes, at 45.2 W", Row(card, "charging"));
        Assert.Equal("Microsoft AC Adapter: working", Row(card, "adapter-device"));
        Assert.Equal("Not reported by Windows", Row(card, "rated"));
    }

    [Fact]
    public void On_battery_asks_to_plug_in_and_judges_nothing()
    {
        var card = ChargerCheck.Card([OnBattery], Reading());
        Assert.Equal(AreaLevel.Neutral, card.Level);
        Assert.Equal("Not connected", card.Headline);
        Assert.Equal("No (running on battery)", Row(card, "connected"));
        Assert.Contains("replug test", card.Note);
    }

    [Fact]
    public void Draining_while_plugged_in_is_too_small_and_fails()
    {
        var draining = OnAc with { IsCharging = false, IsDischarging = true, ChargeRateMw = null, DischargeRateMw = 14500 };
        var card = ChargerCheck.Card([draining], Reading(), dischargingOnAc: true);
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.Equal("Too small", card.Headline);
        Assert.Equal("No, the battery is draining at 14.5 W", Row(card, "charging"));
    }

    [Fact]
    public void Processor_held_back_on_the_charger_is_below_requirement()
    {
        var card = ChargerCheck.Card([OnAc], Reading(), heldBackOnAc: true, perf: new ProcessorPerformanceSample(60, 55));
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Equal("Below requirement", card.Headline);
        Assert.Equal("Held back to 60% while plugged in", Row(card, "perf-limit"));
    }

    [Fact]
    public void An_adapter_with_a_problem_code_is_not_functioning_even_on_battery()
    {
        var card = ChargerCheck.Card([OnBattery], Reading(adapters: [new("Microsoft AC Adapter", "Error", 43)]));
        Assert.Equal(AreaLevel.Error, card.Level);
        Assert.Equal("Not functioning", card.Headline);
        Assert.Contains("Code 43", Row(card, "adapter-device"));
    }

    [Fact]
    public void Slow_charger_events_warn()
    {
        var at = new DateTimeOffset(2026, 11, 26, 9, 0, 0, TimeSpan.Zero);
        var card = ChargerCheck.Card([OnAc], Reading(slow: [Event(at, "Microsoft-Windows-USB-UCMUCSICX", 1, "The charger is a slow charger.")]));
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Equal("Slow charger", card.Headline);
        Assert.StartsWith("1 in the last 7 days", Row(card, "slow-charger"));
    }

    [Fact]
    public void Repeated_brief_power_drops_warn_but_ordinary_unplugging_does_not()
    {
        var t = new DateTimeOffset(2026, 11, 26, 9, 0, 0, TimeSpan.Zero);
        List<PowerSourceChange> Drops(int n) => Enumerable.Range(0, n).SelectMany(i => new[]
            { new PowerSourceChange(t.AddHours(i), false), new PowerSourceChange(t.AddHours(i).AddSeconds(2), true) }).ToList();

        var flaky = ChargerCheck.Card([OnAc], Reading(changes: Drops(ChargerCheck.DropoutsWarn)));
        Assert.Equal(AreaLevel.Warning, flaky.Level);
        Assert.Equal("The charger connection keeps dropping", flaky.Meta);
        Assert.StartsWith("3 in the last 7 days", Row(flaky, "dropouts"));

        // Unplugged for an hour, twice: not a dropout.
        var normal = ChargerCheck.Card([OnAc], Reading(changes: [new(t, false), new(t.AddHours(1), true), new(t.AddHours(2), false), new(t.AddHours(3), true)]));
        Assert.Equal(AreaLevel.Ok, normal.Level);
        Assert.Equal("None in the last 7 days", Row(normal, "dropouts"));
        Assert.StartsWith("4 times", Row(normal, "source-changes"));
    }

    [Fact]
    public void A_usb_c_connector_manager_problem_warns()
    {
        var card = ChargerCheck.Card([OnAc], Reading(usbC: [new("UCM-UCSI ACPI Device", "Error", 10)]));
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Equal(AreaLevel.Warning, card.Rows[0].Level);
        Assert.Contains("Code 10", Row(card, "usbc-device"));
    }

    [Fact]
    public void Without_the_Agent_the_device_rows_say_so()
    {
        var card = ChargerCheck.Card([OnAc], new ChargerReading(null, null, [], [], null, NeedsAgent: true));
        Assert.Equal("Needs the Agent", Row(card, "adapter-device"));
        Assert.Equal(AreaLevel.Ok, card.Level);
    }

    [Fact]
    public async Task Reads_devices_and_events()
    {
        var wmi = new FakeWmi((_, q) => q == ChargerCheck.AdapterSql
            ? new WmiQueryResult(@"root\cimv2", q, [WmiRow.From([new("Name", "Microsoft AC Adapter"), new("Status", "OK"), new("ConfigManagerErrorCode", 0)])])
            : new WmiQueryResult(@"root\cimv2", q, []));
        const string sys = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Power"/><EventID>105</EventID><Level>4</Level><TimeCreated SystemTime="2026-11-05T20:15:20.000Z"/><Channel>System</Channel></System><EventData><Data Name="AcOnline">true</Data><Data Name="RemainingCapacity">39560</Data><Data Name="FullChargeCapacity">39670</Data></EventData></Event>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Power"/><EventID>105</EventID><Level>4</Level><TimeCreated SystemTime="2026-11-05T20:15:19.000Z"/><Channel>System</Channel></System><EventData><Data Name="AcOnline">false</Data></EventData></Event>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Processor-Power"/><EventID>37</EventID><Level>3</Level><TimeCreated SystemTime="2026-11-05T21:00:00.000Z"/><Channel>System</Channel></System><EventData><Data>0</Data></EventData></Event>
            """;
        var launcher = new ScriptedLauncher((file, args) => file == "wevtutil.exe" && args[1] == "System" ? ScriptedLauncher.Ok(sys) : ScriptedLauncher.Fail("The specified channel could not be found."));

        var r = await ChargerCheck.ReadAsync(wmi, new WindowsEventLog(new SystemCommandRunner(launcher)), TestContext.Current.CancellationToken);

        Assert.Equal([GoodAdapter], r.Adapters);
        Assert.Empty(r.UsbC!);
        Assert.Equal([true, false], r.SourceChanges!.Select(c => c.AcOnline));
        Assert.Single(r.FirmwareLimits!);
        Assert.Null(r.SlowCharger);
        Assert.False(r.NeedsAgent);
        Assert.Single(ChargerCheck.Dropouts(r.SourceChanges));
    }

    [Fact]
    public void The_system_query_asks_for_power_source_and_firmware_limit_events()
    {
        var q = ChargerCheck.SystemEventQuery(7);
        Assert.Contains("Microsoft-Windows-Kernel-Power'] and EventID=105", q);
        Assert.Contains("Microsoft-Windows-Kernel-Processor-Power'] and EventID=37", q);
        Assert.Contains("604800000", q);
    }

    private sealed class FakeWmi(Func<string, string, WmiQueryResult> answer) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) => Task.FromResult(answer(wmiNamespace, wql));
    }
}
