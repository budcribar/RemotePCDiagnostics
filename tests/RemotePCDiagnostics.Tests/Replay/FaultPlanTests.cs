using System.Text.Json;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>The fault plan the replay host's UI tests inject faults with (docs/fault-injection.md).</summary>
public sealed class FaultPlanTests
{
    private static readonly MachineRecording Sample = RecordingLibrary.Load("sample/sample-laptop");

    private static string FirstWmi(out string ns, out string wql)
    {
        var c = Sample.Calls.First(c => c.Kind == RecordedCall.WmiKind && c.Rows is { Count: > 0 });
        ns = c.Namespace!;
        wql = c.Query!;
        return c.Query!;
    }

    [Fact]
    public async Task No_rule_gives_the_recorded_answer()
    {
        FirstWmi(out var ns, out var wql);
        var pc = new ReplayedPc(Sample, new FaultPlan());
        var r = await pc.Wmi.QueryAsync(ns, wql);
        Assert.True(r.Success);
        Assert.NotEmpty(r.Rows!);
    }

    [Theory]
    [InlineData(Faults.MissingClass, "InvalidClass (0x80041010): Invalid class")]
    [InlineData(Faults.AccessDenied, "AccessDenied (0x80041003): Access denied")]
    [InlineData(Faults.Disconnected, AgentWmiSource.NotConnected)]
    public async Task Error_faults_fail_with_Windows_wording(string fault, string error)
    {
        FirstWmi(out var ns, out var wql);
        var plan = new FaultPlan([new FaultRule { Source = "wmi", Match = wql.Split(' ').Last(), Fault = fault }]);
        var r = await new ReplayedPc(Sample, plan).Wmi.QueryAsync(ns, wql);
        Assert.Equal(error, r.Error);
        Assert.Single(plan.Hits);
    }

    [Fact]
    public async Task Match_is_case_insensitive_text_and_other_sources_are_untouched()
    {
        FirstWmi(out var ns, out var wql);
        var plan = new FaultPlan([new FaultRule { Source = "registry", Match = "*", Fault = Faults.AccessDenied }]);
        Assert.True((await new ReplayedPc(Sample, plan).Wmi.QueryAsync(ns, wql)).Success);
        plan.Set([new FaultRule { Source = "WMI", Match = wql.ToUpperInvariant(), Fault = Faults.Empty }]);
        Assert.Empty((await new ReplayedPc(Sample, plan).Wmi.QueryAsync(ns, wql)).Rows!);
    }

    [Fact]
    public async Task Once_breaks_only_the_first_answer()
    {
        FirstWmi(out var ns, out var wql);
        var plan = new FaultPlan([new FaultRule { Source = "wmi", Fault = Faults.MissingClass, Once = true }]);
        var pc = new ReplayedPc(Sample, plan);
        Assert.False((await pc.Wmi.QueryAsync(ns, wql)).Success);
        Assert.True((await pc.Wmi.QueryAsync(ns, wql)).Success);
    }

    [Fact]
    public async Task Drop_after_fails_every_WMI_answer_after_the_first_n()
    {
        FirstWmi(out var ns, out var wql);
        var plan = new FaultPlan([new FaultRule { Fault = Faults.DropAfter, After = 1 }]);
        var pc = new ReplayedPc(Sample, plan);
        Assert.True((await pc.Wmi.QueryAsync(ns, wql)).Success);
        Assert.Equal(AgentWmiSource.NotConnected, (await pc.Wmi.QueryAsync(ns, wql)).Error);
        plan.Clear();
        Assert.True((await pc.Wmi.QueryAsync(ns, wql)).Success);
    }

    [Fact]
    public async Task Hang_waits_until_cancelled()
    {
        FirstWmi(out var ns, out var wql);
        var plan = new FaultPlan([new FaultRule { Source = "wmi", Fault = Faults.Hang }]);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new ReplayedPc(Sample, plan).Wmi.QueryAsync(ns, wql, cts.Token));
    }

    [Fact]
    public async Task Value_fault_changes_one_property_of_one_row()
    {
        FirstWmi(out var ns, out var wql);
        var original = (await new ReplayedPc(Sample).Wmi.QueryAsync(ns, wql)).Rows![0];
        var property = original.Values.Keys.First();
        var plan = new FaultPlan([new FaultRule { Source = "wmi", Fault = Faults.Value, Property = property, Value = JsonSerializer.SerializeToElement(-1) }]);
        var row = (await new ReplayedPc(Sample, plan).Wmi.QueryAsync(ns, wql)).Rows![0];
        Assert.Equal(-1, row.Long(property));
        Assert.Equal(original.Values.Count, row.Values.Count);
    }

    [Fact]
    public async Task Recorded_errors_replace_the_standard_wording()
    {
        FirstWmi(out var ns, out var wql);
        var (fault, probeNs, probeQuery) = ErrorProbes.Wmi[0];
        var probe = new RecordedCall { Kind = RecordedCall.WmiKind, Namespace = probeNs, Query = probeQuery, Error = "InvalidClass (0x80041010): Classe non valide" };
        var rec = new MachineRecording { Schema = Sample.Schema, Machine = Sample.Machine, CapturedAt = Sample.CapturedAt, Calls = [.. Sample.Calls, probe] };
        var plan = new FaultPlan([new FaultRule { Source = "wmi", Fault = fault }]);
        var r = await new ReplayedPc(rec, plan).Wmi.QueryAsync(ns, wql);
        Assert.Equal("InvalidClass (0x80041010): Classe non valide", r.Error);
        // A fault the recording has no probe for keeps the standard wording.
        plan.Set([new FaultRule { Source = "wmi", Fault = Faults.AccessDenied }]);
        Assert.Equal("AccessDenied (0x80041003): Access denied", (await new ReplayedPc(rec, plan).Wmi.QueryAsync(ns, wql)).Error);
    }

    [Fact]
    public void Plan_reads_rules_object_or_bare_array()
    {
        var a = FaultPlan.Parse("""{ "rules": [ { "source": "process", "match": "powercfg", "fault": "hang" } ] }""");
        var b = FaultPlan.Parse("""[ { "source": "wmi", "match": "Win32_Battery", "fault": "delay", "ms": 50, "once": true } ]""");
        Assert.Equal(("process", "powercfg", Faults.Hang), (a[0].Source, a[0].Match, a[0].Fault));
        Assert.Equal((50, true), (b[0].Ms, b[0].Once));
    }

    /// <summary>Every whole-answer fault on every answer the battery check asks for: the check still finishes with a result.</summary>
    [Fact]
    public async Task Battery_check_finishes_under_every_whole_answer_fault()
    {
        foreach (var fault in Faults.WholeAnswer)
        {
            var plan = new FaultPlan([new FaultRule { Fault = fault, Ms = 1 }]);
            var result = await new ReplayedPc(Sample, plan).BatteryPower().RefreshAsync(null, CancellationToken.None);
            Assert.NotNull(result);
            Assert.NotEmpty(plan.Hits);
        }
    }
}
