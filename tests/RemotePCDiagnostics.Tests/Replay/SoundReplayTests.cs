using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>Sound replayed from recorded PCs (recorder v9 on, which records Core Audio): snapshots and broken answers.</summary>
public sealed class SoundReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(pc.HasAudio, "Recorded before recorder v9: no Core Audio answer.");
        var result = await pc.Sound().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "Sound", result);
    }

    /// <summary>Every whole-answer fault on every source Sound reads: it still finishes with a summary, never a nonsense number.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Every_whole_answer_fault_finishes(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(new ReplayedPc(rec).HasAudio, "Recorded before recorder v9: no Core Audio answer.");
        foreach (var fault in Faults.WholeAnswer)
        {
            var plan = new FaultPlan([new FaultRule { Source = "*", Fault = fault, Ms = 1 }]);
            var r = await new ReplayedPc(rec, plan).Sound().RefreshAsync(null, TestContext.Current.CancellationToken);
            Assert.False(string.IsNullOrWhiteSpace(r.Message), $"{fault}: no summary");
            Assert.NotEmpty(plan.Hits);
            if (r.Payload is AreaReport a) Assert.Empty(DamagedRuns.CommonProblems(a));
        }
    }
}
