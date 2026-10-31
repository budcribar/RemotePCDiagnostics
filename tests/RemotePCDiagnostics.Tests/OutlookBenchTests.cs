using RemotePCDiagnostics.Core.OutlookBench;

namespace RemotePCDiagnostics.Tests;

public class OutlookBenchTests
{
    [Fact]
    public void Ready_IsStartOfFirstQuietStretchAfterWindow()
    {
        // 500 ms samples: busy until 4 s (window at 2 s), quiet from 4 s on.
        var s = Enumerable.Range(1, 16).Select(i => (i * 500.0, i <= 8 ? 400.0 : 10.0)).ToList();
        Assert.Equal(4000, OutlookBenchMath.ReadyAt(s, windowMs: 2000, intervalMs: 500));
        // Quiet before the window shows doesn't count.
        var early = Enumerable.Range(1, 10).Select(i => (i * 500.0, 5.0)).ToList();
        Assert.Equal(3000, OutlookBenchMath.ReadyAt(early, windowMs: 3000, intervalMs: 500));
        // A blip resets the quiet count; never quiet long enough → null.
        var blippy = Enumerable.Range(1, 10).Select(i => (i * 500.0, i % 2 == 0 ? 300.0 : 5.0)).ToList();
        Assert.Null(OutlookBenchMath.ReadyAt(blippy, 0, 500));
    }

    [Fact]
    public void LoadTimes_ParseWithAndWithoutCountPrefix()
    {
        byte[] B(params int[] v) => v.SelectMany(BitConverter.GetBytes).ToArray();
        Assert.Equal([1200, 900, 1500], OutlookBenchMath.ParseLoadTimes(B(3, 1200, 900, 1500)));
        Assert.Equal([1200, 900], OutlookBenchMath.ParseLoadTimes(B(1200, 900)));
        Assert.Empty(OutlookBenchMath.ParseLoadTimes([1, 2, 3]));
        Assert.Empty(OutlookBenchMath.ParseLoadTimes(null));
        Assert.Equal("0A000000", OutlookBenchMath.Hex(B(10)));
    }

    [Fact]
    public void Summary_AddinCostIsNormalMinusSafe_FirstStartSeparate()
    {
        StartRun R(int i, StartMode m, bool first, double? ms) => new(i, m, first, 1000, ms, 400L << 20, 300L << 20, 50L << 20, 120, 2L << 30, true, null);
        var s = StartSummary.From([R(1, StartMode.Normal, true, 20000), R(2, StartMode.Safe, false, 5000), R(3, StartMode.Normal, false, 9000),
            R(4, StartMode.Safe, false, 6000), R(5, StartMode.Normal, false, 8000), R(6, StartMode.Safe, false, null), R(7, StartMode.Normal, false, 10000)]);
        Assert.Equal(20, s.FirstStartS);
        Assert.Equal(9, s.NormalMedianS);
        Assert.Equal(5.5, s.SafeMedianS);
        Assert.Equal(3.5, s.AddinCostS);
        Assert.Equal(400, s.PeakWorkingSetMb);
        Assert.Null(StartSummary.From([]).NormalMedianS);
    }

    [Fact]
    public void Csv_HeaderMatchesRow_AndQuotes()
    {
        var sys = new SystemProfile("PC1", "LENOVO", "IdeaPad, 15", new("AMD Ryzen 7 5700U", 8, 16, 1801), new(16L << 30, 4L << 30, 1, 2, 3200, 32L << 30),
            new("SAMSUNG", "SSD", "NVMe", 512L << 30, 100L << 30), "Windows 11 Home", "26300", 10.5, 2L << 30, 300, false, "Balanced", ["Microsoft Defender"], "Wi-Fi", 25, 1500, 8000, 0.12);
        var ol = new OutlookProfile(true, "16.0.1", "x64", "Current", false, true, true, 12,
            [new("ost", 12.5, false, null), new("pst", 3, true, null)],
            [new("A", "Teams", "Machine", 3, [1200], "B0040000", false), new("B", "Off", "User", 2, [], null, false)]);
        var r = new BenchResult("1.1.0", DateTimeOffset.UtcNow, sys, ol, [], StartSummary.From([]), []);
        var row = r.ToCsvRow();
        Assert.Contains("\"IdeaPad, 15\"", row);
        Assert.Contains(",12.5,3,True,1,1200,", row); // ost, pst, pst on network, add-ins at start-up, recorded ms
        // Same number of fields as the header (count commas outside quotes).
        var fields = 1; var inQ = false;
        foreach (var c in row) { if (c == '"') inQ = !inQ; else if (c == ',' && !inQ) fields++; }
        Assert.Equal(BenchResult.CsvColumns.Length, fields);
        Assert.Contains("\"Outlook\"", r.ToJson());
    }

    [Fact]
    public void Anonymize_IsStableAndHidesName()
    {
        Assert.Equal(OutlookBenchMath.Anonymize("budslaptop"), OutlookBenchMath.Anonymize("BUDSLAPTOP"));
        Assert.DoesNotContain("BUD", OutlookBenchMath.Anonymize("BUDSLAPTOP"));
        Assert.StartsWith("PC-", OutlookBenchMath.Anonymize("x"));
    }
}
