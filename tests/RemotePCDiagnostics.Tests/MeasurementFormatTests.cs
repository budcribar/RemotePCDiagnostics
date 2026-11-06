using System.Globalization;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

public sealed class MeasurementFormatTests
{
    private static readonly CultureInfo Us = CultureInfo.GetCultureInfo("en-US");

    [Theory]
    // The drive test result that prompted this: no reading claims more precision than its source has.
    [InlineData("MaxDriveTemperatureC", "66.85", "67")]
    [InlineData("SequentialReadMBps", "1597.757", "1,598")]
    [InlineData("RandomReadIops", "20931.916", "20,932")]
    [InlineData("TestBytes", "1073741824", "1 GB")]
    [InlineData("Hottest CPU", "71.4", "71")]
    [InlineData("DownloadMbps", "94.567", "94.6")]
    [InlineData("UploadMbps", "8.4567", "8.46")]
    [InlineData("AverageMs", "0.012345", "0.0123")]
    [InlineData("Errors", "0", "0")]
    [InlineData("ChunksDone", "123456", "123,456")]
    [InlineData("Ran", "125.4 s", "2 min 5 s")]
    [InlineData("Latency", "26 ms", "26 ms")]
    [InlineData("Mode", "Quick", "Quick")]
    [InlineData("Cards", "3 item(s)", "3 item(s)")]
    public void Display_RoundsToTheSourcesPrecision(string name, string raw, string expected) =>
        Assert.Equal(expected, MeasurementFormat.Display(name, raw, Us));

    [Theory]
    [InlineData("MaxDriveTemperatureC", "66.85", "67")]
    [InlineData("SequentialReadMBps", "1597.757", "1598")]
    [InlineData("TestBytes", "1073741824", "1073741824")]
    [InlineData("Ran", "125.43 s", "125.4 s")]
    [InlineData("Mode", "Quick", "Quick")]
    public void Round_KeepsAPlainNumberForLogsAndCsv(string name, string raw, string expected) =>
        Assert.Equal(expected, MeasurementFormat.Round(name, raw));

    [Fact]
    public void ResultEvent_StoresRoundedMeasurements()
    {
        var report = new DiskSpeedReport(DiskSpeedOutcome.Passed, "C:", 1073741824, TimeSpan.FromSeconds(60),
            1234.5678, 1597.757, 25000.4, 20931.916, 10, 0, 66.85, true);
        var ms = ResultEventLogger.Measurements(report).ToDictionary(m => m.Name, m => m.Value);
        Assert.Equal("67", ms["MaxDriveTemperatureC"]);
        Assert.Equal("1598", ms["SequentialReadMBps"]);
        Assert.Equal("20932", ms["RandomReadIops"]);
        Assert.Equal("1073741824", ms["TestBytes"]);
    }

    [Fact]
    public void Csv_UsesRoundedValues()
    {
        var e = new HistoryEntry(DateTimeOffset.UnixEpoch, "disk-speed", "Drive speed", "OK", "Passed", 60, null,
            [new("MaxDriveTemperatureC", "66.85"), new("SequentialReadMBps", "1597.757")], "PC", "1.0");
        var csv = HistoryQuery.ToCsv([e]);
        Assert.Contains("MaxDriveTemperatureC=67; SequentialReadMBps=1598", csv);
    }
}
