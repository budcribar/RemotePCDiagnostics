using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Platform;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class NativePowerShellReplacementTests
{
    [Theory]
    [InlineData(0, "Unknown")]
    [InlineData(1, "Disabled")]
    [InlineData(2, "Queued")]
    [InlineData(3, "Ready")]
    [InlineData(4, "Running")]
    [InlineData(99, "Unknown")]
    public void TaskScheduler_FormatsTaskStates_MatchingPowerShellNames(int code, string expected) =>
        Assert.Equal(expected, WindowsTaskScheduler.FormatTaskState(code));

    [Theory]
    [InlineData(null, "\\")]
    [InlineData("", "\\")]
    [InlineData("\\", "\\")]
    [InlineData(@"\Microsoft\XblGameSave\", @"\Microsoft\XblGameSave")]
    [InlineData(@"\Lenovo", @"\Lenovo")]
    public void TaskScheduler_NormalizesFolderPaths(string? input, string expected) =>
        Assert.Equal(expected, WindowsTaskScheduler.NormalizeFolder(input));

    [Theory]
    [InlineData(@"\Microsoft\Windows", @"\Microsoft\Windows\", true)]
    [InlineData(@"\Microsoft\Windows\Defrag", @"\Microsoft\Windows\", true)]
    [InlineData(@"\microsoft\windows\UpdateOrchestrator", @"\Microsoft\Windows\", true)]
    [InlineData(@"\Microsoft\XblGameSave", @"\Microsoft\Windows\", false)]
    [InlineData(@"\", @"\Microsoft\Windows\", false)]
    public void TaskScheduler_ExcludesWindowsFolderSubtree(string folder, string excludedPrefix, bool expected) =>
        Assert.Equal(expected, WindowsTaskScheduler.IsExcludedFolder(folder, excludedPrefix));

    [Theory]
    [InlineData(0, "VGA")]
    [InlineData(4, "DVI")]
    [InlineData(5, "HDMI")]
    [InlineData(6, "Built-in display")]
    [InlineData(10, "External DisplayPort")]
    [InlineData(11, "Built-in display")]
    [InlineData(13, "Built-in display")]
    [InlineData(15, "Miracast")]
    [InlineData(16, "Indirect wired display")]
    [InlineData(2147483648, "Built-in display")]
    [InlineData(999, null)]
    public void DockDeviceReader_FormatsVideoOutputTechnology(long tech, string? expected) =>
        Assert.Equal(expected, WindowsDockDeviceReader.FormatVideoOutputTechnology(tech));

    [Theory]
    [InlineData(@"DISPLAY\DELA0F1\4&12345&0&UID16843008_0", @"DISPLAY\DELA0F1\4&12345&0&UID16843008")]
    [InlineData(@"DISPLAY\LEN40BA\4&12345&0&UID256_12", @"DISPLAY\LEN40BA\4&12345&0&UID256")]
    [InlineData(@"DISPLAY\NO_SUFFIX", @"DISPLAY\NO_SUFFIX")]
    public void DockDeviceReader_NormalizesMonitorInstanceName(string raw, string expected) =>
        Assert.Equal(expected, WindowsDockDeviceReader.NormalizeMonitorInstanceName(raw));

    [Fact]
    public void InventoryProbe_CountsMatchingBloatwarePackageFullNames()
    {
        string[] packages =
        [
            "Clipchamp.Clipchamp_3.0.100_neutral__yxz26nhyzhsrt",
            "Microsoft.BingNews_4.55.62231.0_x64__8wekyb3d8bbwe",
            "Microsoft.Windows.DevHome_0.1800.0.0_x64__8wekyb3d8bbwe",
            "Microsoft.WindowsTerminal_1.21.2361.0_x64__8wekyb3d8bbwe",
            "Microsoft.Paint_11.2404.1020.0_x64__8wekyb3d8bbwe",
        ];

        Assert.Equal(3, InventoryProbe.CountMatchingPackageNames(packages));
    }

    [Fact]
    public void RebootResumeCoordinator_BuildsLimitedPrivilegeTaskXml()
    {
        var now = new DateTimeOffset(2026, 11, 20, 15, 0, 0, TimeSpan.Zero);
        var xmlText = RebootResumeCoordinator.BuildRegisterResumeTaskXml(
            @"C:\Bud's Apps\RemotePCDiagnostics.Host.exe",
            "\"C:\\Bud's Apps\\RemotePCDiagnostics.Host.exe\" --post-reboot",
            @"PC\ann",
            now);

        var xml = XDocument.Parse(xmlText);
        static string? Text(XDocument d, string name) => d.Descendants().FirstOrDefault(e => e.Name.LocalName == name)?.Value;
        Assert.Equal(@"C:\Bud's Apps\RemotePCDiagnostics.Host.exe", Text(xml, "Command"));
        Assert.Equal("--post-reboot", Text(xml, "Arguments"));
        Assert.Equal(@"C:\Bud's Apps", Text(xml, "WorkingDirectory"));
        Assert.Equal("LeastPrivilege", Text(xml, "RunLevel"));
        Assert.Equal(@"PC\ann", Text(xml, "UserId"));
        var end = now.Add(SessionLaunchOptions.PendingRebootMaxAge).LocalDateTime.ToString("s", System.Globalization.CultureInfo.InvariantCulture);
        Assert.Equal(end, Text(xml, "EndBoundary"));
    }
}
