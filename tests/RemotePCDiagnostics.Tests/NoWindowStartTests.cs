using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class NoWindowStartTests
{
    private static string? None(string _) => null;

    [Theory]
    [InlineData("--no-window", true)]
    [InlineData("--NO-WINDOW", true)]
    [InlineData("--unattended", false)]
    public void Requested_by_argument(string arg, bool expected) =>
        Assert.Equal(expected, NoWindowStart.Requested(["-u=https://relay.example", arg], None));

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("0", false)]
    [InlineData("1", true)]
    [InlineData("true", true)]
    [InlineData("On", true)]
    public void Requested_by_environment(string? value, bool expected) =>
        Assert.Equal(expected, NoWindowStart.Requested([], k => k == NoWindowStart.Variable ? value : null));

    [Fact]
    public void Applies_only_to_a_remote_session()
    {
        string[] args = [NoWindowStart.Arg];
        Assert.True(NoWindowStart.Applies(args, None, SessionMode.Remote));
        Assert.False(NoWindowStart.Applies(args, None, SessionMode.Local));
        Assert.False(NoWindowStart.Applies([], None, SessionMode.Remote));
    }

    [Fact]
    public void The_agent_starts_the_app_with_the_switch_the_app_reads()
    {
        var line = RemotePCDiagnostics.Agent.Core.LaunchRules.AppCommandLine(@"C:\App\RemotePCDiagnostics.Host.exe", "https://relay.example", Guid.NewGuid(), hidden: true);
        var args = line.Split(' ').Skip(1);
        Assert.True(NoWindowStart.Applies(args, None, SessionLaunchOptions.Parse(args).Mode));
    }

    [Fact]
    public void Tray_tip_fits_the_notification_area_limit() => Assert.InRange(NoWindowStart.TrayTip.Length, 1, 127);
}
