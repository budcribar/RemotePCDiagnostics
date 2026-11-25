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
}
