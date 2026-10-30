using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public class RemoteLinkInfoTests
{
    private static readonly Guid Id = Guid.Parse("11111111-2222-3333-4444-555555555555");

    [Theory]
    [InlineData("https://remoteblazor.pagetomovie.com:34544", "https://remoteblazor.pagetomovie.com:34544/app/11111111-2222-3333-4444-555555555555")]
    [InlineData("https://remoteblazor.pagetomovie.com:34544/", "https://remoteblazor.pagetomovie.com:34544/app/11111111-2222-3333-4444-555555555555")]
    [InlineData("https://localhost:5001", "https://localhost:5001/app/11111111-2222-3333-4444-555555555555")]
    [InlineData("http://example.com/relay", "http://example.com/relay/app/11111111-2222-3333-4444-555555555555")]
    [InlineData("http://example.com/relay/?x=1", "http://example.com/relay/app/11111111-2222-3333-4444-555555555555")]
    public void BuildTechnicianUrl_JoinsSafely(string server, string expected) =>
        Assert.Equal(expected, RemoteLinkInfo.BuildTechnicianUrl(new Uri(server), Id).ToString());

    [Fact]
    public void BuildTechnicianUrl_RejectsRelative() =>
        Assert.Throws<ArgumentException>(() => RemoteLinkInfo.BuildTechnicianUrl(new Uri("/x", UriKind.Relative), Id));

    [Fact]
    public void HostAndPort_IncludesDefaultPort() =>
        Assert.Equal("example.com:443", RemoteLinkInfo.HostAndPort(new Uri("https://example.com/")));

    [Fact]
    public void StatusTexts()
    {
        var s = new Uri("https://remoteblazor.pagetomovie.com:34544");
        Assert.Equal("Connecting to server…", RemoteLinkInfo.StatusText(RemoteSessionState.Connecting, s));
        Assert.Equal("Ready. Share this link with the technician:", RemoteLinkInfo.StatusText(RemoteSessionState.Ready, s));
        Assert.Equal("Technician connected", RemoteLinkInfo.StatusText(RemoteSessionState.TechnicianConnected, s));
        var warn = RemoteLinkInfo.StatusText(RemoteSessionState.Unreachable, s);
        Assert.Equal("Couldn't reach the server yet: remoteblazor.pagetomovie.com:34544. Check your internet connection; still trying…", warn);
        Assert.True(RemoteLinkInfo.IsWarning(RemoteSessionState.Unreachable));
        Assert.False(RemoteLinkInfo.IsWarning(RemoteSessionState.Ready));
        Assert.Equal(TimeSpan.FromSeconds(15), RemoteLinkInfo.ReadyTimeout);
    }
}
