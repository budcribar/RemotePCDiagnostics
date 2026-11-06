using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public class RemoteLinkInfoTests
{
    private static readonly Guid Id = Guid.Parse("11111111-2222-3333-4444-555555555555");

    [Theory]
    [InlineData("https://remoteblazorwebview.com:34544", "https://remoteblazorwebview.com:34544/app/11111111-2222-3333-4444-555555555555")]
    [InlineData("https://remoteblazorwebview.com:34544/", "https://remoteblazorwebview.com:34544/app/11111111-2222-3333-4444-555555555555")]
    [InlineData("https://localhost:5001", "https://localhost:5001/app/11111111-2222-3333-4444-555555555555")]
    [InlineData("http://example.com/relay", "http://example.com/relay/app/11111111-2222-3333-4444-555555555555")]
    [InlineData("http://example.com/relay/?x=1", "http://example.com/relay/app/11111111-2222-3333-4444-555555555555")]
    public void BuildTechnicianUrl_JoinsSafely(string server, string expected) =>
        Assert.Equal(expected, RemoteLinkInfo.BuildTechnicianUrl(new Uri(server), Id).ToString());

    [Theory]
    [InlineData("https://remoteblazorwebview.com:34544", "https://remoteblazorwebview.com:34544/mirror/11111111-2222-3333-4444-555555555555")]
    [InlineData("https://remoteblazorwebview.com:34544/", "https://remoteblazorwebview.com:34544/mirror/11111111-2222-3333-4444-555555555555")]
    public void BuildMirrorUrl_JoinsSafely(string server, string expected) =>
        Assert.Equal(expected, RemoteLinkInfo.BuildMirrorUrl(new Uri(server), Id).ToString());

    [Fact]
    public void BuildTechnicianUrl_RejectsRelative() =>
        Assert.Throws<ArgumentException>(() => RemoteLinkInfo.BuildTechnicianUrl(new Uri("/x", UriKind.Relative), Id));

    [Fact]
    public void HostAndPort_IncludesDefaultPort() =>
        Assert.Equal("example.com:443", RemoteLinkInfo.HostAndPort(new Uri("https://example.com/")));

    [Fact]
    public void StatusTexts()
    {
        var s = new Uri("https://remoteblazorwebview.com:34544");
        Assert.Equal("Connecting to server…", RemoteLinkInfo.StatusText(RemoteSessionState.Connecting, s));
        Assert.Equal("Ready. Share this link with the technician:", RemoteLinkInfo.StatusText(RemoteSessionState.Ready, s));
        Assert.Equal("Technician connected", RemoteLinkInfo.StatusText(RemoteSessionState.TechnicianConnected, s));
        Assert.Equal("Technician connected — watching live below", RemoteLinkInfo.StatusText(RemoteSessionState.TechnicianConnected, s, mirror: true));
        var warn = RemoteLinkInfo.StatusText(RemoteSessionState.Unreachable, s);
        Assert.Equal("Couldn't reach the server yet: remoteblazorwebview.com:34544. Check your internet connection; still trying…", warn);
        Assert.True(RemoteLinkInfo.IsWarning(RemoteSessionState.Unreachable));
        Assert.False(RemoteLinkInfo.IsWarning(RemoteSessionState.Ready));
        Assert.Equal(TimeSpan.FromSeconds(15), RemoteLinkInfo.ReadyTimeout);
    }

    [Fact]
    public void ReverseMirror_SharesTheReadOnlyMirrorLink()
    {
        var s = new Uri("https://remoteblazorwebview.com:34544");
        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        Assert.Equal("https://remoteblazorwebview.com:34544/mirror/7e57c0de-0000-4000-8000-000000000001", RemoteLinkInfo.BuildShareUrl(s, id, reverseMirror: true).ToString());
        Assert.Equal("https://remoteblazorwebview.com:34544/app/7e57c0de-0000-4000-8000-000000000001", RemoteLinkInfo.BuildShareUrl(s, id, reverseMirror: false).ToString());
        Assert.Equal("Demo: you're in control here. Share this view-only link:", RemoteLinkInfo.StatusText(RemoteSessionState.Ready, s, reverseMirror: true));
        Assert.Contains("can watch but not click", RemoteLinkInfo.StatusText(RemoteSessionState.TechnicianConnected, s, reverseMirror: true));
        Assert.Equal("Ready. Share this link with the technician:", RemoteLinkInfo.StatusText(RemoteSessionState.Ready, s));
    }

    [Fact]
    public void ToMirrorMarkup_SwapsOnlyTheAppLink()
    {
        var app = "<div class='card'><h3><a href = 'https://remoteblazorwebview.com:34544/app/7e57c0de-0000-4000-8000-000000000001' > HOST </a></h3></div>";
        var mirror = RemoteLinkInfo.ToMirrorMarkup(app);
        Assert.Contains("/mirror/7e57c0de-0000-4000-8000-000000000001", mirror);
        Assert.DoesNotContain("/app/", mirror);
        Assert.Equal(string.Empty, RemoteLinkInfo.ToMirrorMarkup(null));
    }

    [Fact]
    public void IsServerShutdown_OnlyForTheRelaysShutdownCommand()
    {
        Assert.True(RemoteLinkInfo.IsServerShutdown(new Exception("Server shut down connection")));
        Assert.False(RemoteLinkInfo.IsServerShutdown(new Exception("Connection refused")));
        Assert.False(RemoteLinkInfo.IsServerShutdown(null));
    }
}
