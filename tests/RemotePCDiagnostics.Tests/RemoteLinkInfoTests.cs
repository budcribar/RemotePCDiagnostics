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
    public void BuildRemoteUserUrl_JoinsSafely(string server, string expected) =>
        Assert.Equal(expected, RemoteLinkInfo.BuildRemoteUserUrl(new Uri(server), Id).ToString());

    [Theory]
    [InlineData("https://remoteblazorwebview.com:34544", "https://remoteblazorwebview.com:34544/mirror/11111111-2222-3333-4444-555555555555")]
    [InlineData("https://remoteblazorwebview.com:34544/", "https://remoteblazorwebview.com:34544/mirror/11111111-2222-3333-4444-555555555555")]
    public void BuildMirrorUrl_JoinsSafely(string server, string expected) =>
        Assert.Equal(expected, RemoteLinkInfo.BuildMirrorUrl(new Uri(server), Id).ToString());

    [Fact]
    public void BuildRemoteUserUrl_RejectsRelative() =>
        Assert.Throws<ArgumentException>(() => RemoteLinkInfo.BuildRemoteUserUrl(new Uri("/x", UriKind.Relative), Id));

    [Fact]
    public void HostAndPort_IncludesDefaultPort() =>
        Assert.Equal("example.com:443", RemoteLinkInfo.HostAndPort(new Uri("https://example.com/")));

    [Fact]
    public void StatusTexts()
    {
        var s = new Uri("https://remoteblazorwebview.com:34544");
        Assert.Equal("Connecting to server…", RemoteLinkInfo.StatusText(RemoteSessionState.Connecting, s));
        Assert.Equal("Ready. Share this link:", RemoteLinkInfo.StatusText(RemoteSessionState.Ready, s));
        Assert.Equal("Remote user connected", RemoteLinkInfo.StatusText(RemoteSessionState.RemoteUserConnected, s));
        Assert.Equal("Remote user disconnected", RemoteLinkInfo.StatusText(RemoteSessionState.Disconnected, s));
        var warn = RemoteLinkInfo.StatusText(RemoteSessionState.Unreachable, s);
        Assert.Equal("Couldn't reach the server yet: remoteblazorwebview.com:34544. Check your internet connection; still trying…", warn);
        Assert.True(RemoteLinkInfo.IsWarning(RemoteSessionState.Unreachable));
        Assert.False(RemoteLinkInfo.IsWarning(RemoteSessionState.Ready));
        Assert.Equal(TimeSpan.FromSeconds(15), RemoteLinkInfo.ReadyTimeout);
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

    [Fact]
    public void TheOwnersPage_IsTheAppPageWithTheOwnerRole()
    {
        var server = new Uri("https://remoteblazorwebview.com:34544");
        var page = RemoteLinkInfo.WithOwnerRole(RemoteLinkInfo.BuildRemoteUserUrl(server, Id));
        Assert.Equal($"https://remoteblazorwebview.com:34544/app/{Id}?role=owner", page.ToString());
    }

    [Fact]
    public void AnUnattendedOwnersPage_AsksForControlToGoToTheRemoteUser()
    {
        var server = new Uri("https://remoteblazorwebview.com:34544");
        var page = RemoteLinkInfo.WithRemoteUserFirst(RemoteLinkInfo.WithOwnerRole(RemoteLinkInfo.BuildRemoteUserUrl(server, Id)));
        Assert.Equal($"https://remoteblazorwebview.com:34544/app/{Id}?role=owner&control=remote", page.ToString());
    }

    [Fact]
    public void WithRemoteUserFirst_OnAPageWithoutAQuery()
    {
        var page = RemoteLinkInfo.WithRemoteUserFirst(new Uri($"https://x.example/app/{Id}"));
        Assert.Equal($"https://x.example/app/{Id}?control=remote", page.ToString());
    }

    [Fact]
    public void ASharedSession_SharesTheReadOnlyLink_NeverTheOwnersPage()
    {
        var server = new Uri("https://remoteblazorwebview.com:34544");
        var shared = RemoteLinkInfo.BuildMirrorUrl(server, Id);
        Assert.Equal($"https://remoteblazorwebview.com:34544/mirror/{Id}", shared.ToString());
        Assert.DoesNotContain("role=owner", shared.ToString());
    }

    [Fact]
    public void UnreachableHtml_NamesTheServer_AndEncodesIt()
    {
        var html = RemoteLinkInfo.UnreachableHtml(new Uri("https://remoteblazorwebview.com:34544"));
        Assert.Contains("Remote session not connected", html);
        Assert.Contains("remoteblazorwebview.com:34544", html);
        Assert.StartsWith("<!DOCTYPE html>", html);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OnScreenText_DoesNotAssumeWhoTheRemoteUserIs()
    {
        var s = new Uri("https://remoteblazorwebview.com:34544");
        foreach (var state in Enum.GetValues<RemoteSessionState>())
            Assert.DoesNotContain("technician", RemoteLinkInfo.StatusText(state, s), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("technician", RemoteLinkInfo.UnreachableHtml(s), StringComparison.OrdinalIgnoreCase);
    }
}
