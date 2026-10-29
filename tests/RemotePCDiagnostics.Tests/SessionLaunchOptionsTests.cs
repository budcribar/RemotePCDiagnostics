using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class SessionLaunchOptionsTests
{
    private static Func<string, string?> Env(params (string K, string V)[] kv) =>
        k => kv.FirstOrDefault(x => x.K == k).V;

    [Fact]
    public void Default_IsLocal()
    {
        var o = SessionLaunchOptions.Resolve([], Env());
        Assert.Equal(SessionMode.Local, o.Mode);
        Assert.Null(o.ServerUri);
    }

    [Fact]
    public void RemoteEnv_WithoutUrl_UsesDefaultServer()
    {
        var o = SessionLaunchOptions.Resolve([], Env(("REMOTEPC_MODE", "remote")));
        Assert.Equal(SessionMode.Remote, o.Mode);
        Assert.Equal(new Uri("https://remoteblazor.pagetomovie.com:34544"), o.ServerUri);
    }

    [Fact]
    public void RemoteEnv_UrlOverride()
    {
        var o = SessionLaunchOptions.Resolve([], Env(("REMOTEPC_MODE", "Remote"), ("REMOTEPC_SERVER_URL", "https://server.remoteblazorwebview.com")));
        Assert.Equal(new Uri("https://server.remoteblazorwebview.com"), o.ServerUri);
        Assert.Equal(443, o.ServerUri!.Port);
    }

    [Fact]
    public void UrlArg_ForcesRemote_AndIdArgParsed()
    {
        var id = Guid.NewGuid();
        var o = SessionLaunchOptions.Resolve(["-u=https://localhost:5001", $"-i={id}"], Env(("REMOTEPC_MODE", "Local")));
        Assert.Equal(SessionMode.Remote, o.Mode);
        Assert.Equal(5001, o.ServerUri!.Port);
        Assert.Equal(id, o.Id);
    }

    [Fact]
    public void LocalEnv_IgnoresServerUrl() =>
        Assert.Equal(SessionMode.Local, SessionLaunchOptions.Resolve([], Env(("REMOTEPC_MODE", "Local"), ("REMOTEPC_SERVER_URL", "https://x"))).Mode);

    [Fact]
    public void InvalidUrl_Throws() =>
        Assert.Throws<ArgumentException>(() => SessionLaunchOptions.Resolve(["-u=not a url"], Env()));
}
