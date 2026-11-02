using RemotePCDiagnostics.Core.Areas;
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

    [Fact]
    public void PostReboot_RestoresPreviousIdAndServerFromPendingRebootState()
    {
        // Even if Remote mode was originally started without -i= (so SessionContext generated a SessionId),
        // that SessionId is saved to PendingRebootState and restored on restart even if launched without args.
        var initialCtx = new SessionContext(SessionMode.Remote, new Uri("https://remoteblazor.pagetomovie.com:34544"));
        Assert.NotEqual(Guid.Empty, initialCtx.SessionId);

        var pending = new PendingRebootState(
            DateTimeOffset.UtcNow,
            "Remote technician",
            SessionMode.Remote,
            initialCtx.ServerUri!.AbsoluteUri,
            initialCtx.SessionId,
            PreUptimeSeconds: 500_000,
            PreUsedMemoryBytes: 8L * 1024 * 1024 * 1024,
            PreProcessCount: 180,
            PreTopProcesses: "chrome.exe (4 GB)");

        var resumed = SessionLaunchOptions.Resolve([], Env(), pending);
        Assert.Equal(SessionMode.Remote, resumed.Mode);
        Assert.Equal(initialCtx.ServerUri, resumed.ServerUri);
        Assert.Equal(initialCtx.SessionId, resumed.Id);
        Assert.True(resumed.PostReboot);
    }

    [Fact]
    public void RestartArguments_KeepServerAndSession_AndMarkTheRestart()
    {
        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var args = SessionLaunchOptions.RestartArguments(new Uri("https://remoteblazor.pagetomovie.com:34544/"), id);
        Assert.Equal(["-u=https://remoteblazor.pagetomovie.com:34544", "-i=7e57c0de-0000-4000-8000-000000000001", "--restarted"], args);
        Assert.True(SessionLaunchOptions.IsRestarted(args));
        var resolved = SessionLaunchOptions.Resolve(args, _ => null);
        Assert.Equal(SessionMode.Remote, resolved.Mode);
        Assert.Equal(id, resolved.Id);
        Assert.Equal(new Uri("https://remoteblazor.pagetomovie.com:34544"), resolved.ServerUri);
    }

    [Fact]
    public void RestartArguments_NeedTheAssignedSessionId()
    {
        Assert.Throws<ArgumentException>(() => SessionLaunchOptions.RestartArguments(new Uri("https://x.example/"), Guid.Empty));
        Assert.False(SessionLaunchOptions.IsRestarted(["-u=https://x.example"]));
    }
}
