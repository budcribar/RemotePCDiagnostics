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
        Assert.False(o.Mirror);
    }

    [Fact]
    public void RemoteEnv_WithoutUrl_UsesDefaultServer()
    {
        var o = SessionLaunchOptions.Resolve([], Env(("REMOTEPC_MODE", "remote")));
        Assert.Equal(SessionMode.Remote, o.Mode);
        Assert.Equal(new Uri("https://remoteblazorwebview.com:34544"), o.ServerUri);
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

    [Theory]
    [InlineData("-m", true)]
    [InlineData("--mirror", true)]
    [InlineData("-m=true", true)]
    [InlineData("--mirror=1", true)]
    [InlineData("-m=false", false)]
    public void MirrorArg_AndEnv_ParsedAndPreservedAcrossRestartAndReboot(string arg, bool expected)
    {
        var o = SessionLaunchOptions.Resolve(["-u=https://localhost:5001", arg], Env(("REMOTEPC_MIRROR", "true")));
        Assert.Equal(expected, o.Mirror);

        var envOnly = SessionLaunchOptions.Resolve(["-u=https://localhost:5001"], Env(("REMOTEPC_MIRROR", "1")));
        Assert.True(envOnly.Mirror);

        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var restartArgs = SessionLaunchOptions.RestartArguments(new Uri("https://remoteblazorwebview.com:34544/"), id, mirror: true);
        Assert.Equal(["-u=https://remoteblazorwebview.com:34544", "-i=7e57c0de-0000-4000-8000-000000000001", "--mirror", "--restarted"], restartArgs);
        Assert.True(SessionLaunchOptions.Resolve(restartArgs, _ => null).Mirror);

        var resumeCmd = SessionLaunchOptions.BuildResumeCommandLine(@"C:\App\RemotePCDiagnostics.Host.exe", SessionMode.Remote, new Uri("https://remoteblazorwebview.com:34544"), id, mirror: true);
        Assert.Equal("\"C:\\App\\RemotePCDiagnostics.Host.exe\" -u=https://remoteblazorwebview.com:34544 -i=7e57c0de-0000-4000-8000-000000000001 --mirror --post-reboot", resumeCmd);
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
        var initialCtx = new SessionContext(SessionMode.Remote, new Uri("https://remoteblazorwebview.com:34544"), mirror: true);
        Assert.NotEqual(Guid.Empty, initialCtx.SessionId);

        var pending = new PendingRebootState(
            DateTimeOffset.UtcNow,
            "Remote user",
            SessionMode.Remote,
            initialCtx.ServerUri!.AbsoluteUri,
            initialCtx.SessionId,
            PreUptimeSeconds: 500_000,
            PreUsedMemoryBytes: 8L * 1024 * 1024 * 1024,
            PreProcessCount: 180,
            PreTopProcesses: "chrome.exe (4 GB)",
            Mirror: initialCtx.Mirror);

        var resumed = SessionLaunchOptions.Resolve([], Env(), pending);
        Assert.Equal(SessionMode.Remote, resumed.Mode);
        Assert.Equal(initialCtx.ServerUri, resumed.ServerUri);
        Assert.Equal(initialCtx.SessionId, resumed.Id);
        Assert.True(resumed.PostReboot);
        Assert.True(resumed.Mirror);
    }

    [Fact]
    public void RestartArguments_KeepServerAndSession_AndMarkTheRestart()
    {
        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var args = SessionLaunchOptions.RestartArguments(new Uri("https://remoteblazorwebview.com:34544/"), id);
        Assert.Equal(["-u=https://remoteblazorwebview.com:34544", "-i=7e57c0de-0000-4000-8000-000000000001", "--restarted"], args);
        Assert.True(SessionLaunchOptions.IsRestarted(args));
        var resolved = SessionLaunchOptions.Resolve(args, _ => null);
        Assert.Equal(SessionMode.Remote, resolved.Mode);
        Assert.Equal(id, resolved.Id);
        Assert.Equal(new Uri("https://remoteblazorwebview.com:34544"), resolved.ServerUri);
    }

    [Fact]
    public void RestartArguments_NeedTheAssignedSessionId()
    {
        Assert.Throws<ArgumentException>(() => SessionLaunchOptions.RestartArguments(new Uri("https://x.example/"), Guid.Empty));
        Assert.False(SessionLaunchOptions.IsRestarted(["-u=https://x.example"]));
    }

    [Fact]
    public void ReverseMirror_FromArgOrEnv_AndWinsOverMirror()
    {
        var byArg = SessionLaunchOptions.Resolve(["-u=https://remoteblazorwebview.com:34544", "--reverse-mirror"], _ => null);
        Assert.True(byArg.ReverseMirror);
        Assert.False(byArg.Mirror);

        var byEnv = SessionLaunchOptions.Resolve([], v => v switch { "REMOTEPC_MODE" => "Remote", "REMOTEPC_REVERSE_MIRROR" => "1", "REMOTEPC_MIRROR" => "1", _ => null });
        Assert.True(byEnv.ReverseMirror);
        Assert.False(byEnv.Mirror); // the two directions exclude each other

        Assert.False(SessionLaunchOptions.Resolve(["-u=https://x.example", "--reverse-mirror=false"], _ => null).ReverseMirror);
        Assert.False(SessionLaunchOptions.Resolve(["-u=https://x.example", "--mirror"], _ => null).ReverseMirror);
    }

    [Fact]
    public void Unattended_FromArgOrEnv_ImpliesTheSharedSession_AndSurvivesRestartAndReboot()
    {
        var byArg = SessionLaunchOptions.Resolve(["-u=https://x.example", "--unattended"], _ => null);
        Assert.True(byArg.Unattended);
        Assert.True(byArg.Mirror);
        Assert.True(SessionLaunchOptions.Resolve([], n => n == "REMOTEPC_MODE" ? "Remote" : n == "REMOTEPC_UNATTENDED" ? "1" : null).Unattended);
        Assert.False(SessionLaunchOptions.Resolve(["-u=https://x.example", "--mirror"], _ => null).Unattended);
        Assert.False(SessionLaunchOptions.Resolve(["-u=https://x.example", "--unattended", "--reverse-mirror"], _ => null).Unattended);

        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var server = new Uri("https://remoteblazorwebview.com:34544");
        var restart = SessionLaunchOptions.RestartArguments(server, id, mirror: true, unattended: true);
        Assert.Contains("--unattended", restart);
        Assert.True(SessionLaunchOptions.Resolve(restart, _ => null).Unattended);

        var cmd = SessionLaunchOptions.BuildResumeCommandLine(@"C:\App\RemotePCDiagnostics.Host.exe", SessionMode.Remote, server, id, mirror: true, unattended: true);
        Assert.Contains(" --unattended ", cmd);
        Assert.EndsWith(" --post-reboot", cmd);
    }

    [Fact]
    public void Voice_FromArgOrEnv_AndSurvivesRestartAndReboot()
    {
        Assert.True(SessionLaunchOptions.Resolve(["-u=https://x.example", "--mirror", "--voice"], _ => null).Voice);
        Assert.True(SessionLaunchOptions.Resolve([], n => n == "REMOTEPC_MODE" ? "Remote" : n == "REMOTEPC_VOICE" ? "1" : null).Voice);
        Assert.False(SessionLaunchOptions.Resolve(["-u=https://x.example", "--mirror"], _ => null).Voice);

        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var server = new Uri("https://remoteblazorwebview.com:34544");
        var restart = SessionLaunchOptions.RestartArguments(server, id, mirror: true, voice: true);
        Assert.Contains("--voice", restart);
        Assert.True(SessionLaunchOptions.Resolve(restart, _ => null).Voice);

        var cmd = SessionLaunchOptions.BuildResumeCommandLine(@"C:\App\RemotePCDiagnostics.Host.exe", SessionMode.Remote, server, id, mirror: true, voice: true);
        Assert.Contains(" --voice ", cmd);
    }

    [Fact]
    public void ReverseMirror_SurvivesRestartAndReboot()
    {
        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var args = SessionLaunchOptions.RestartArguments(new Uri("https://remoteblazorwebview.com:34544/"), id, mirror: false, reverseMirror: true);
        Assert.Contains("--reverse-mirror", args);
        Assert.DoesNotContain("--mirror", args);
        Assert.True(SessionLaunchOptions.Resolve(args, _ => null).ReverseMirror);

        var cmd = SessionLaunchOptions.BuildResumeCommandLine(@"C:\App\RemotePCDiagnostics.Host.exe", SessionMode.Remote, new Uri("https://remoteblazorwebview.com:34544"), id, reverseMirror: true);
        Assert.Contains(" --reverse-mirror ", cmd);
        Assert.DoesNotContain(" --mirror ", cmd);
    }
}
