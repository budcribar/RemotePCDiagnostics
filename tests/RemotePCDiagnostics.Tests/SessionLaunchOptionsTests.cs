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
        Assert.False(o.Unattended);
        Assert.False(o.Voice);
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
    [InlineData("--mirror")]
    [InlineData("-m")]
    [InlineData("--reverse-mirror")]
    public void SwitchesOfTheModesThatWereRemoved_AreIgnored(string arg)
    {
        // Every remote session is shared now; an old shortcut or saved command line that still passes these must keep working.
        var o = SessionLaunchOptions.Resolve(["-u=https://localhost:5001", arg], Env(("REMOTEPC_MIRROR", "1"), ("REMOTEPC_REVERSE_MIRROR", "1")));
        Assert.Equal(SessionMode.Remote, o.Mode);
        Assert.False(o.Unattended);
        Assert.False(o.Voice);
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
        var initialCtx = new SessionContext(SessionMode.Remote, new Uri("https://remoteblazorwebview.com:34544"), unattended: true, voice: true);
        Assert.NotEqual(Guid.Empty, initialCtx.SessionId);

        var saved = new DateTimeOffset(2026, 3, 2, 10, 0, 0, TimeSpan.Zero);
        var pending = new PendingRebootState(
            saved,
            "Remote user",
            SessionMode.Remote,
            initialCtx.ServerUri!.AbsoluteUri,
            initialCtx.SessionId,
            PreUptimeSeconds: 500_000,
            PreUsedMemoryBytes: 8L * 1024 * 1024 * 1024,
            PreProcessCount: 180,
            PreTopProcesses: "chrome.exe (4 GB)",
            Unattended: initialCtx.Unattended,
            Voice: initialCtx.Voice);

        // Three minutes later Windows has been up for one: it restarted after the session was saved.
        var resumed = SessionLaunchOptions.Resolve([], Env(), pending, nowUtc: saved.AddMinutes(3), uptime: TimeSpan.FromMinutes(1));
        Assert.Equal(SessionMode.Remote, resumed.Mode);
        Assert.Equal(initialCtx.ServerUri, resumed.ServerUri);
        Assert.Equal(initialCtx.SessionId, resumed.Id);
        Assert.True(resumed.PostReboot);
        Assert.True(resumed.Unattended);
        Assert.True(resumed.Voice);
    }

    private static readonly DateTimeOffset Saved = new(2026, 3, 2, 10, 0, 0, TimeSpan.Zero);
    private static readonly Guid SavedId = Guid.Parse("bfdffa8b-70ac-4740-bdb1-c7f62a0b598f");

    /// <summary>A remote, unattended session saved by "Schedule clean restart" at <see cref="Saved"/>, when the PC had been up two days.</summary>
    private static PendingRebootState SavedRemoteSession() => new(Saved, "Remote user", SessionMode.Remote, "https://remoteblazorwebview.com:34544",
        SavedId, PreUptimeSeconds: 172_800, PreUsedMemoryBytes: 8L << 30, PreProcessCount: 180, PreTopProcesses: "chrome.exe (4 GB)", Unattended: true, Voice: true);

    [Theory]
    [InlineData(1, 172_860)]      // a minute later, still counting down: the PC has simply been up a minute longer
    [InlineData(3 * 60, 183_600)] // three hours later, never restarted (the restart was called off)
    public void SavedSession_IsNotRestored_WhenThePcHasNotRestartedSince(int minutesLater, int uptimeSeconds)
    {
        // Started by hand, no arguments: the app must come up Local, not in the old remote, unattended session.
        var o = SessionLaunchOptions.Resolve([], Env(), SavedRemoteSession(), nowUtc: Saved.AddMinutes(minutesLater), uptime: TimeSpan.FromSeconds(uptimeSeconds));
        Assert.Equal(SessionMode.Local, o.Mode);
        Assert.Null(o.ServerUri);
        Assert.Equal(Guid.Empty, o.Id);
        Assert.False(o.PostReboot);
        Assert.False(o.Unattended);
        Assert.False(o.Voice);
    }

    [Fact]
    public void SavedSession_IsNotRestored_WhenItIsOlderThanTwoDays()
    {
        // The PC did restart, but three days later (shut down over a weekend): too old to pick the session up again.
        var o = SessionLaunchOptions.Resolve([], Env(), SavedRemoteSession(), nowUtc: Saved.AddDays(3), uptime: TimeSpan.FromMinutes(2));
        Assert.Equal(SessionMode.Local, o.Mode);
        Assert.False(o.PostReboot);
        Assert.False(o.Unattended);
    }

    [Fact]
    public void TheResumeEntry_AfterARealRestart_ResumesTheSession()
    {
        string[] runOnce = ["-u=https://remoteblazorwebview.com:34544", $"-i={SavedId}", "--unattended", "--voice", "--post-reboot"];
        var o = SessionLaunchOptions.Resolve(runOnce, Env(), SavedRemoteSession(), nowUtc: Saved.AddMinutes(4), uptime: TimeSpan.FromMinutes(2));
        Assert.Equal(SessionMode.Remote, o.Mode);
        Assert.Equal(SavedId, o.Id);
        Assert.True(o.PostReboot);
        Assert.True(o.Unattended);
        Assert.True(o.Voice);
    }

    [Fact]
    public void TheResumeEntry_WithoutARestart_StartsLocal()
    {
        // The restart was called off; the RunOnce entry it left runs at the next sign-in with the old server and session id.
        string[] runOnce = ["-u=https://remoteblazorwebview.com:34544", $"-i={SavedId}", "--unattended", "--voice", "--post-reboot"];
        var o = SessionLaunchOptions.Resolve(runOnce, Env(), SavedRemoteSession(), nowUtc: Saved.AddHours(5), uptime: TimeSpan.FromSeconds(172_800 + 5 * 3600));
        Assert.Equal(SessionMode.Local, o.Mode);
        Assert.Equal(Guid.Empty, o.Id);
        Assert.False(o.PostReboot);
        Assert.False(o.Unattended);
        Assert.False(o.Voice);
    }

    [Fact]
    public void TheWorkflowResumeTask_KeepsItsSession_WhateverTheSavedSessionSays()
    {
        // The service workflow's task passes the same arguments plus --workflow, and checks its own restart: a stale clean-restart
        // file must neither be restored nor take the task's session away.
        string[] task = ["-u=https://relay.example", $"-i={SavedId}", "--post-reboot", "--workflow"];
        var o = SessionLaunchOptions.Resolve(task, Env(), SavedRemoteSession(), nowUtc: Saved.AddHours(5), uptime: TimeSpan.FromSeconds(172_800 + 5 * 3600));
        Assert.Equal(SessionMode.Remote, o.Mode);
        Assert.Equal(new Uri("https://relay.example"), o.ServerUri);
        Assert.Equal(SavedId, o.Id);
        Assert.True(o.PostReboot);   // from the argument
        Assert.False(o.Unattended);  // not from the stale file
    }

    [Theory]
    [InlineData(4, 120, true)]        // up two minutes, saved four minutes ago: started after the save
    [InlineData(4, 172_800 + 240, false)] // up since before the save
    [InlineData(-30, 120, true)]      // the clock was set back half an hour, but the PC has been up far less than it had been
    public void RestartedSince_GoesByWhenWindowsStarted(int minutesSinceSave, int uptimeSeconds, bool expected) =>
        Assert.Equal(expected, SessionLaunchOptions.RestartedSince(SavedRemoteSession(), Saved.AddMinutes(minutesSinceSave), TimeSpan.FromSeconds(uptimeSeconds)));

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
    public void Unattended_FromArgOrEnv_AndSurvivesRestartAndReboot()
    {
        var byArg = SessionLaunchOptions.Resolve(["-u=https://x.example", "--unattended"], _ => null);
        Assert.True(byArg.Unattended);
        Assert.True(SessionLaunchOptions.Resolve([], n => n == "REMOTEPC_MODE" ? "Remote" : n == "REMOTEPC_UNATTENDED" ? "1" : null).Unattended);
        Assert.False(SessionLaunchOptions.Resolve(["-u=https://x.example"], _ => null).Unattended);
        Assert.False(SessionLaunchOptions.Resolve(["-u=https://x.example", "--unattended=false"], _ => null).Unattended);

        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var server = new Uri("https://remoteblazorwebview.com:34544");
        var restart = SessionLaunchOptions.RestartArguments(server, id, unattended: true);
        Assert.Equal(["-u=https://remoteblazorwebview.com:34544", "-i=7e57c0de-0000-4000-8000-000000000001", "--unattended", "--restarted"], restart);
        Assert.True(SessionLaunchOptions.Resolve(restart, _ => null).Unattended);

        var cmd = SessionLaunchOptions.BuildResumeCommandLine(@"C:\App\RemotePCDiagnostics.Host.exe", SessionMode.Remote, server, id, unattended: true);
        Assert.Equal("\"C:\\App\\RemotePCDiagnostics.Host.exe\" -u=https://remoteblazorwebview.com:34544 -i=7e57c0de-0000-4000-8000-000000000001 --unattended --post-reboot", cmd);
    }

    [Fact]
    public void Voice_FromArgOrEnv_AndSurvivesRestartAndReboot()
    {
        Assert.True(SessionLaunchOptions.Resolve(["-u=https://x.example", "--voice"], _ => null).Voice);
        Assert.True(SessionLaunchOptions.Resolve([], n => n == "REMOTEPC_MODE" ? "Remote" : n == "REMOTEPC_VOICE" ? "1" : null).Voice);
        Assert.False(SessionLaunchOptions.Resolve(["-u=https://x.example"], _ => null).Voice);

        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var server = new Uri("https://remoteblazorwebview.com:34544");
        var restart = SessionLaunchOptions.RestartArguments(server, id, voice: true);
        Assert.Contains("--voice", restart);
        Assert.True(SessionLaunchOptions.Resolve(restart, _ => null).Voice);

        var cmd = SessionLaunchOptions.BuildResumeCommandLine(@"C:\App\RemotePCDiagnostics.Host.exe", SessionMode.Remote, server, id, voice: true);
        Assert.Contains(" --voice ", cmd);
    }

    [Fact]
    public void Admin_RemoteSessionsDefaultToAdmin_UnlessOverridden()
    {
        // Default remote session enables admin
        var remoteDefault = SessionLaunchOptions.Resolve(["-u=https://x.example"], _ => null);
        Assert.True(remoteDefault.Admin);

        // Explicit --no-admin flag
        var remoteNoAdmin = SessionLaunchOptions.Resolve(["-u=https://x.example", "--no-admin"], _ => null);
        Assert.False(remoteNoAdmin.Admin);

        // Explicit --admin=false
        var remoteAdminFalse = SessionLaunchOptions.Resolve(["-u=https://x.example", "--admin=false"], _ => null);
        Assert.False(remoteAdminFalse.Admin);

        // Explicit env REMOTEPC_ADMIN=0
        var remoteEnvNoAdmin = SessionLaunchOptions.Resolve([], n => n == "REMOTEPC_MODE" ? "Remote" : n == "REMOTEPC_ADMIN" ? "0" : null);
        Assert.False(remoteEnvNoAdmin.Admin);

        // Remote Admin launch profile settings
        var remoteAdminProfile = SessionLaunchOptions.Resolve([], n => n == "REMOTEPC_MODE" ? "Remote" : n == "REMOTEPC_ADMIN" ? "1" : null);
        Assert.True(remoteAdminProfile.Admin);
    }

    [Fact]
    public void Admin_LocalSessionsDefaultToUser_UnlessOverridden()
    {
        // Local session defaults to standard user (Admin == false)
        var localDefault = SessionLaunchOptions.Resolve([], _ => null);
        Assert.False(localDefault.Admin);

        // Local User profile (REMOTEPC_MODE=Local, REMOTEPC_ADMIN=0)
        var localUser = SessionLaunchOptions.Resolve([], n => n == "REMOTEPC_MODE" ? "Local" : n == "REMOTEPC_ADMIN" ? "0" : null);
        Assert.False(localUser.Admin);

        // Local Admin profile (REMOTEPC_MODE=Local, REMOTEPC_ADMIN=1)
        var localAdminProfile = SessionLaunchOptions.Resolve([], n => n == "REMOTEPC_MODE" ? "Local" : n == "REMOTEPC_ADMIN" ? "1" : null);
        Assert.True(localAdminProfile.Admin);

        // Local Admin via CLI --admin
        var localAdminArg = SessionLaunchOptions.Resolve(["--admin"], _ => null);
        Assert.True(localAdminArg.Admin);
    }

    [Fact]
    public void Admin_SurvivesRestartAndReboot()
    {
        var id = Guid.Parse("7e57c0de-0000-4000-8000-000000000001");
        var server = new Uri("https://remoteblazorwebview.com:34544");

        var restartAdmin = SessionLaunchOptions.RestartArguments(server, id, admin: true);
        Assert.Contains("--admin", restartAdmin);
        Assert.True(SessionLaunchOptions.Resolve(restartAdmin, _ => null).Admin);

        var restartNoAdmin = SessionLaunchOptions.RestartArguments(server, id, admin: false);
        Assert.Contains("--no-admin", restartNoAdmin);
        Assert.False(SessionLaunchOptions.Resolve(restartNoAdmin, _ => null).Admin);

        var cmdRemoteAdmin = SessionLaunchOptions.BuildResumeCommandLine(@"C:\App\RemotePCDiagnostics.Host.exe", SessionMode.Remote, server, id, admin: true);
        Assert.Contains(" --admin ", cmdRemoteAdmin);

        var cmdLocalAdmin = SessionLaunchOptions.BuildResumeCommandLine(@"C:\App\RemotePCDiagnostics.Host.exe", SessionMode.Local, null, Guid.Empty, admin: true);
        Assert.Contains(" --admin ", cmdLocalAdmin);
    }
}
