using System.Diagnostics;
using RemotePCDiagnostics.Agent;

namespace RemotePCDiagnostics.Agent.Core.Tests;

public class ActiveSessionTests
{
    [Fact]
    public void ActiveSessionInfo_RoundTripsJson()
    {
        var now = DateTimeOffset.UtcNow;
        var info = new ActiveSessionInfo(
            ProcessId: 1234,
            Running: true,
            SessionId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            Group: "testgroup",
            Mode: "Remote",
            StartedUtc: now);

        var json = info.ToJson();
        Assert.NotNull(json);

        var parsed = ActiveSessionInfo.Parse(json);
        Assert.NotNull(parsed);
        Assert.Equal(1234, parsed.ProcessId);
        Assert.True(parsed.Running);
        Assert.Equal("a1b2c3d4-e5f6-7890-abcd-ef1234567890", parsed.SessionId);
        Assert.Equal("testgroup", parsed.Group);
        Assert.Equal("Remote", parsed.Mode);
        Assert.Equal(now, parsed.StartedUtc);
    }

    [Fact]
    public void ActiveSessionInfo_LocalMode_NullSessionId()
    {
        var now = DateTimeOffset.UtcNow;
        var info = new ActiveSessionInfo(
            ProcessId: 5678,
            Running: true,
            SessionId: null,
            Group: null,
            Mode: "Local",
            StartedUtc: now);

        var json = info.ToJson();
        var parsed = ActiveSessionInfo.Parse(json);
        Assert.NotNull(parsed);
        Assert.Equal(5678, parsed.ProcessId);
        Assert.True(parsed.Running);
        Assert.Null(parsed.SessionId);
        Assert.Null(parsed.Group);
        Assert.Equal("Local", parsed.Mode);
    }

    [Fact]
    public void ActiveSessionInfo_Parse_InvalidJsonReturnsNull()
    {
        Assert.Null(ActiveSessionInfo.Parse(null));
        Assert.Null(ActiveSessionInfo.Parse(""));
        Assert.Null(ActiveSessionInfo.Parse("   "));
        Assert.Null(ActiveSessionInfo.Parse("not json"));
        Assert.Null(ActiveSessionInfo.Parse("{ invalid: json }"));
    }

    [Fact]
    public void ActiveSessionInfo_TryWriteAndTryDelete()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"active-session-test-{Guid.NewGuid()}.json");
        try
        {
            var info = new ActiveSessionInfo(
                ProcessId: 99999,
                Running: true,
                SessionId: "sess-1",
                Group: "g",
                Mode: "Remote",
                StartedUtc: DateTimeOffset.UtcNow);

            Assert.True(ActiveSessionInfo.TryWrite(info, tempFile));
            Assert.True(File.Exists(tempFile));

            // TryDelete with mismatched PID should not delete the file
            Assert.False(ActiveSessionInfo.TryDelete(tempFile, expectedProcessId: 11111));
            Assert.True(File.Exists(tempFile));

            // TryDelete with matching PID should delete the file
            Assert.True(ActiveSessionInfo.TryDelete(tempFile, expectedProcessId: 99999));
            Assert.False(File.Exists(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void AgentLayout_ActiveSessionPath_EndsWithActiveSessionJson()
    {
        var path = AgentLayout.ActiveSessionPath();
        Assert.EndsWith(AgentLayout.ActiveSessionFileName, path);
    }

    [Fact]
    public void ResolveSessionStatus_WhenInternalRunning_ReturnsTrueAndInternalId()
    {
        var (running, sessionId) = AgentHubWorker.ResolveSessionStatus(
            internalRunning: true,
            internalSessionId: "internal-id-123",
            activeSessionPath: "/nonexistent/path/active-session.json",
            processChecker: _ => (false, ""),
            hostProcessRunningChecker: () => false);

        Assert.True(running);
        Assert.Equal("internal-id-123", sessionId);
    }

    [Fact]
    public void ResolveSessionStatus_WithLiveRemoteHostProcess_ReturnsRunningAndSessionId()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"active-session-test-{Guid.NewGuid()}.json");
        try
        {
            var info = new ActiveSessionInfo(
                ProcessId: 4321,
                Running: true,
                SessionId: "remote-session-abc",
                Group: "shop1",
                Mode: "Remote",
                StartedUtc: DateTimeOffset.UtcNow);

            File.WriteAllText(tempFile, info.ToJson());

            var (running, sessionId) = AgentHubWorker.ResolveSessionStatus(
                internalRunning: false,
                internalSessionId: "",
                activeSessionPath: tempFile,
                processChecker: pid => (pid == 4321, "RemotePCDiagnostics.Host"),
                hostProcessRunningChecker: () => false);

            Assert.True(running);
            Assert.Equal("remote-session-abc", sessionId);
            Assert.True(File.Exists(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void ResolveSessionStatus_WithLiveLocalHostProcess_ReturnsRunningAndEmptySessionId()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"active-session-test-{Guid.NewGuid()}.json");
        try
        {
            var info = new ActiveSessionInfo(
                ProcessId: 7890,
                Running: true,
                SessionId: null,
                Group: null,
                Mode: "Local",
                StartedUtc: DateTimeOffset.UtcNow);

            File.WriteAllText(tempFile, info.ToJson());

            var (running, sessionId) = AgentHubWorker.ResolveSessionStatus(
                internalRunning: false,
                internalSessionId: "",
                activeSessionPath: tempFile,
                processChecker: pid => (pid == 7890, "RemotePCDiagnostics.Host"),
                hostProcessRunningChecker: () => false);

            Assert.True(running);
            Assert.Equal("", sessionId);
            Assert.True(File.Exists(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void ResolveSessionStatus_WithDeadHostProcess_DeletesStaleFile()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"active-session-test-{Guid.NewGuid()}.json");
        try
        {
            var info = new ActiveSessionInfo(
                ProcessId: 1122,
                Running: true,
                SessionId: "stale-session",
                Group: null,
                Mode: "Remote",
                StartedUtc: DateTimeOffset.UtcNow);

            File.WriteAllText(tempFile, info.ToJson());

            var (running, sessionId) = AgentHubWorker.ResolveSessionStatus(
                internalRunning: false,
                internalSessionId: "",
                activeSessionPath: tempFile,
                processChecker: _ => (false, ""),
                hostProcessRunningChecker: () => false);

            Assert.False(running);
            Assert.Equal("", sessionId);
            // Stale file must have been deleted
            Assert.False(File.Exists(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void ResolveSessionStatus_NoFile_HostProcessRunningReturnsTrue()
    {
        var (running, sessionId) = AgentHubWorker.ResolveSessionStatus(
            internalRunning: false,
            internalSessionId: "",
            activeSessionPath: "/nonexistent/active-session.json",
            processChecker: _ => (false, ""),
            hostProcessRunningChecker: () => true);

        Assert.True(running);
        Assert.Equal("", sessionId);
    }
}
