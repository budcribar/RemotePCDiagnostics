using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public class SessionAuditTests
{
    private readonly List<LogEntry> _log = [];
    private SessionAudit New() => new(_log.Add);
    private static SessionParticipant Owner(bool control) => new("o", true, control, "");
    private static SessionParticipant Page(string id, bool control = false, string name = "") => new(id, false, control, name);
    private int[] Ids => [.. _log.Select(e => e.EventId)];

    [Theory]
    [InlineData(false, "Supervised")]
    [InlineData(true, "Unattended")]
    public void The_start_says_which_mode(bool unattended, string mode)
    {
        var audit = New();
        audit.Started(unattended);
        audit.Started(unattended); // ReadyToConnect again: one entry

        var entry = Assert.Single(_log);
        Assert.Equal(SessionAuditIds.Started, entry.EventId);
        Assert.Contains(mode, entry.Message);
    }

    [Fact]
    public void A_supervised_session_from_join_to_leave()
    {
        var audit = New();
        audit.Started(false);
        audit.Update([Owner(true)]);                                  // this PC's window: not news
        audit.Update([Owner(true), Page("r", name: "Pat Lee")]);      // joined
        audit.Update([Owner(false), Page("r", true, "Pat Lee")]);     // given control
        audit.Update([Owner(true), Page("r", name: "Pat Lee")]);      // taken back
        audit.Update([Owner(true)]);                                  // left
        audit.Ended("");

        Assert.Equal([SessionAuditIds.Started, SessionAuditIds.RemoteUserJoined, SessionAuditIds.ControlToRemoteUser,
            SessionAuditIds.ControlBackToOwner, SessionAuditIds.Left, SessionAuditIds.Ended], Ids);
        Assert.Contains("Pat Lee", _log[1].Message);
        Assert.Contains("Pat Lee", _log[2].Message);
        Assert.Contains("Pat Lee", _log[4].Message);
    }

    [Fact]
    public void The_same_roster_twice_writes_nothing_new()
    {
        var audit = New();
        audit.Update([Owner(true), Page("r")]);
        var count = _log.Count;

        audit.Update([Owner(true), Page("r")]);

        Assert.Equal(count, _log.Count);
    }

    [Fact]
    public void A_second_page_is_a_viewer_and_stays_one()
    {
        var audit = New();
        audit.Update([Owner(true), Page("r", name: "Pat"), Page("v", name: "Sam")]);
        audit.Update([Owner(true), Page("v", name: "Sam")]); // the remote user left; the viewer is still a viewer

        Assert.Equal([SessionAuditIds.RemoteUserJoined, SessionAuditIds.ViewerJoined, SessionAuditIds.Left], Ids);
        Assert.StartsWith("Viewer joined", _log[1].Message);
        Assert.StartsWith("Remote user left", _log[2].Message);
    }

    [Fact]
    public void Without_sign_in_the_name_says_so()
    {
        var audit = New();
        audit.Update([Owner(true), Page("r")]);

        Assert.Contains("(not signed in)", Assert.Single(_log).Message);
    }

    [Fact]
    public void An_unattended_remote_user_who_leaves_with_control_is_logged_and_control_returns()
    {
        var audit = New();
        audit.Update([Owner(true)]);
        audit.Update([Owner(false), Page("r", true, "Pat")]);
        audit.Update([Owner(true)]);

        Assert.Equal([SessionAuditIds.RemoteUserJoined, SessionAuditIds.ControlToRemoteUser, SessionAuditIds.ControlBackToOwner, SessionAuditIds.Left], Ids);
    }

    [Fact]
    public void The_end_is_written_once_and_only_for_a_started_session()
    {
        var audit = New();
        audit.Ended("never started");
        Assert.Empty(_log);

        audit.Started(false);
        audit.Ended("Server shut down connection");
        audit.Ended("The app was closed");

        Assert.Equal([SessionAuditIds.Started, SessionAuditIds.Ended], Ids);
        Assert.Contains("Server shut down connection", _log[1].Message);
    }

    [Fact]
    public void A_failing_log_never_throws()
    {
        var audit = new SessionAudit(_ => throw new InvalidOperationException());
        audit.Started(false);
        audit.Update([Owner(true), Page("r")]);
        audit.Ended("");
    }
}
