using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class SessionControlTrackerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 20, 21, 0, 0, TimeSpan.Zero);

    private static SessionControlTracker.Observation See(
        bool ownerHasControl, bool remotePresent, bool fromOwner = true, string? gesture = null, int? gestureAgeMs = null) =>
        new(fromOwner, ownerHasControl, remotePresent, gesture, gestureAgeMs);

    [Fact]
    public void Owner_keeps_control_until_a_mirror_has_taken_it()
    {
        var tracker = new SessionControlTracker();

        Assert.False(tracker.Observe(See(ownerHasControl: true, remotePresent: false), T0));
        Assert.Equal("owner", tracker.ActualHolder);
        Assert.Equal("owner", tracker.KeptWith);
        Assert.Equal("owner-holds", tracker.Reason);

        Assert.False(tracker.Observe(See(ownerHasControl: true, remotePresent: true), T0.AddSeconds(1)));
        Assert.Equal("owner", tracker.KeptWith);
        Assert.Equal("owner-holds", tracker.Reason);
    }

    [Fact]
    public void After_the_mirror_has_control_an_owner_gain_without_a_click_is_given_back()
    {
        var tracker = new SessionControlTracker();
        tracker.Observe(See(ownerHasControl: false, remotePresent: true), T0);

        Assert.Equal("remote", tracker.ActualHolder);
        Assert.Equal("remote", tracker.KeptWith);
        Assert.Equal("remote-holds", tracker.Reason);

        // The field failure: the mirror drops to view-only and the owner window has control, with no Take click.
        var moved = tracker.MovedAt;
        Assert.True(tracker.Observe(See(ownerHasControl: true, remotePresent: true), T0.AddMinutes(1)));
        Assert.Equal("owner", tracker.ActualHolder);
        Assert.Equal("remote", tracker.KeptWith);
        Assert.Equal("restored", tracker.Reason);
        Assert.True(tracker.MovedAt > moved);

        // A report from the mirror cannot give control back; only the owner window can.
        Assert.False(tracker.Observe(See(ownerHasControl: true, remotePresent: true, fromOwner: false), T0.AddMinutes(1).AddSeconds(1)));
    }

    [Fact]
    public void Explicit_take_on_the_owner_window_is_kept()
    {
        var tracker = new SessionControlTracker();
        tracker.Observe(See(ownerHasControl: false, remotePresent: true), T0);

        Assert.False(tracker.Observe(See(ownerHasControl: true, remotePresent: true, gesture: "take", gestureAgeMs: 200), T0.AddSeconds(5)));
        Assert.Equal("owner", tracker.KeptWith);
        Assert.Equal("explicit-take", tracker.Reason);

        Assert.False(tracker.Observe(See(ownerHasControl: true, remotePresent: true), T0.AddSeconds(30)));
        Assert.Equal("owner", tracker.KeptWith);
        Assert.Equal("owner-holds", tracker.Reason);
    }

    [Fact]
    public void A_stale_or_mirror_take_click_does_not_count()
    {
        var tracker = new SessionControlTracker();
        tracker.Observe(See(ownerHasControl: false, remotePresent: true), T0);

        Assert.True(tracker.Observe(
            See(ownerHasControl: true, remotePresent: true, gesture: "take", gestureAgeMs: SessionControlTracker.GestureWindowMs + 1),
            T0.AddSeconds(20)));
        Assert.Equal("restored", tracker.Reason);

        tracker.Observe(See(ownerHasControl: false, remotePresent: true), T0.AddSeconds(21));
        // A Take click on the mirror is that mirror asking for control, not the person at the PC taking it back.
        Assert.False(tracker.Observe(
            See(ownerHasControl: true, remotePresent: true, fromOwner: false, gesture: "take", gestureAgeMs: 100),
            T0.AddSeconds(22)));
        Assert.Equal("remote", tracker.KeptWith);
        Assert.Equal("restored", tracker.Reason);
    }

    [Fact]
    public void Explicit_give_is_restored_if_the_owner_window_gets_control_again()
    {
        var tracker = new SessionControlTracker();
        tracker.Observe(See(ownerHasControl: true, remotePresent: true), T0);

        Assert.False(tracker.Observe(See(ownerHasControl: true, remotePresent: true, gesture: "give", gestureAgeMs: 50), T0.AddSeconds(1)));
        Assert.Equal("remote", tracker.KeptWith);
        Assert.Equal("explicit-give", tracker.Reason);

        Assert.True(tracker.Observe(See(ownerHasControl: true, remotePresent: true), T0.AddMinutes(1)));
        Assert.Equal("restored", tracker.Reason);
    }

    [Fact]
    public void A_mirror_that_left_is_given_control_again_when_it_rejoins()
    {
        var tracker = new SessionControlTracker();
        tracker.Observe(See(ownerHasControl: false, remotePresent: true), T0);

        Assert.False(tracker.Observe(See(ownerHasControl: true, remotePresent: false), T0.AddSeconds(70)));
        Assert.Equal("owner", tracker.ActualHolder);
        Assert.Equal("remote", tracker.KeptWith);
        Assert.Equal("remote-away", tracker.Reason);

        Assert.True(tracker.Observe(See(ownerHasControl: true, remotePresent: true), T0.AddSeconds(73)));
        Assert.Equal("restored", tracker.Reason);
    }

    [Fact]
    public void Handback_is_not_repeated_inside_the_interval()
    {
        var tracker = new SessionControlTracker();
        Assert.True(tracker.TryMarkHandback(T0));
        Assert.False(tracker.TryMarkHandback(T0.AddMilliseconds(SessionControlTracker.HandbackIntervalMs - 1)));
        Assert.True(tracker.TryMarkHandback(T0.AddMilliseconds(SessionControlTracker.HandbackIntervalMs)));
    }
}
