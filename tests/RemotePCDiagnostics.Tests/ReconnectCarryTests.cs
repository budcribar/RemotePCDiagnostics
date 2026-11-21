using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class ReconnectCarryTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 21, 18, 44, 0, TimeSpan.Zero);

    [Fact]
    public void A_copy_started_without_the_values_is_not_reconnecting() =>
        Assert.Null(ReconnectCarry.FromEnvironment(_ => null, Now));

    [Fact]
    public void Values_written_for_the_next_copy_read_back()
    {
        var env = new Dictionary<string, string?>();
        ReconnectCarry.Start(Now.AddMinutes(-3)).Next().Next().WriteTo(env);

        var read = ReconnectCarry.FromEnvironment(k => env.TryGetValue(k, out var v) ? v : null, Now);

        Assert.NotNull(read);
        Assert.Equal(Now.AddMinutes(-3), read!.Since);
        Assert.Equal(2, read.Attempt);
    }

    [Fact]
    public void Waits_grow_from_two_seconds_to_a_minute()
    {
        var carry = ReconnectCarry.Start(Now);
        var waits = new List<double>();
        for (var i = 0; i < 8; i++)
        {
            waits.Add(carry.NextDelay().TotalSeconds);
            carry = carry.Next();
        }
        Assert.Equal([2, 4, 8, 16, 32, 60, 60, 60], waits);
    }

    [Fact]
    public void Gives_up_once_the_window_has_passed()
    {
        var carry = ReconnectCarry.Start(Now);
        Assert.False(carry.Expired(Now + ReconnectCarry.Window - TimeSpan.FromSeconds(1)));
        Assert.True(carry.Expired(Now + ReconnectCarry.Window + TimeSpan.FromSeconds(1)));
    }

    [Theory]
    [InlineData("not a date")]
    [InlineData("2026-11-21T19:30:00.0000000+00:00")] // well after now
    public void Unusable_values_are_ignored(string since) =>
        Assert.Null(ReconnectCarry.FromEnvironment(k => k == ReconnectCarry.SinceEnvVar ? since : null, Now));

    [Fact]
    public void Clearing_removes_both_values()
    {
        var env = new Dictionary<string, string?>();
        ReconnectCarry.Start(Now).WriteTo(env);
        ReconnectCarry.ClearIn(env);
        Assert.Empty(env);
    }
}
