using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>The count behind the top bar's "N Remote Users" badge.</summary>
public class RemoteUsersTests
{
    [Theory]
    [InlineData(0, "0 Remote Users")]
    [InlineData(1, "1 Remote User")]
    [InlineData(2, "2 Remote Users")]
    [InlineData(12, "12 Remote Users")]
    public void Label_counts_with_the_singular_for_one(int count, string expected) =>
        Assert.Equal(expected, RemoteUsers.Label(count));

    [Fact]
    public void Changed_is_raised_only_when_the_count_moves()
    {
        var users = new RemoteUsers();
        int raised = 0;
        users.Changed += () => raised++;

        users.Set(0);
        Assert.Equal(0, raised);
        users.Set(2);
        users.Set(2);
        Assert.Equal(1, raised);
        Assert.Equal(2, users.Count);
        users.Set(-3); // never below zero
        Assert.Equal(0, users.Count);
        Assert.Equal(2, raised);
    }
}
