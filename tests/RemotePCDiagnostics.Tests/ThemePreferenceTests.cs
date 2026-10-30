using RemotePCDiagnostics.Core.Theming;

public class ThemePreferenceTests
{
    [Theory]
    [InlineData("dark", ThemeChoice.Dark)]
    [InlineData("LIGHT", ThemeChoice.Light)]
    [InlineData(" system ", ThemeChoice.System)]
    [InlineData(null, ThemeChoice.System)]
    [InlineData("", ThemeChoice.System)]
    [InlineData("purple", ThemeChoice.System)]
    public void Parse_FallsBackToSystem(string? input, ThemeChoice expected) => Assert.Equal(expected, ThemePreference.Parse(input));

    [Theory]
    [InlineData(ThemeChoice.Dark, false, "dark")]
    [InlineData(ThemeChoice.Dark, true, "dark")]
    [InlineData(ThemeChoice.Light, true, "light")]
    [InlineData(ThemeChoice.System, true, "dark")]
    [InlineData(ThemeChoice.System, false, "light")]
    public void Resolve_FollowsOsOnlyForSystem(ThemeChoice c, bool osDark, string expected) => Assert.Equal(expected, ThemePreference.Resolve(c, osDark));

    [Fact]
    public void Storage_RoundTrips()
    {
        foreach (var c in Enum.GetValues<ThemeChoice>()) Assert.Equal(c, ThemePreference.Parse(ThemePreference.ToStorage(c)));
        Assert.Equal(ThemeChoice.System, ThemePreference.Default);
    }
}
