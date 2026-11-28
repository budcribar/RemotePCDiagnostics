namespace RemotePCDiagnostics.Core.Display;

/// <summary>
/// One monitor Windows shows the desktop on, as the app's window can be placed on it. <see cref="Id"/> is the GDI device name
/// (<c>\\.\DISPLAY1</c>), stable while the PC runs. The rectangle is the monitor's, in physical pixels, in desktop coordinates.
/// </summary>
public sealed record ScreenInfo(string Id, string Name, bool Primary, int X, int Y, int Width, int Height);

/// <summary>
/// The screens the full-screen display test can use, and the short screen off and on check. Read in the app (no administrator rights):
/// placing the app's own window and turning the displays off for a moment both work as the signed-in user.
/// </summary>
public interface IScreenControl
{
    /// <summary>The monitors showing the desktop, primary first. Empty when they can't be read (the test then uses the app's screen).</summary>
    IReadOnlyList<ScreenInfo> ListScreens();

    /// <summary>
    /// Turns every display off for <paramref name="off"/>, then back on. Null when it ran; otherwise why it couldn't (the check is then
    /// Not supported). Whether the picture really came back only the person can say.
    /// </summary>
    Task<string?> BlankScreensAsync(TimeSpan off, CancellationToken ct = default);
}

/// <summary>The color channels the number check draws in: each number is drawn only in that channel on black.</summary>
public enum ColorChannel { Red, Green, Blue }

/// <summary>One color channel's number: the one shown and the one the person typed (null when they typed none).</summary>
public sealed record ColorChannelAnswer(ColorChannel Channel, int Shown, int? Entered)
{
    public bool Passed => Entered == Shown;
}

/// <summary>Where a screen's color number check is.</summary>
public enum ColorCheckState { NotRun, WaitingForAnswers, Passed, Failed }

/// <summary>The display test on one screen: the patterns looked at and the color number check.</summary>
public sealed record DisplayScreenResult(
    string ScreenId,
    string Name,
    bool Primary = false,
    int? Width = null,
    int? Height = null,
    int PatternsInspected = 0,
    /// <summary>The numbers shown, in red, green and blue order. Null until the number step shows on this screen.</summary>
    IReadOnlyList<int>? ShownNumbers = null,
    /// <summary>The graded answers. Null until the person submits them.</summary>
    IReadOnlyList<ColorChannelAnswer>? Answers = null,
    DateTimeOffset? CheckedUtc = null)
{
    public ColorCheckState ColorCheck =>
        Answers is { Count: > 0 } a ? (a.All(x => x.Passed) ? ColorCheckState.Passed : ColorCheckState.Failed)
        : ShownNumbers is { Count: > 0 } ? ColorCheckState.WaitingForAnswers
        : ColorCheckState.NotRun;

    public IReadOnlyList<ColorChannel> FailedChannels =>
        Answers is null ? [] : [.. Answers.Where(a => !a.Passed).Select(a => a.Channel)];
}

/// <summary>The screen off and on check: did every screen come back after the displays were turned off for a moment.</summary>
public enum BlankScreenOutcome { NotRun, Returned, DidNotReturn, NotSupported }

/// <summary>
/// The objective part of the display test. On a black background three numbers are drawn, one only in red, one only in green and one
/// only in blue; a channel that doesn't light leaves its number invisible, so a wrong or missing answer fails that channel without asking
/// the person to judge the colors.
/// </summary>
public static class DisplayColorCheck
{
    public static readonly IReadOnlyList<ColorChannel> Channels = [ColorChannel.Red, ColorChannel.Green, ColorChannel.Blue];

    /// <summary>How long the displays stay off in the screen off and on check.</summary>
    public static readonly TimeSpan BlankDuration = TimeSpan.FromSeconds(2);

    /// <summary>Three different two-digit numbers (10 to 99), one per channel, so a guess is right about once in 90 tries.</summary>
    public static IReadOnlyList<int> NewNumbers(Random? random = null)
    {
        var rng = random ?? Random.Shared;
        var picked = new List<int>(3);
        while (picked.Count < 3)
        {
            var n = rng.Next(10, 100);
            if (!picked.Contains(n)) picked.Add(n);
        }
        return picked;
    }

    /// <summary>
    /// Reads what the person typed for one channel: digits only, spaces ignored. Null when nothing usable was typed (that channel fails).
    /// </summary>
    public static int? ParseAnswer(string? typed)
    {
        if (string.IsNullOrWhiteSpace(typed)) return null;
        var value = 0;
        var digits = 0;
        foreach (var c in typed)
        {
            if (char.IsWhiteSpace(c)) continue;
            if (c is < '0' or > '9') return null;
            if (++digits > 6) return null;
            value = value * 10 + (c - '0');
        }
        return value;
    }

    /// <summary>Grades the typed answers against the numbers shown, in channel order.</summary>
    public static IReadOnlyList<ColorChannelAnswer> Grade(IReadOnlyList<int> shown, IReadOnlyList<string?> typed)
    {
        ArgumentNullException.ThrowIfNull(shown);
        ArgumentNullException.ThrowIfNull(typed);
        if (shown.Count != Channels.Count) throw new ArgumentException("One number per channel.", nameof(shown));
        return [.. Channels.Select((ch, i) => new ColorChannelAnswer(ch, shown[i], ParseAnswer(i < typed.Count ? typed[i] : null)))];
    }

    /// <summary>The CSS color a channel's number is drawn in: full intensity in that channel only.</summary>
    public static string Hex(ColorChannel channel) => channel switch
    {
        ColorChannel.Red => "#FF0000",
        ColorChannel.Green => "#00FF00",
        _ => "#0000FF",
    };

    public static string Name(ColorChannel channel) => channel switch
    {
        ColorChannel.Red => "red",
        ColorChannel.Green => "green",
        _ => "blue",
    };

    /// <summary>"red", "red and blue", "red, green and blue".</summary>
    public static string Names(IReadOnlyList<ColorChannel> channels) => channels.Count switch
    {
        0 => "",
        1 => Name(channels[0]),
        _ => string.Join(", ", channels.Take(channels.Count - 1).Select(Name)) + " and " + Name(channels[^1]),
    };

    /// <summary>One line for a screen whose color check ran: "Red channel failed on DELL U2720Q", "Color channels OK".</summary>
    public static string Summary(DisplayScreenResult screen) => screen.ColorCheck switch
    {
        ColorCheckState.Passed => $"Color channels OK on {screen.Name}",
        ColorCheckState.Failed => $"{Capitalize(Names(screen.FailedChannels))} {(screen.FailedChannels.Count == 1 ? "channel" : "channels")} failed on {screen.Name}",
        ColorCheckState.WaitingForAnswers => $"Waiting for the color numbers on {screen.Name}",
        _ => $"Color numbers not checked on {screen.Name}",
    };

    private static string Capitalize(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];

    /// <summary>
    /// The display test's verdict once the person has finished: a failed color channel on any screen, or a screen that didn't come back
    /// after the screen off and on check, fails it whatever button was pressed. Otherwise the person's choice stands.
    /// </summary>
    public static Workflow.PhysicalCheckOutcome Effective(Workflow.PhysicalCheckOutcome chosen, IReadOnlyList<DisplayScreenResult>? screens,
        BlankScreenOutcome blank)
    {
        if (chosen == Workflow.PhysicalCheckOutcome.NotRun) return chosen;
        if (blank == BlankScreenOutcome.DidNotReturn) return Workflow.PhysicalCheckOutcome.Failed;
        if (screens is not null && screens.Any(s => s.ColorCheck == ColorCheckState.Failed)) return Workflow.PhysicalCheckOutcome.Failed;
        return chosen;
    }
}

/// <summary>No screen control here (tests, replay, non-Windows): the app's own screen only, and no screen off and on check.</summary>
public sealed class NullScreenControl : IScreenControl
{
    public IReadOnlyList<ScreenInfo> ListScreens() => [];

    public Task<string?> BlankScreensAsync(TimeSpan off, CancellationToken ct = default) =>
        Task.FromResult<string?>("The screens can't be turned off from here.");
}
