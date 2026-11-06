using Microsoft.Extensions.Logging;
using RemotePCDiagnostics.Core.Logging;
using AppLevel = RemotePCDiagnostics.Core.Logging.LogLevel;
using MelLevel = Microsoft.Extensions.Logging.LogLevel;

namespace RemotePCDiagnostics.Tests;

/// <summary>ILogger&lt;T&gt; over the app's sinks: the level comes from the call, not from the wording.</summary>
public sealed class AppLoggerTests
{
    private readonly List<(AppLevel Level, string Category, string Message)> _lines = [];
    private AppLoggerFactory Factory => new((l, c, m) => _lines.Add((l, c, m)));

    [Fact]
    public void Level_and_category_come_from_the_call()
    {
        var log = Factory.CreateLogger<AppLoggerTests>();
        log.LogInformation("Scan failed to find anything"); // wording that the text classifier would call a warning
        log.LogWarning("Disk {Disk} is hot", "C:");
        log.LogCritical("Gone");
        Assert.Equal([AppLevel.Information, AppLevel.Warning, AppLevel.Error], _lines.Select(l => l.Level));
        Assert.Equal("Disk C: is hot", _lines[1].Message);
        Assert.Equal(typeof(AppLoggerTests).FullName, _lines[0].Category);
    }

    [Fact]
    public void Debug_and_framework_information_are_dropped()
    {
        var factory = Factory;
        factory.CreateLogger("RemotePCDiagnostics.X").LogDebug("noise");
        factory.CreateLogger("Microsoft.AspNetCore.Components.RenderTree").LogInformation("noise");
        factory.CreateLogger("Microsoft.AspNetCore.Components.RenderTree").LogWarning("kept");
        Assert.Equal(["kept"], _lines.Select(l => l.Message));
        Assert.False(factory.CreateLogger("System.Net").IsEnabled(MelLevel.Information));
    }

    [Fact]
    public void An_exception_is_summarised_on_the_line()
    {
        Factory.CreateLogger("C").LogError(new InvalidOperationException("boom"), "Start failed");
        Assert.Equal("Start failed (InvalidOperationException: boom)", _lines.Single().Message);
    }

    [Fact]
    public void Plain_lines_keep_the_level_of_the_call_and_their_text_as_is()
    {
        var log = Factory.CreateLogger("RemotePCDiagnostics.Core.X");
        log.Info("Scan failed to find anything {not a template}");
        log.Warn("Disk is hot");
        log.Error("Gone");
        log.Line("Restore failed: access denied"); // wording from elsewhere: level read from the text
        Assert.Equal([AppLevel.Information, AppLevel.Warning, AppLevel.Error, AppLevel.Warning], _lines.Select(l => l.Level));
        Assert.Equal("Scan failed to find anything {not a template}", _lines[0].Message);
        ILogger? none = null;
        none.Info("nothing happens");
    }

    [Fact]
    public void LineLogger_bridges_text_callbacks()
    {
        var lines = new List<string>();
        var log = new LineLogger(lines.Add);
        log.Warn("one");
        log.Line("two failed: x");
        Assert.Equal(["one", "two failed: x"], lines);
        Assert.Null(LineLogger.From(null));
    }

    [Fact]
    public void From_writes_short_category_lines_to_an_action_log()
    {
        var lines = new List<string>();
        AppLoggerFactory.From(lines.Add).CreateLogger("RemotePCDiagnostics.Host.ModuleUiFrames").LogInformation("relay up");
        Assert.Equal(["[ModuleUiFrames] relay up"], lines);
    }
}
