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
    public void From_writes_short_category_lines_to_an_action_log()
    {
        var lines = new List<string>();
        AppLoggerFactory.From(lines.Add).CreateLogger("RemotePCDiagnostics.Host.ModuleUiFrames").LogInformation("relay up");
        Assert.Equal(["[ModuleUiFrames] relay up"], lines);
    }
}
