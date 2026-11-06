using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;

namespace SampleModule;

/// <summary>The entry type named in module.json. Registers exactly one module, with the id the manifest declares.</summary>
public sealed class SampleModulePlugin : IModulePlugin
{
    public static readonly Guid Id = new("e38471d6-d5da-4ef8-9063-155f4bd2ec1a");

    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddSingleton<IDiagnosticModule>(new UptimeModule(context.Log));
}

/// <summary>Reports how long Windows has been running. Reads only, changes nothing, needs no administrator.</summary>
public sealed class UptimeModule(ILogger? log) : AreaModuleBase(log)
{
    public override Guid Id => SampleModulePlugin.Id;
    public override string Name => "sample.uptime";
    public override string DisplayName => "Uptime (sample plugin)";
    protected override string FailedMessage => "Couldn't read the uptime.";

    protected override Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var up = TimeSpan.FromMilliseconds(Environment.TickCount64);
        var level = up.TotalDays >= 7 ? AreaLevel.Warning : AreaLevel.Ok;
        var text = up.TotalDays >= 1 ? $"{(int)up.TotalDays} days {up.Hours} hours" : $"{up.Hours} hours {up.Minutes} minutes";
        var card = new AreaCard("uptime", "Uptime", level, text,
            level == AreaLevel.Warning ? "Restart the PC to finish updates and free memory." : "Restarted recently.", ["Since"],
            [new AreaRow(level, [DateTimeOffset.Now.Subtract(up).ToString("g")])]);
        return Task.FromResult(new AreaReport([card], $"Up {text}", AreaReport.Worst([level])));
    }
}
