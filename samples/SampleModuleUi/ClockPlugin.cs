using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;

namespace SampleModuleUi;

/// <summary>The entry type named in module.json: one module, plus its own details UI.</summary>
public sealed class ClockPlugin : IModulePlugin
{
    public static readonly Guid Id = new("a22691b9-cab4-4006-b4c0-5428268812d6");

    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(new ClockModule(context.Log));
        context.SetDetailsComponent(Id, typeof(ClockDetails));
    }
}

/// <summary>Reports the PC's clock and time zone. Reads only, changes nothing, needs no administrator.</summary>
public sealed class ClockModule(Action<string>? log) : AreaModuleBase(log)
{
    public override Guid Id => ClockPlugin.Id;
    public override string Name => "sample.clock";
    public override string DisplayName => "Clock (sample plugin with its own UI)";
    protected override string FailedMessage => "Couldn't read the clock.";

    protected override Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var zone = TimeZoneInfo.Local;
        var card = new AreaCard("clock", "Clock", AreaLevel.Ok, DateTimeOffset.Now.ToString("g"), zone.DisplayName, ["Time zone", "UTC offset"],
            [new AreaRow(AreaLevel.Ok, [zone.Id, zone.GetUtcOffset(DateTime.Now).ToString()])]);
        return Task.FromResult(new AreaReport([card], $"Local time {DateTimeOffset.Now:t}", AreaReport.Worst([AreaLevel.Ok])));
    }
}
