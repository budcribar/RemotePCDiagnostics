// Serves the real RPCD pages and checks on a recorded PC, and injects faults into its answers on demand (docs/fault-injection.md).
//
//   dotnet run --project tools/RpcdReplayHost -- --recording <folder> [--port 5099] [--faults plan.json] [--store]
//
// --store runs the Store edition's readers without an Agent (osquery, PowerShell, powercfg) instead of WMI through the Agent.
// Test endpoints (this host only, never the app):
//   POST   /_test/faults   body: { "rules": [ ... ] }  replaces the faults in force
//   DELETE /_test/faults                               no faults
//   GET    /_test/faults                               the rules and each fault injected since they were set
//   GET    /_test/asked                                every question the checks asked (RecordingReplay.Key), for the fault matrix
//   GET    /_test/misses                               questions the recording doesn't hold (the check asks something new: record again)
//   GET    /_test/questions?since=N                    the questions asked, in order, from the Nth on (which ones one check asked)
//   GET    /_test/errors                               errors logged (unhandled exceptions in a page or check)
//   DELETE /_test/errors                               forget them
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Tests.Replay;
using RpcdReplayHost;

var options = ReplayHostOptions.Parse(args);
ReplayHostOptions.Current = options;
var recording = MachineRecording.Load(options.RecordingFolder);
var faults = new FaultPlan(options.FaultsFile is { } f ? FaultPlan.Parse(await File.ReadAllTextAsync(f)) : null);
var pc = new ReplayedPc(recording, faults);
var errors = new ErrorLog();

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [], EnvironmentName = "Development" });
builder.WebHost.UseUrls($"http://127.0.0.1:{options.Port}");
builder.Logging.AddProvider(errors);
builder.Services.AddRazorComponents().AddInteractiveServerComponents(o => o.DetailedErrors = true);
builder.Services.AddSingleton(faults);
builder.Services.AddSingleton(pc);
builder.Services.AddSingleton(errors);
ReplayServices.Add(builder.Services, pc, options);

var app = builder.Build();
app.UseStaticFiles();
app.UseAntiforgery();
app.MapStaticAssets();

app.MapPost("/_test/faults", async (HttpRequest req) =>
{
    using var reader = new StreamReader(req.Body);
    faults.Set(FaultPlan.Parse(await reader.ReadToEndAsync()));
    return Results.Ok(new { rules = faults.Rules.Count });
});
app.MapDelete("/_test/faults", () => { faults.Clear(); return Results.Ok(); });
app.MapGet("/_test/faults", () => Results.Json(new { rules = faults.Rules, hits = faults.Hits }, FaultPlan.Json));
app.MapGet("/_test/asked", () => Results.Json(pc.Replay.Asked.Order(StringComparer.Ordinal)));
app.MapGet("/_test/misses", () => Results.Json(pc.Replay.Misses.Distinct()));
app.MapGet("/_test/questions", (int? since) => Results.Json(new { count = faults.QuestionCount, questions = faults.Questions(since ?? 0) }));
app.MapGet("/_test/errors", () => Results.Json(errors.Entries));
app.MapDelete("/_test/errors", () => { errors.Clear(); return Results.Ok(); });

app.MapRazorComponents<RpcdReplayHost.Components.App>()
    .AddInteractiveServerRenderMode()
    .AddAdditionalAssemblies(typeof(RemotePCDiagnostics.UI.AppServices).Assembly);

Console.WriteLine($"RPCD replay of {options.RecordingName} on http://127.0.0.1:{options.Port}{(options.Store ? " (Store edition readers)" : "")}");
await app.RunAsync();
