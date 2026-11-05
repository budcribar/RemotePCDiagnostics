using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Session;

// RemotePCDiagnostics.ModuleHost "<module.dll>"
// Loads one module into its own load context and answers the app's requests (one JSON line each) until stdin closes or "exit".
// Everything here runs with the token the app gave it: no administrator, Medium integrity.
if (args.Length < 1) { Console.Error.WriteLine("usage: RemotePCDiagnostics.ModuleHost <module.dll>"); return 2; }

// The protocol owns stdout; anything the module prints goes to stderr (the app's log).
var output = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = false };
Console.SetOut(Console.Error);
var writeGate = new object();
void Send(ModuleHostMessage m) { lock (writeGate) { output.WriteLine(m.ToLine()); output.Flush(); } }

IDiagnosticModule module;
try { module = Load(args[0]); }
catch (Exception ex)
{
    Send(new ModuleHostMessage { Type = "error", Message = $"Couldn't load the module: {ex.GetType().Name}: {ex.Message}" });
    return 1;
}
Send(new ModuleHostMessage { Type = "ready", Message = module.Name });

CancellationTokenSource? running = null;
Task? refresh = null;
while (Console.In.ReadLine() is { } line)
{
    var request = ModuleHostMessage.Parse(line);
    switch (request?.Type)
    {
        case "availability":
            try
            {
                var a = await module.CheckAvailabilityAsync();
                Send(new ModuleHostMessage { Type = "availability", Available = a.IsAvailable, Reason = a.Reason });
            }
            catch (Exception ex) { Send(new ModuleHostMessage { Type = "availability", Available = false, Reason = ex.Message }); }
            break;
        case "refresh":
            if (refresh is { IsCompleted: false }) { Send(new ModuleHostMessage { Type = "error", Message = "already running" }); break; }
            running = new CancellationTokenSource();
            var ct = running.Token;
            refresh = Task.Run(async () =>
            {
                var progress = CheckProgressExtensions.Create(p => Send(new ModuleHostMessage { Type = "progress", Message = p.Message, Step = p.Step, Total = p.Total }));
                try
                {
                    var r = await module.RefreshAsync(progress, ct);
                    Send(new ModuleHostMessage
                    {
                        Type = "result", Status = r.Status, Message = r.Message, Cancelled = r.Cancelled || ct.IsCancellationRequested, Report = r.Payload as AreaReport,
                    });
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    Send(new ModuleHostMessage { Type = "result", Status = DiagnosticStatus.Warning, Message = "Cancelled", Cancelled = true });
                }
                catch (Exception ex) { Send(new ModuleHostMessage { Type = "error", Message = $"{ex.GetType().Name}: {ex.Message}" }); }
            });
            break;
        case "stop":
            try { running?.Cancel(); } catch (ObjectDisposedException) { }
            break;
        case "exit":
            return 0;
    }
}
try { running?.Cancel(); } catch { }
return 0;

static IDiagnosticModule Load(string path)
{
    var dll = File.ReadAllBytes(path);
    var (manifest, _) = ModuleManifest.ReadFromAssembly(dll);
    if (manifest.Problem(new Version(int.MaxValue, 0)) is { } problem && !problem.StartsWith("needs app version", StringComparison.Ordinal))
        throw new InvalidDataException(problem);
    var alc = new ModuleLoadContext(manifest.Slug, dll);
    var asm = alc.LoadFromStream(new MemoryStream(dll, writable: false));
    var entry = asm.GetType(manifest.EntryType, throwOnError: false) ?? throw new InvalidDataException($"entryType {manifest.EntryType} not found");
    if (Activator.CreateInstance(entry) is not IModulePlugin plugin) throw new InvalidDataException($"{manifest.EntryType} does not implement IModulePlugin");
    var services = new ServiceCollection();
    plugin.Register(services, new HostContext(manifest.Slug));
    var sp = services.BuildServiceProvider();
    var modules = sp.GetServices<IDiagnosticModule>().ToList();
    if (modules.Count != 1) throw new InvalidDataException($"registered {modules.Count} modules; a plugin registers exactly one");
    if (modules[0].Id != manifest.Id) throw new InvalidDataException($"registered module {modules[0].Id}, but its manifest says {manifest.Id}");
    return modules[0];
}

sealed class HostContext(string pluginId) : IPluginContext
{
    public string PluginId => pluginId;
    // Remote rules still apply in the app (actor attribution, notices); the module host itself never acts for a technician.
    public ISessionContext Session { get; } = new SessionContext(SessionMode.Local);
    public Version HostVersion => typeof(HostContext).Assembly.GetName().Version ?? new Version(0, 0);
    public Version ContractVersion => RemotePCDiagnostics.Core.Plugins.ContractVersion.Current;
    public void Log(string message) { try { Console.Error.WriteLine($"[{pluginId}] {message}"); } catch { } }
    public void SetDetailsComponent(Guid moduleId, Type component) { } // UI in the module host comes with the iframe work
}
