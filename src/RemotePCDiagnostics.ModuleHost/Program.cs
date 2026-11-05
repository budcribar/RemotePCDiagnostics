using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;

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
try { module = UserModePlugin.Load(args[0], line => Console.Error.WriteLine(line)).Module; }
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
