using System.Diagnostics;
using System.Globalization;
using RemotePCDiagnostics.Core.Stress;

// Usage: RemotePCDiagnostics.MemTest --bytes <n> --seconds <n>
// Writes MemTestMessage lines to stdout. Exit 0 = finished (see DONE errors), 1 = failed, 2 = bad arguments.
static void Emit(MemTestMessage m) { Console.Out.WriteLine(m.Format()); Console.Out.Flush(); }

long bytes = 0, seconds = 0;
for (int i = 0; i + 1 < args.Length; i += 2)
{
    if (args[i] == "--bytes") long.TryParse(args[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out bytes);
    else if (args[i] == "--seconds") long.TryParse(args[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out seconds);
}
if (bytes <= 0 || seconds <= 0) { Emit(new MemTestMessage.Fail("usage: --bytes <n> --seconds <n>")); return 2; }

try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
try { Thread.CurrentThread.Priority = ThreadPriority.BelowNormal; } catch { }

var sw = Stopwatch.StartNew();
var deadline = TimeSpan.FromSeconds(seconds);
var blocks = new List<IMemoryBlock>();
try
{
    long chunk = Math.Min(MemorySizing.ChunkBytes, bytes), allocated = 0;
    try
    {
        while (allocated < bytes && sw.Elapsed < deadline)
        {
            var size = Math.Min(chunk, bytes - allocated);
            size -= size % 4096;
            if (size <= 0) break;
            blocks.Add(new NativeMemoryBlock(size));
            allocated += size;
        }
    }
    catch (OutOfMemoryException)
    {
        Console.Error.WriteLine($"allocation stopped at {allocated} bytes (out of memory)");
    }
    if (blocks.Count == 0) { Emit(new MemTestMessage.Fail("could not allocate memory")); return 1; }
    Emit(new MemTestMessage.Allocated(allocated));

    var sweep = new MemorySweep(blocks, () => sw.Elapsed >= deadline, Emit);
    sweep.Run();
    return 0;
}
catch (Exception ex)
{
    Emit(new MemTestMessage.Fail(ex.GetType().Name + ": " + ex.Message));
    return 1;
}
finally
{
    foreach (var b in blocks) b.Dispose();
}
