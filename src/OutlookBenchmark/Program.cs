using System.Reflection;
using RemotePCDiagnostics.Core.OutlookBench;

namespace OutlookBenchmark;

internal static class Program
{
    private const string Help = """
        OutlookBenchmark — measures how fast classic Outlook starts on this PC and records the PC's configuration,
        so results from different PCs can be compared. Nothing on the PC is changed.

        Usage: OutlookBenchmark.exe [options]
          --runs N           normal/safe-mode start pairs (default 3; plus one first start)
          --skip-start-test  only record the PC and Outlook configuration
          --close-outlook    if Outlook is open, close it (like clicking X) instead of waiting
          --anonymize        replace the computer name with a short code
          --no-reference     skip the processor and disk reference tests (~30 s)
          --out DIR          results folder (default: "OutlookBenchmark results" next to this program)
          --yes              don't wait for Enter at the end

        Results: one JSON file per run (everything, including add-in details) and one line per run appended to results.csv.
        Copy the results folders from each PC into one place to compare them.
        """;

    private static int Main(string[] args)
    {
        if (args.Any(a => a is "-h" or "--help" or "/?")) { Console.WriteLine(Help); return 0; }
        int runs = 3;
        var i = Array.IndexOf(args, "--runs");
        if (i >= 0 && i + 1 < args.Length && int.TryParse(args[i + 1], out var n)) runs = Math.Clamp(n, 1, 10);
        var outIdx = Array.IndexOf(args, "--out");
        var outDir = outIdx >= 0 && outIdx + 1 < args.Length ? args[outIdx + 1] : Path.Combine(AppContext.BaseDirectory, "OutlookBenchmark results");
        bool Has(string f) => args.Contains(f, StringComparer.OrdinalIgnoreCase);
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "?";
        var notes = new List<string>();

        Console.WriteLine($"OutlookBenchmark {version}\n");
        Console.WriteLine("Recording this PC's configuration…");
        var system = Probes.System(Has("--anonymize"), !Has("--no-reference"));
        var outlook = Probes.Outlook();
        Console.WriteLine($"  {system.Manufacturer} {system.Model} · {system.Cpu.Name} · {system.Ram.TotalBytes / 1073741824.0:0.#} GB RAM · {system.SystemDisk.MediaType} {system.SystemDisk.BusType}");
        Console.WriteLine(outlook.Installed
            ? $"  Outlook {outlook.Version} ({outlook.Bitness}) · offline mail {outlook.OstGb:0.#} GB · archives {outlook.PstGb:0.#} GB · {outlook.AddinsAtStartup} add-ins at start-up"
            : "  Classic Outlook isn't installed.");

        IReadOnlyList<StartRun> starts = [];
        if (!outlook.Installed) notes.Add("Classic Outlook not installed: start test skipped.");
        else if (outlook.NewOutlookDefault) notes.Add("New Outlook is the default on this PC; the start test times classic Outlook.");
        if (outlook.Installed && !Has("--skip-start-test"))
        {
            if (StartTest.OutlookRunning())
            {
                if (Has("--close-outlook")) { Console.WriteLine("Closing Outlook…"); CloseOutlook(); }
                else
                {
                    Console.WriteLine("\nOutlook is open. Close it (save any drafts first), and the test continues by itself…");
                    var end = DateTime.UtcNow.AddMinutes(10);
                    while (StartTest.OutlookRunning() && DateTime.UtcNow < end) Thread.Sleep(1000);
                }
            }
            if (StartTest.OutlookRunning()) notes.Add("Outlook stayed open: start test skipped.");
            else
            {
                Console.WriteLine($"\nTiming Outlook start-up ({runs * 2 + 1} starts; Outlook will open and close by itself — please don't use the PC meanwhile)…");
                starts = new StartTest(Probes.OutlookExe()!, Probes.DefaultProfile()).Run(runs);
            }
        }

        var summary = StartSummary.From(starts);
        var result = new BenchResult(version, DateTimeOffset.UtcNow, system, outlook, starts, summary, notes);
        Directory.CreateDirectory(outDir);
        var json = Path.Combine(outDir, $"{system.Machine} {result.TimeUtc.ToLocalTime():yyyy-MM-dd HHmm}.json");
        File.WriteAllText(json, result.ToJson());
        var csv = Path.Combine(outDir, "results.csv");
        if (!File.Exists(csv)) File.WriteAllText(csv, string.Join(",", BenchResult.CsvColumns) + Environment.NewLine);
        File.AppendAllText(csv, result.ToCsvRow() + Environment.NewLine);

        Console.WriteLine("\nResult");
        if (summary.NormalMedianS is { } nm) Console.WriteLine($"  Outlook start: {nm:0.0} s normal · {summary.SafeMedianS:0.0} s without add-ins · add-ins cost {summary.AddinCostS:0.0} s · first start {summary.FirstStartS:0.0} s");
        if (summary.PeakWorkingSetMb is { } ws) Console.WriteLine($"  Outlook memory {ws:0} MB · paging {summary.PagesPerSec:0} pages/s · lowest free memory {summary.MinAvailableMb:0} MB");
        foreach (var a in outlook.Addins.Where(a => a.LoadsAtStartup && a.RecordedLoadMs.Count > 0).OrderByDescending(a => a.RecordedLoadMs[0]).Take(5))
            Console.WriteLine($"  Add-in {a.Name}: {a.RecordedLoadMs[0] / 1000.0:0.00} s (Outlook's own measurement)");
        foreach (var x in notes) Console.WriteLine("  Note: " + x);
        Console.WriteLine($"\nSaved: {json}\n       {csv}");
        if (!Has("--yes") && !Console.IsInputRedirected) { Console.WriteLine("\nPress Enter to close."); Console.ReadLine(); }
        return 0;
    }

    private static void CloseOutlook()
    {
        foreach (var p in System.Diagnostics.Process.GetProcessesByName("OUTLOOK"))
        {
            try { p.CloseMainWindow(); p.WaitForExit(60_000); } catch { }
            p.Dispose();
        }
    }
}
