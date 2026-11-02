using System.Diagnostics;
using System.Text;
using System.Text.Json;
using RemotePCDiagnostics.Core.NetworkUsage;

namespace NetworkUsagePrototype;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Contains("--help"))
        {
            Console.WriteLine("NetworkUsagePrototype [--days 1..30] [--out folder] [--srum | --srum-copy file | --demo]\nDefault: read Windows historical usage API. --srum: run as administrator; acquire a VSS-recovered COPY of SRUM with Windows esentutl, then read the copy. No service/configuration changes. --srum-copy: analyze an existing copy. --demo: synthetic data, for report testing only.");
            return 0;
        }
        var interactive = args.Length == 0;
        string? output = null;
        var diagnostics = new List<string>();
        try
        {
            for (var i = 0; i < args.Length; i++)
            {
                if (args[i] is "--days" or "--out" or "--srum-copy")
                {
                    if (++i >= args.Length || args[i].StartsWith("--")) throw new ArgumentException("Missing argument value.");
                }
                else if (args[i] is not ("--srum" or "--demo")) throw new ArgumentException("Unknown argument: " + args[i]);
            }
            string? Value(string key)
            {
                var index = Array.IndexOf(args, key);
                if (index < 0) return null;
                if (index + 1 >= args.Length || args[index + 1].StartsWith("--")) throw new ArgumentException("Missing value for " + key);
                return args[index + 1];
            }
            var days = int.Parse(Value("--days") ?? "7");
            if (days is < 1 or > 30) throw new ArgumentException("--days must be 1 through 30.");
            var copy = Value("--srum-copy");
            var modeCount = (copy is null ? 0 : 1) + (args.Contains("--srum") ? 1 : 0) + (args.Contains("--demo") ? 1 : 0);
            if (modeCount > 1) throw new ArgumentException("Choose only one source mode.");
            output = Path.GetFullPath(Value("--out") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "Remote PC Diagnostics", "Network usage", DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6]));
            if (Directory.Exists(output) && Directory.EnumerateFileSystemEntries(output).Any()) throw new IOException("Output directory must be new or empty.");
            Directory.CreateDirectory(output);
            var now = DateTime.UtcNow;
            var end = new DateTimeOffset(now.Date.AddHours(now.Hour), TimeSpan.Zero);
            var start = end.AddDays(-days);
            diagnostics.Add($"Windows {Environment.OSVersion}; machine {Environment.MachineName}; requested UTC window {start:O} to {end:O}");
            Console.WriteLine("Reading existing Windows history. No apps will be stopped and no network settings changed.");
            NetworkUsageReport report;
            try
            {
                if (args.Contains("--demo"))
                    report = new("DEMO — synthetic fixture, not this computer", start, end,
                        [new("demo-browser", "Example Browser", "Demo user", "Demo adapter", end.AddHours(-1), 12_000_000, 950_000_000)], ["DEMO DATA ONLY"]);
                else if (copy is not null || args.Contains("--srum"))
                {
                    // Always work on a fresh private copy; never attach ESE to the supplied/live database.
                    var work = Directory.CreateDirectory(Path.Combine(output, "srum-work")).FullName;
                    var database = Path.Combine(work, "SRUDB.dat");
                    if (copy is not null) File.Copy(Path.GetFullPath(copy), database, overwrite: false);
                    else await CaptureSrumAsync(database, diagnostics);
                    report = SrumReader.Read(database, start, end);
                }
                else report = await WindowsUsage.ReadAsync(start, end);
            }
            catch (Exception ex)
            {
                diagnostics.Add(ex.ToString());
                report = new(copy is not null || args.Contains("--srum") ? "SRUM read failed" : "Windows usage API failed", start, end, [],
                    [$"History unavailable: {ex.GetType().Name}: {ex.Message}", "Try --srum from an administrator terminal if API access is restricted. If SRUM acquisition/reading fails, keep diagnostics.json; the prototype does not repair the live database or stop its service."]);
            }
            if (!args.Contains("--demo")) report = report with { Entries = ProgramNames.Resolve(report.Entries) };
            diagnostics.AddRange(report.Warnings);
            await File.WriteAllTextAsync(Path.Combine(output, "network-usage.html"), report.ToHtml(), Encoding.UTF8);
            await File.WriteAllTextAsync(Path.Combine(output, "network-usage.csv"), report.ToCsv(), Encoding.UTF8);
            await File.WriteAllTextAsync(Path.Combine(output, "network-usage.json"), JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            await File.WriteAllTextAsync(Path.Combine(output, "diagnostics.json"), JsonSerializer.Serialize(diagnostics, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"\nReport: {Path.Combine(output, "network-usage.html")}");
            foreach (var app in report.TopApps()) Console.WriteLine($"{app.App}: {NetworkUsageReport.Size(app.Total)} total ({NetworkUsageReport.Size(app.Downloaded)} down, {NetworkUsageReport.Size(app.Uploaded)} up)");
            foreach (var warning in report.Warnings) Console.WriteLine("NOTE: " + warning);
            if (report.Entries.Count == 0) Console.WriteLine("No attributed history available. This does not mean zero usage.");
            return report.Entries.Count > 0 ? 0 : 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
        finally
        {
            if (interactive && !Console.IsInputRedirected) { Console.WriteLine("Press Enter to close."); Console.ReadLine(); }
        }
    }

    private static async Task CaptureSrumAsync(string destination, List<string> diagnostics)
    {
        var directory = Path.Combine(Environment.SystemDirectory, "sru");
        var source = Path.Combine(directory, "SRUDB.dat");
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "esentutl.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
            RedirectStandardError = true, WorkingDirectory = Path.GetDirectoryName(destination)!
        };
        // Recovery is performed within the transient VSS snapshot, not against the live database.
        foreach (var argument in new[] { "/y", source, "/d", destination, "/vssrec", "sru", directory, "/o" }) psi.ArgumentList.Add(argument);
        diagnostics.Add("Acquisition: esentutl /y SRUDB.dat /vssrec sru (VSS snapshot recovery and copy)");
        using var process = Process.Start(psi) ?? throw new IOException("Could not launch esentutl.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromMinutes(2)); }
        catch (TimeoutException) { process.Kill(entireProcessTree: true); throw new IOException("SRUM acquisition timed out after two minutes."); }
        diagnostics.Add(await stdout);
        diagnostics.Add(await stderr);
        if (process.ExitCode != 0 || !File.Exists(destination)) throw new IOException($"SRUM snapshot acquisition failed (exit {process.ExitCode}). Run --srum as administrator; see diagnostics.json.");
    }
}
