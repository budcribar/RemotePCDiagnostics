// Records the raw answers this PC gives to the checks that support record and replay, scrubs personal details, and saves a recording
// folder for the replay tests (docs/record-replay.md). It only reads: no fix runs, nothing on the PC changes.
//
//   dotnet run --project tools/RpcdRecorder -- --out <folder> [--osquery <path to osqueryi.exe>] [--note "text"]
//
// Each check runs twice: once on the new WMI path and once on the old osquery / powercfg path, so the tests can check the two agree.


using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;

var outRoot = Arg("--out") ?? Path.Combine(Environment.CurrentDirectory, "recordings");
var osqueryPath = Arg("--osquery") ?? Environment.GetEnvironmentVariable(OsqueryRunner.PathEnvironmentVariable)
    ?? FirstExisting(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RemotePCDiagnostics", "tools", "osquery", "osqueryi.exe"),
        Path.Combine(AppContext.BaseDirectory, OsqueryRunner.RelativePath));
var note = Arg("--note");

if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("Run this on the Windows PC to record."); return 2; }

var recorder = new CallRecorder();
var liveWmi = new SystemWmiSource();
var wmi = new RecordingWmiSource(liveWmi, recorder);
var launcher = new RecordingProcessLauncher(new SystemProcessLauncher(), recorder);
var osquery = new OsqueryRunner(options: new OsqueryOptions { ExecutablePath = osqueryPath }, launcher: launcher);
var commands = new SystemCommandRunner(launcher);
if (!osquery.Exists) Console.WriteLine($"osqueryi.exe not found ({osqueryPath}); the old osquery path won't be recorded. Pass --osquery <path>.");

var machine = await DescribeMachineAsync(liveWmi);
Console.WriteLine($"Recording {machine.Manufacturer} {machine.Model} (product id {machine.ProductId}), Windows {machine.WindowsVersion} build {machine.WindowsBuild}");

var checks = new (string Label, BatteryPowerModule Module)[]
{
    ("BatteryPower (WMI)", new BatteryPowerModule(osquery, commands, wmi)),
    ("BatteryPower (osquery + powercfg)", new BatteryPowerModule(osquery, commands)),
};
foreach (var (label, module) in checks)
{
    var r = await module.RefreshAsync(null);
    Console.WriteLine($"  {label}: {r.Status} - {r.Message}");
    if (r.Payload is AreaReport report)
        foreach (var card in report.Cards)
            foreach (var row in card.Rows)
                Console.WriteLine($"      {string.Join(": ", row.Values)}");
}

var scrubber = new RecordingScrubber(Environment.MachineName, UserNames());
var recording = scrubber.Scrub(new MachineRecording
{
    Machine = machine with { Notes = note },
    CapturedAt = DateTimeOffset.Now,
    Calls = recorder.Snapshot(),
});
var folder = Path.Combine(outRoot, Safe(machine.ProductId) + "-" + recording.CapturedAt.ToString("yyyyMMdd-HHmm"));
recording.Save(folder);
File.WriteAllLines(Path.Combine(folder, "scrub-report.txt"),
    ["Replaced before saving (placeholder kind: count):", .. scrubber.Counts.Select(c => $"  {c.Key}: {c.Value}")]);
Console.WriteLine($"Saved {recording.Calls.Count} answers to {folder}");
return 0;

string? Arg(string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static string FirstExisting(params string[] paths) => paths.FirstOrDefault(File.Exists) ?? paths[0];

static string Safe(string s)
{
    var chars = s.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_').ToArray();
    var t = new string(chars).Trim('_');
    return t.Length == 0 ? "unknown" : t;
}

/// <summary>The signed-in user and every profile folder's name, so they are replaced wherever they appear.</summary>
static IEnumerable<string> UserNames()
{
    yield return Environment.UserName;
    var users = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", "Users");
    string[] profiles;
    try { profiles = Directory.GetDirectories(users); } catch { yield break; }
    string[] shared = ["Public", "Default", "Default User", "All Users", "defaultuser0", "WDAGUtilityAccount"];
    foreach (var p in profiles)
    {
        var name = Path.GetFileName(p);
        if (!shared.Contains(name, StringComparer.OrdinalIgnoreCase)) yield return name;
    }
}

/// <summary>Which PC this is. Read without recording: it describes the recording rather than being part of it.</summary>
static async Task<RecordedMachine> DescribeMachineAsync(IWmiSource wmi)
{
    async Task<WmiRow?> One(string sql) => (await wmi.QueryAsync(@"root\cimv2", sql)).Rows?.FirstOrDefault();
    var cs = await One("SELECT Manufacturer, Model, SystemSKUNumber, SystemFamily FROM Win32_ComputerSystem");
    var product = await One("SELECT UUID, Name, Version FROM Win32_ComputerSystemProduct");
    var board = await One("SELECT Product FROM Win32_BaseBoard");
    var bios = await One("SELECT SMBIOSBIOSVersion FROM Win32_BIOS");
    var os = await One("SELECT Version, BuildNumber FROM Win32_OperatingSystem");

    var sku = Clean(cs?.Str("SystemSKUNumber"));
    var boardProduct = Clean(board?.Str("Product"));
    var model = Clean(cs?.Str("Model"));
    return new RecordedMachine
    {
        ProductId = sku.Length > 0 ? sku : boardProduct.Length > 0 ? boardProduct : model,
        Manufacturer = Clean(cs?.Str("Manufacturer")),
        Model = model,
        SystemSku = sku,
        SystemFamily = Clean(cs?.Str("SystemFamily")),
        BaseBoardProduct = boardProduct,
        SmbiosUuid = Clean(product?.Str("UUID")),
        BiosVersion = Clean(bios?.Str("SMBIOSBIOSVersion")),
        WindowsVersion = Clean(os?.Str("Version")),
        WindowsBuild = Clean(os?.Str("BuildNumber")),
        AppVersion = typeof(BatteryPowerModule).Assembly.GetName().Version?.ToString() ?? "",
        Elevated = Environment.IsPrivilegedProcess,
    };
}

/// <summary>Firmware placeholders ("To be filled by O.E.M.", "Default string") count as empty.</summary>
static string Clean(string? s)
{
    s = (s ?? "").Trim();
    string[] junk = ["To be filled by O.E.M.", "Default string", "System Product Name", "None", "Not Applicable", "N/A", "0"];
    return junk.Contains(s, StringComparer.OrdinalIgnoreCase) ? "" : s;
}
