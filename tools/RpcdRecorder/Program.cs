// Records the raw answers this PC gives to the checks that support record and replay, scrubs personal details, and saves a recording
// folder for the replay tests (docs/record-replay.md). It only reads: no fix runs, nothing on the PC changes.
//
//   dotnet run --project tools/RpcdRecorder -- --out <folder>   (from an admin prompt, as the Agent runs) [--osquery <path to osqueryi.exe>] [--note "text"]
//
// Each check runs twice: once on the new WMI path and once on the old osquery / powercfg / PowerShell path, so the tests can check the two agree.


using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Legacy;

var outRoot = Arg("--out") ?? Path.Combine(Environment.CurrentDirectory, "recordings");
var osqueryPath = Arg("--osquery") ?? Environment.GetEnvironmentVariable(OsqueryRunner.PathEnvironmentVariable)
    ?? FirstExisting(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RemotePCDiagnostics", "tools", "osquery", "osqueryi.exe"),
        Path.Combine(AppContext.BaseDirectory, OsqueryRunner.RelativePath));
var note = Arg("--note");

if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("Run this on the Windows PC to record."); return 2; }
// The app reads WMI through the Agent, which runs as administrator: record from an admin prompt so the answers match.
if (!Environment.IsPrivilegedProcess)
    Console.WriteLine("Not running as administrator. The Agent reads WMI as administrator, so some answers (the power plan) will differ. Run from an admin prompt.");

var recorder = new CallRecorder();
var liveWmi = new SystemWmiSource();
var wmi = new RecordingWmiSource(liveWmi, recorder);
var registry = new RecordingRegistrySource(new SystemRegistrySource(), recorder);
var packages = new RecordingPackageSource(new RemotePCDiagnostics.Host.Platform.SystemPackageSource(), recorder);
var launcher = new RecordingProcessLauncher(new SystemProcessLauncher(), recorder);
var osquery = new OsqueryRunner(options: new OsqueryOptions { ExecutablePath = osqueryPath }, launcher: launcher);
var commands = new SystemCommandRunner(launcher);
if (!osquery.Exists) Console.WriteLine($"osqueryi.exe not found ({osqueryPath}); the old osquery path won't be recorded. Pass --osquery <path>.");

var machine = await DescribeMachineAsync(liveWmi);
Console.WriteLine($"Recording {machine.Manufacturer} {machine.Model} (product id {machine.ProductId}), Windows {machine.WindowsVersion} build {machine.WindowsBuild}");

// Nothing is saved on this PC: drive history is kept in memory, and free space and retrim history aren't part of a recording yet.
DriveHealthModule Drives(IDriveSource source) => new(source, historyStore: new DriveHealthHistoryStore(), volumes: () => []);
// The commands go through the recording launcher, so they count as scripted: the legacy problem devices come from the PowerShell script
// (which can be replayed), not WMI read in this process.
var checks = new (string Label, IDiagnosticModule Module)[]
{
    ("BatteryPower (WMI)", new BatteryPowerModule(new WmiBatteryPowerSource(wmi))),
    ("BatteryPower (legacy: osquery + powercfg)", new BatteryPowerModule(new OsqueryBatteryPowerSource(osquery, commands))),
    ("DriveHealth (WMI)", Drives(new WmiDriveSource(wmi))),
    ("DriveHealth (legacy: PowerShell)", Drives(new PowerShellDriveSource(commands, osquery))),
    ("Hardware inventory (WMI)", new OsqueryModule(new WmiHardwareInventorySource(wmi))),
    ("Hardware inventory (legacy: osquery)", new OsqueryModule(new OsqueryHardwareInventorySource(osquery))),
    ("Services (WMI)", new ServicesModule(new WmiServiceSource(wmi))),
    ("Services (legacy: osquery)", new ServicesModule(new OsqueryServiceSource(osquery))),
    ("Device Manager & drivers (WMI)", new DeviceDriversModule(new WmiDeviceDriverSource(wmi))),
    ("Device Manager & drivers (legacy: PowerShell + osquery)", new DeviceDriversModule(new OsqueryDeviceDriverSource(osquery, commands))),
    ("Programs & updates (WMI + registry)", new ProgramsModule(new WmiProgramsSource(wmi, registry, packages))),
    ("Programs & updates (legacy: osquery)", new ProgramsModule(new OsqueryProgramsSource(osquery))),
    // Without netsh and the event logs (Wi-Fi and event names hold the network's name and its router's address) and offline (no probes or DNS timing).
    ("Network (WMI + registry)", new NetworkModule(new WmiNetworkSource(wmi, registry), includeWifiAndIpConfig: true, offline: true)),
    ("Network (legacy: osquery + PowerShell)", new NetworkModule(new OsqueryNetworkSource(osquery, commands), includeWifiAndIpConfig: true, offline: true)),
};
foreach (var (label, module) in checks)
{
    var r = await module.RefreshAsync(null);
    Console.WriteLine($"  {label}: {r.Status} - {r.Message}");
    // Long lists (services, drivers, programs) print only their size.
    if (r.Payload is AreaReport report)
        foreach (var card in report.Cards)
        {
            if (card.Rows.Count > 12) { Console.WriteLine($"      {card.Title}: {card.Rows.Count} rows"); continue; }
            foreach (var row in card.Rows)
                Console.WriteLine($"      {string.Join(": ", row.Values)}");
        }
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
        ProductId = ProductId(Clean(cs?.Str("Manufacturer")), sku, boardProduct, model),
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

/// <summary>
/// The BIOS identifier that names the hardware platform. HP's is the System Board ID (Win32_BaseBoard.Product, "8CBE" on the OmniBook X 14
/// and EliteBook Ultra G1q), so its recordings are keyed by maker and board ("HP-8CBE"). Other makers' board names are generic (Lenovo's
/// "LNVNB161216"), so their SKU is used, which on Lenovo holds the machine type ("LENOVO_MT_82R4_…").
/// </summary>
static string ProductId(string manufacturer, string sku, string boardProduct, string model)
{
    var hp = manufacturer.Equals("HP", StringComparison.OrdinalIgnoreCase) || manufacturer.StartsWith("Hewlett", StringComparison.OrdinalIgnoreCase);
    if (hp && boardProduct.Length > 0) return "HP-" + boardProduct;
    return sku.Length > 0 ? sku : boardProduct.Length > 0 ? boardProduct : model;
}

/// <summary>Firmware placeholders ("To be filled by O.E.M.", "Default string") count as empty.</summary>
static string Clean(string? s)
{
    s = (s ?? "").Trim();
    string[] junk = ["To be filled by O.E.M.", "Default string", "System Product Name", "None", "Not Applicable", "N/A", "0"];
    return junk.Contains(s, StringComparer.OrdinalIgnoreCase) ? "" : s;
}
