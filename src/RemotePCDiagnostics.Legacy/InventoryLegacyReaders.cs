using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Legacy;

/// <summary>Hardware inventory from osquery (system_info, cpu_info, memory_devices, disk_info, video_info, interface_details, platform_info).</summary>
public sealed class OsqueryHardwareInventorySource(OsqueryRunner runner) : IHardwareInventorySource
{
    /// <summary>The same words as OsqueryModule.ToolMissingMessage.</summary>
    public const string ToolMissingMessage = "The hardware tool wasn't found. Please reinstall the app.";

    public Task<HardwareInventory> ReadAsync(IProgress<string>? progress, CancellationToken ct) => CollectAsync(runner, progress, ct);

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => LegacyAvailability.Of(runner, ToolMissingMessage);

    public static async Task<HardwareInventory> CollectAsync(OsqueryRunner runner, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        async Task<OsqueryQueryResult> Q(int step, string msg, string sql) { progress.ReportStep(step, HardwareInventory.SectionCount, msg); return await runner.RunQueryAsync(sql, ct).ConfigureAwait(false); }
        var sys = InventorySection<SystemInfo>.From(await Q(1, "Reading computer details…", HardwareInventory.SystemSql).ConfigureAwait(false), SystemInfo.FromRow);
        var cpu = InventorySection<CpuInfo>.From(await Q(2, "Reading processor details…", HardwareInventory.CpuSql).ConfigureAwait(false), CpuInfo.FromRow);
        var mem = InventorySection<MemoryDevice>.From(await Q(3, "Reading memory modules…", HardwareInventory.MemorySql).ConfigureAwait(false), MemoryDevice.FromRow);
        var disk = InventorySection<DiskInfo>.From(await Q(4, "Reading storage drives…", HardwareInventory.DiskSql).ConfigureAwait(false), DiskInfo.FromRow);
        // Each section is its own query, so one that fails (or a table this platform lacks) leaves the others intact.
        var gpu = InventorySection<GpuInfo>.FromOptional(await Q(5, "Reading graphics adapters…", HardwareInventory.GpuSql).ConfigureAwait(false), GpuInfo.FromRow);
        var net = InventorySection<NetworkAdapterInfo>.FromOptional(await Q(6, "Reading network adapters…", HardwareInventory.NetworkSql).ConfigureAwait(false), NetworkAdapterInfo.FromRow);
        var bios = InventorySection<BiosInfo>.FromOptional(await Q(7, "Reading BIOS details…", HardwareInventory.BiosSql).ConfigureAwait(false), BiosInfo.FromRow);

        // Fallbacks (shown to the user as normal values).
        var s0 = sys.Items.FirstOrDefault();
        if (cpu.Success && cpu.Items.Count == 0 && s0 is { CpuBrand.Length: > 0 })
            cpu = cpu with { Items = [HardwareInventory.CpuFromSystemPublic(s0)], FromFallback = true };
        if (mem.Success && !mem.Items.Any(m => m.IsPopulated) && s0?.PhysicalMemoryBytes is > 0)
            mem = mem with { FromFallback = true }; // UI/summary use system_info.physical_memory for the total
        if (disk.Success && disk.Items.Count == 1 && disk.Items[0].SizeBytes is not > 0)
        {
            var ld = await runner.RunQueryAsync(HardwareInventory.LogicalDrivesSql, ct).ConfigureAwait(false);
            var total = ld.Success ? HardwareInventory.SumFixedDrives(ld.Rows!) : 0;
            if (total > 0) disk = disk with { Items = [disk.Items[0] with { SizeBytes = total }], FromFallback = true };
        }
        return new HardwareInventory(sys, cpu, mem, disk) { Gpus = gpu, NetworkAdapters = net, Bios = bios, ToolMissing = !runner.Exists };
    }

}

/// <summary>Services from osquery <c>services</c> (kernel and file-system drivers left out).</summary>
public sealed class OsqueryServiceSource(OsqueryRunner runner) : IServiceSource
{
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => LegacyAvailability.Of(runner, LegacyAvailability.ToolMissingMessage);

    public const string Sql = "SELECT name, display_name, status, start_type, user_account, description FROM services WHERE service_type NOT LIKE '%DRIVER%';";

    public async Task<IReadOnlyList<ServiceInfo>?> ReadServicesAsync(CancellationToken ct)
    {
        var q = await runner.RunQueryAsync(Sql, ct).ConfigureAwait(false);
        return q.Success ? q.Rows!.Select(ServiceInfo.FromRow).ToList() : null;
    }
}

/// <summary>
/// Problem devices from Win32_PnPEntity read in this process (WMI as a standard user), or the ProblemDevices PowerShell script when that fails;
/// drivers from osquery <c>drivers</c>.
/// </summary>
public sealed class OsqueryDeviceDriverSource(OsqueryRunner runner, SystemCommandRunner? commands) : IDeviceDriverSource
{
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => LegacyAvailability.Of(runner, LegacyAvailability.ToolMissingMessage);

    public const string DriversSql = "SELECT device_name, description, class, provider, manufacturer, version, date, signed FROM drivers WHERE device_name != '';";
    public static string ProblemDevicesScript => Core.Scripts.PowerShellScripts.Get("ProblemDevices");

    public async Task<IReadOnlyList<ProblemDevice>?> ReadProblemDevicesAsync(CancellationToken ct)
    {
        // A scripted runner (tests, recordings) answers the script; the in-process reader can't be replayed.
        if (commands is not { IsScripted: true })
        {
            try
            {
                return ProblemDevicesReader.Read().Select(p => new ProblemDevice(p.Name, p.Class, p.DeviceId, p.ErrorCode, p.Status)).ToList();
            }
            catch (Exception ex) { runner.Options.Log.Warn($"DeviceDrivers: in-process problem devices reader failed: {ex.Message}"); }
        }
        if (commands is null) return null;
        var pr = await commands.RunPowerShellAsync(ProblemDevicesScript, ct).ConfigureAwait(false);
        if (pr is not { ExitCode: 0 }) return null;
        if (string.IsNullOrWhiteSpace(pr.StdOut) || pr.StdOut.Trim() == "[]") return [];
        try { return OsqueryJson.ParseRows(pr.StdOut).Select(ProblemDevice.FromRow).ToList(); }
        catch (FormatException ex) { runner.Options.Log.Warn($"DeviceDrivers: problem devices output unreadable: {ex.Message}"); return null; }
    }

    public async Task<IReadOnlyList<DriverEntry>?> ReadDriversAsync(CancellationToken ct)
    {
        var q = await runner.RunQueryAsync(DriversSql, ct).ConfigureAwait(false);
        return q.Success ? q.Rows!.Select(DriverEntry.FromRow).ToList() : null;
    }
}

/// <summary>The Windows version, updates and programs from osquery <c>os_version</c>, <c>patches</c> and <c>programs</c>.</summary>
public sealed class OsqueryProgramsSource(OsqueryRunner runner) : IProgramsSource
{
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => LegacyAvailability.Of(runner, LegacyAvailability.ToolMissingMessage);

    public const string OsSql = "SELECT * FROM os_version;";
    public const string PatchesSql = "SELECT hotfix_id, description, installed_on FROM patches;";
    public const string ProgramsSql = "SELECT name, version, publisher, install_date FROM programs;";

    public async Task<WindowsVersionRead> ReadWindowsVersionAsync(CancellationToken ct)
    {
        var q = await runner.RunQueryAsync(OsSql, ct).ConfigureAwait(false);
        return new(q.Success, q.Success ? q.Rows!.FirstOrDefault() : null);
    }

    public async Task<IReadOnlyList<InstalledUpdate>?> ReadUpdatesAsync(CancellationToken ct)
    {
        var q = await runner.RunQueryAsync(PatchesSql, ct).ConfigureAwait(false);
        return q.Success ? q.Rows!.Select(InstalledUpdate.FromRow).ToList() : null;
    }

    public async Task<IReadOnlyList<InstalledProgram>?> ReadProgramsAsync(CancellationToken ct)
    {
        var q = await runner.RunQueryAsync(ProgramsSql, ct).ConfigureAwait(false);
        return q.Success ? q.Rows!.Select(InstalledProgram.FromRow).ToList() : null;
    }
}

/// <summary>The legacy readers need osqueryi.exe: without it the check says so (the path goes to the log only).</summary>
public static class LegacyAvailability
{
    /// <summary>What a legacy check says when osqueryi.exe is missing.</summary>
    public const string ToolMissingMessage = "The diagnostics tool wasn't found. Please reinstall the app.";

    public static Task<ModuleAvailability> Of(OsqueryRunner runner, string message)
    {
        var a = runner.CheckAvailability();
        if (a.IsAvailable) return Task.FromResult(a);
        runner.Options.Log.Line(a.Reason ?? runner.NotFoundMessage);
        return Task.FromResult(ModuleAvailability.Unavailable(message));
    }
}
