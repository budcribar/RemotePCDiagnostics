using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>Result of creating and mounting a temporary RPCD Dev Drive VHDX in the Agent.</summary>
public sealed record DevDriveMountResult(
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("vhdxPath")] string? VhdxPath = null,
    [property: JsonPropertyName("driveLetter")] string? DriveLetter = null,
    [property: JsonPropertyName("buildFolder")] string? BuildFolder = null,
    [property: JsonPropertyName("error")] string? Error = null)
{
    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    public string ToJson() => JsonSerializer.Serialize(this, Json);
    public static DevDriveMountResult? FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<DevDriveMountResult>(json, Json); }
        catch (JsonException) { return null; }
    }
}

/// <summary>
/// Strict path and argument rules enforced by the Agent before it touches a temporary build exclusion or Dev Drive VHDX.
/// The Agent never accepts scripts or arbitrary paths from the app.
/// </summary>
public static class DevDriveRules
{
    public const string VolumeLabel = "RPCD-DevDrive";
    public const string VhdxPrefix = "rpcd-devdrive-";
    public const string BuildTempPrefix = "rpcd-devbench-";
    public const int DefaultSizeGb = 50;
    public const int MinSizeGb = 50;
    public const int MaxSizeGb = 64;

    /// <summary>%ProgramData%\RemotePCDiagnostics\devdrive-temp — owned by the Agent.</summary>
    public static string DefaultVhdxFolder() => Path.Combine(ProtectedState.AppDataFolder(), "devdrive-temp");

    /// <summary>
    /// True only for an RPCD temporary build folder directly inside a user Temp directory, e.g.
    /// <c>C:\Users\alice\AppData\Local\Temp\rpcd-devbench-0123456789abcdef</c>.
    /// </summary>
    public static bool IsRpcdTempBuildFolder(string? folder)
    {
        if (!DefenderPaths.IsLocalPath(folder)) return false;
        var parts = folder!.TrimEnd('\\').Split('\\');
        if (parts.Length < 3) return false;
        var leaf = parts[^1];
        var parent = parts[^2];
        if (!parent.Equals("Temp", StringComparison.OrdinalIgnoreCase)) return false;
        if (!leaf.StartsWith(BuildTempPrefix, StringComparison.OrdinalIgnoreCase)) return false;
        var suffix = leaf[BuildTempPrefix.Length..];
        if (suffix.Length is < 8 or > 40) return false;
        return suffix.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
    }

    /// <summary>Why <paramref name="folder"/> is refused as a temporary build exclusion, or null when allowed.</summary>
    public static string? TempBuildFolderRefusal(string? folder, bool mustExist, Func<string, bool>? dirExists = null)
    {
        if (!IsRpcdTempBuildFolder(folder))
            return "Temporary build exclusions are only allowed for RPCD build temp folders (Temp\\rpcd-devbench-*).";
        if (mustExist && !(dirExists ?? Directory.Exists)(folder!))
            return $"{folder} doesn't exist.";
        return null;
    }

    /// <summary>
    /// True only for an RPCD VHDX file directly inside the Agent's own <c>devdrive-temp</c> folder
    /// with name <c>rpcd-devdrive-&lt;id&gt;.vhdx</c>.
    /// </summary>
    public static bool IsRpcdDevDriveVhdx(string? path, string? allowedFolder = null)
    {
        if (!DefenderPaths.IsLocalPath(path)) return false;
        var root = (allowedFolder ?? DefaultVhdxFolder()).TrimEnd('\\');
        if (!DefenderPaths.IsLocalPath(root)) return false;
        var trimmed = path!.TrimEnd('\\');
        var sep = trimmed.LastIndexOf('\\');
        if (sep <= 0) return false;
        var dir = trimmed[..sep];
        var file = trimmed[(sep + 1)..];
        if (!dir.Equals(root, StringComparison.OrdinalIgnoreCase)) return false;
        if (!file.StartsWith(VhdxPrefix, StringComparison.OrdinalIgnoreCase)
            || !file.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase))
            return false;
        var suffix = file[VhdxPrefix.Length..^".vhdx".Length];
        if (suffix.Length is < 8 or > 40) return false;
        return suffix.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
    }

    /// <summary>Validates a Windows SID like <c>S-1-5-21-...</c> before passing it to icacls.</summary>
    public static bool IsValidUserSid(string? sid)
    {
        if (string.IsNullOrEmpty(sid) || sid.Length > 128) return false;
        if (!sid.StartsWith("S-1-", StringComparison.Ordinal)) return false;
        var parts = sid.Split('-');
        return parts.Length >= 4 && parts.Skip(1).All(p => p.Length > 0 && p.All(char.IsAsciiDigit));
    }

    /// <summary>Builds the fixed diskpart fallback script for creating and attaching the VHDX.</summary>
    public static string BuildDiskpartCreateScript(string vhdxPath, int sizeGb)
    {
        var maxMb = Math.Clamp(sizeGb, MinSizeGb, MaxSizeGb) * 1024;
        return $"create vdisk file=\"{vhdxPath}\" maximum={maxMb} type=expandable\r\nselect vdisk file=\"{vhdxPath}\"\r\nattach vdisk\r\n";
    }

    /// <summary>Builds the fixed diskpart fallback script for detaching the VHDX.</summary>
    public static string BuildDiskpartDetachScript(string vhdxPath) =>
        $"select vdisk file=\"{vhdxPath}\"\r\ndetach vdisk\r\n";

    /// <summary>Builds the Agent's Storage PowerShell script to initialize, partition, and format the attached VHDX as a Dev Drive.</summary>
    public static string BuildFormatDevDriveScript(string vhdxPath)
    {
        var q = "'" + vhdxPath.Replace("'", "''") + "'";
        var label = "'" + VolumeLabel + "'";
        return "$ErrorActionPreference='Stop';"
            + $"$d = Get-Disk | Where-Object {{ $_.Location -eq {q} }} | Select-Object -First 1;"
            + "if (-not $d) { throw 'Attached VHDX disk not found.' };"
            + "Initialize-Disk -Number $d.Number -PartitionStyle GPT -Confirm:$false | Out-Null;"
            + "$p = New-Partition -DiskNumber $d.Number -UseMaximumSize -AssignDriveLetter;"
            + $"Format-Volume -Partition $p -DevDrive -FileSystem ReFS -NewFileSystemLabel {label} -Confirm:$false | Out-Null;"
            + "Write-Output $p.DriveLetter";
    }
}

/// <summary>
/// Creates, mounts, formats, and cleans up temporary RPCD Dev Drive VHDX images in the elevated Agent.
/// Uses the Virtual Disk API (<c>virtdisk.dll</c>, present on every Windows edition) with a fixed <c>diskpart</c> fallback.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDevDriveManager(ILogger? log = null, IProcessLauncher? launcher = null, string? vhdxFolder = null)
{
    private readonly IProcessLauncher _launcher = launcher ?? new SystemProcessLauncher();
    private readonly string _folder = vhdxFolder ?? DevDriveRules.DefaultVhdxFolder();

    private void Log(string m) => log.Info("[devdrive] " + m);

    public async Task<DevDriveMountResult> CreateAndMountAsync(int sizeGb, string? grantUserSid, CancellationToken ct)
    {
        var clampedGb = Math.Clamp(sizeGb <= 0 ? DevDriveRules.DefaultSizeGb : sizeGb, DevDriveRules.MinSizeGb, DevDriveRules.MaxSizeGb);
        if (grantUserSid is not null && !DevDriveRules.IsValidUserSid(grantUserSid))
            return new(false, Error: "Invalid user SID.");

        Directory.CreateDirectory(_folder);
        var vhdxPath = Path.Combine(_folder, $"{DevDriveRules.VhdxPrefix}{Guid.NewGuid():N}.vhdx");

        try
        {
            var created = TryCreateAndAttachViaVirtDisk(vhdxPath, clampedGb, out var virtErr);
            if (!created)
            {
                Log($"virtdisk.dll failed ({virtErr}); falling back to fixed diskpart script.");
                var dpOk = await RunDiskpartAsync(DevDriveRules.BuildDiskpartCreateScript(vhdxPath, clampedGb), ct).ConfigureAwait(false);
                if (!dpOk)
                {
                    TryDeleteFile(vhdxPath);
                    return new(false, Error: $"Could not create temporary Dev Drive VHDX ({virtErr}).");
                }
            }

            var fmt = await _launcher.RunAsync(
                SystemCommandRunner.PowerShell,
                SystemCommandRunner.PowerShellArgs(DevDriveRules.BuildFormatDevDriveScript(vhdxPath)),
                TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);

            var driveLetter = fmt.StdOut?.Trim();
            if (fmt.ExitCode != 0 || string.IsNullOrWhiteSpace(driveLetter) || driveLetter.Length != 1 || !char.IsAsciiLetter(driveLetter[0]))
            {
                await RemoveAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false);
                var err = string.IsNullOrWhiteSpace(fmt.StdErr) ? "Format-Volume -DevDrive failed." : fmt.StdErr.Trim();
                return new(false, Error: err);
            }

            var buildFolder = $"{char.ToUpperInvariant(driveLetter[0])}:\\rpcd-devbench";
            Directory.CreateDirectory(buildFolder);

            if (!string.IsNullOrWhiteSpace(grantUserSid))
            {
                var icacls = Path.Combine(Environment.SystemDirectory, "icacls.exe");
                var acl = await _launcher.RunAsync(
                    File.Exists(icacls) ? icacls : "icacls.exe",
                    [buildFolder, "/grant", $"*{grantUserSid}:(OI)(CI)M", "/Q"],
                    TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                if (acl.ExitCode != 0)
                    Log($"icacls grant warning (exit {acl.ExitCode}): {acl.StdErr.Trim()}");
            }

            Log($"Mounted temporary Dev Drive {driveLetter}: ({vhdxPath})");
            return new(true, vhdxPath, driveLetter.ToUpperInvariant(), buildFolder);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RemoveAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false);
            Log("CreateAndMount failed: " + ex.Message);
            return new(false, Error: ex.Message);
        }
    }

    public async Task<bool> RemoveAsync(string vhdxPath, CancellationToken ct)
    {
        if (!DevDriveRules.IsRpcdDevDriveVhdx(vhdxPath, _folder))
            return false;

        var detached = TryDetachViaVirtDisk(vhdxPath);
        if (!detached && File.Exists(vhdxPath))
            await RunDiskpartAsync(DevDriveRules.BuildDiskpartDetachScript(vhdxPath), ct).ConfigureAwait(false);

        var deleted = TryDeleteFile(vhdxPath);
        Log($"Removed temporary Dev Drive VHDX {vhdxPath} (deleted={deleted})");
        return deleted;
    }

    /// <summary>
    /// Called on Agent startup: detaches and deletes any leftover RPCD Dev Drive VHDX files in the Agent's temp folder
    /// and removes any leftover RPCD temp build Defender exclusions.
    /// </summary>
    public async Task<int> SweepLeftoversAsync(IMachineTweaks? tweaks, CancellationToken ct)
    {
        var cleaned = 0;
        if (Directory.Exists(_folder))
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(_folder, $"{DevDriveRules.VhdxPrefix}*.vhdx"); }
            catch { files = []; }
            foreach (var f in files)
            {
                if (!DevDriveRules.IsRpcdDevDriveVhdx(f, _folder)) continue;
                if (await RemoveAsync(f, ct).ConfigureAwait(false)) cleaned++;
            }
        }

        if (tweaks is not null)
        {
            try
            {
                var json = await tweaks.ReadDefenderAsync(ct).ConfigureAwait(false);
                var status = DefenderProbe.Parse(json);
                if (status is { ExclusionsReadable: true })
                {
                    var leftovers = status.Paths.Where(DevDriveRules.IsRpcdTempBuildFolder).ToList();
                    foreach (var folder in leftovers)
                    {
                        if (await tweaks.RemoveTempBuildDefenderExclusionAsync(folder, ct).ConfigureAwait(false))
                        {
                            cleaned++;
                            Log($"Removed leftover temporary Defender exclusion: {folder}");
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log("Startup Defender sweep skipped: " + ex.Message);
            }
        }

        return cleaned;
    }

    private async Task<bool> RunDiskpartAsync(string script, CancellationToken ct)
    {
        var scriptPath = Path.Combine(_folder, $"rpcd-dp-{Guid.NewGuid():N}.txt");
        try
        {
            Directory.CreateDirectory(_folder);
            await File.WriteAllTextAsync(scriptPath, script, ct).ConfigureAwait(false);
            var dp = Path.Combine(Environment.SystemDirectory, "diskpart.exe");
            var r = await _launcher.RunAsync(File.Exists(dp) ? dp : "diskpart.exe", ["/s", scriptPath], TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
            return r.ExitCode == 0;
        }
        finally
        {
            TryDeleteFile(scriptPath);
        }
    }

    private static bool TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
            return !File.Exists(path);
        }
        catch { return false; }
    }

    // ---- virtdisk.dll P/Invoke (available on all Windows editions, no Hyper-V required) ----

    private static readonly Guid VirtualStorageTypeVendorMicrosoft = new("EC984AEC-A0F9-47E9-901F-71415A66345B");
    private const uint VirtualStorageTypeDeviceVhdx = 3;
    private const uint VirtualDiskAccessAll = 0x003f0000;
    private const uint VirtualDiskAccessDetach = 0x00040000;
    private const uint OpenVirtualDiskFlagNone = 0;
    private const uint CreateVirtualDiskFlagNone = 0;
    private const uint AttachVirtualDiskFlagPermanentLifetime = 0x00000004;
    private const uint DetachVirtualDiskFlagNone = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct VIRTUAL_STORAGE_TYPE
    {
        public uint DeviceId;
        public Guid VendorId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREATE_VIRTUAL_DISK_PARAMETERS_V2
    {
        public uint Version;
        public Guid UniqueId;
        public ulong MaximumSize;
        public uint BlockSizeInBytes;
        public uint SectorSizeInBytes;
        public uint PhysicalSectorSizeInBytes;
        public IntPtr ParentPath;
        public IntPtr SourcePath;
        public uint OpenFlags;
        public VIRTUAL_STORAGE_TYPE ParentVirtualStorageType;
        public VIRTUAL_STORAGE_TYPE SourceVirtualStorageType;
        public Guid ResiliencyGuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OPEN_VIRTUAL_DISK_PARAMETERS
    {
        public uint Version;
        public uint RWDepth;
    }

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
    private static extern uint CreateVirtualDisk(
        ref VIRTUAL_STORAGE_TYPE virtualStorageType,
        string path,
        uint virtualDiskAccessMask,
        IntPtr securityDescriptor,
        uint flags,
        uint providerSpecificFlags,
        ref CREATE_VIRTUAL_DISK_PARAMETERS_V2 parameters,
        IntPtr overlapped,
        out IntPtr handle);

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode)]
    private static extern uint OpenVirtualDisk(
        ref VIRTUAL_STORAGE_TYPE virtualStorageType,
        string path,
        uint virtualDiskAccessMask,
        uint flags,
        ref OPEN_VIRTUAL_DISK_PARAMETERS parameters,
        out IntPtr handle);

    [DllImport("virtdisk.dll")]
    private static extern uint AttachVirtualDisk(
        IntPtr virtualDiskHandle,
        IntPtr securityDescriptor,
        uint flags,
        uint providerSpecificFlags,
        IntPtr parameters,
        IntPtr overlapped);

    [DllImport("virtdisk.dll")]
    private static extern uint DetachVirtualDisk(
        IntPtr virtualDiskHandle,
        uint flags,
        uint providerSpecificFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static bool TryCreateAndAttachViaVirtDisk(string vhdxPath, int sizeGb, out string error)
    {
        error = "";
        var storageType = new VIRTUAL_STORAGE_TYPE { DeviceId = VirtualStorageTypeDeviceVhdx, VendorId = VirtualStorageTypeVendorMicrosoft };
        var createParams = new CREATE_VIRTUAL_DISK_PARAMETERS_V2
        {
            Version = 2,
            MaximumSize = (ulong)sizeGb * 1024UL * 1024UL * 1024UL,
            BlockSizeInBytes = 0,
            SectorSizeInBytes = 512,
            PhysicalSectorSizeInBytes = 4096,
        };

        var rc = CreateVirtualDisk(ref storageType, vhdxPath, VirtualDiskAccessAll, IntPtr.Zero, CreateVirtualDiskFlagNone, 0, ref createParams, IntPtr.Zero, out var handle);
        if (rc != 0)
        {
            error = $"CreateVirtualDisk returned {rc}";
            return false;
        }
        try
        {
            rc = AttachVirtualDisk(handle, IntPtr.Zero, AttachVirtualDiskFlagPermanentLifetime, 0, IntPtr.Zero, IntPtr.Zero);
            if (rc != 0)
            {
                error = $"AttachVirtualDisk returned {rc}";
                return false;
            }
            return true;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static bool TryDetachViaVirtDisk(string vhdxPath)
    {
        if (!File.Exists(vhdxPath)) return true;
        var storageType = new VIRTUAL_STORAGE_TYPE { DeviceId = VirtualStorageTypeDeviceVhdx, VendorId = VirtualStorageTypeVendorMicrosoft };
        var openParams = new OPEN_VIRTUAL_DISK_PARAMETERS { Version = 2, RWDepth = 0 };
        var rc = OpenVirtualDisk(ref storageType, vhdxPath, VirtualDiskAccessDetach, OpenVirtualDiskFlagNone, ref openParams, out var handle);
        if (rc != 0) return false;
        try
        {
            return DetachVirtualDisk(handle, DetachVirtualDiskFlagNone, 0) == 0;
        }
        finally
        {
            CloseHandle(handle);
        }
    }
}
