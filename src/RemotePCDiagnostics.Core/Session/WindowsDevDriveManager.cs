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
    public const string PersistentVolumeLabel = "DevDrive";
    public const string VhdxPrefix = "rpcd-devdrive-";
    public const string PersistentVhdxPrefix = "rpcd-persistent-devdrive-";
    public const string BuildTempPrefix = "rpcd-devbench-";
    public const string DevDriveBuildRootName = "rpcd-devbench";
    public const int DefaultSizeGb = 50;
    public const int MinSizeGb = 50;
    public const int MaxSizeGb = 64;

    /// <summary>%ProgramData%\RemotePCDiagnostics\devdrive-temp — owned by the Agent.</summary>
    public static string DefaultVhdxFolder() => Path.Combine(ProtectedState.AppDataFolder(), "devdrive-temp");

    /// <summary>%ProgramData%\RemotePCDiagnostics\devdrive — persistent user Dev Drives owned by the Agent (never swept on startup).</summary>
    public static string DefaultPersistentVhdxFolder() => Path.Combine(ProtectedState.AppDataFolder(), "devdrive");

    /// <summary>
    /// True only for an RPCD temporary build folder directly inside a user Temp directory
    /// (<c>...\Temp\rpcd-devbench-&lt;id&gt;</c>) or directly inside the RPCD temporary Dev Drive root
    /// (<c>X:\rpcd-devbench\rpcd-devbench-&lt;id&gt;</c>).
    /// </summary>
    public static bool IsRpcdTempBuildFolder(string? folder)
    {
        if (!DefenderPaths.IsLocalPath(folder)) return false;
        var parts = folder!.TrimEnd('\\').Split('\\');
        if (parts.Length < 3) return false;
        var leaf = parts[^1];
        var parent = parts[^2];
        var isUserTemp = parent.Equals("Temp", StringComparison.OrdinalIgnoreCase);
        var isDevDriveTemp = parts.Length == 3
            && parts[0].Length == 2 && char.IsAsciiLetter(parts[0][0]) && parts[0][1] == ':'
            && parent.Equals(DevDriveBuildRootName, StringComparison.OrdinalIgnoreCase);
        if (!isUserTemp && !isDevDriveTemp) return false;
        if (!leaf.StartsWith(BuildTempPrefix, StringComparison.OrdinalIgnoreCase)) return false;
        var suffix = leaf[BuildTempPrefix.Length..];
        if (suffix.Length is < 8 or > 40) return false;
        return suffix.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
    }

    /// <summary>True when <paramref name="folder"/> is a temporary build folder on the RPCD Dev Drive (<c>X:\rpcd-devbench\rpcd-devbench-&lt;id&gt;</c>).</summary>
    public static bool IsRpcdDevDriveBuildFolder(string? folder)
    {
        if (!IsRpcdTempBuildFolder(folder)) return false;
        var parts = folder!.TrimEnd('\\').Split('\\');
        return parts.Length == 3 && parts[1].Equals(DevDriveBuildRootName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Why <paramref name="folder"/> is refused as a new temporary build exclusion, or null when allowed: it must be an RPCD build
    /// folder directly inside one of <paramref name="userTempFolders"/> (the signed-in user's own Temp) or inside the mounted
    /// <c>RPCD-DevDrive</c> temporary Dev Drive, exist, and not be a link.
    /// </summary>
    public static string? TempBuildFolderRefusal(
        string? folder,
        IReadOnlyList<string> userTempFolders,
        Func<string, bool>? dirExists = null,
        Func<string, bool>? isReparsePoint = null,
        Func<string, string?>? getVolumeLabel = null)
    {
        if (!IsRpcdTempBuildFolder(folder))
            return "Temporary build exclusions are only allowed for RPCD build temp folders (Temp\\rpcd-devbench-* or <DevDrive>:\\rpcd-devbench\\rpcd-devbench-*).";
        if (IsRpcdDevDriveBuildFolder(folder))
        {
            var root = folder![..2] + "\\";
            var label = getVolumeLabel is not null ? getVolumeLabel(root) : TryReadVolumeLabel(root);
            if (!string.Equals(label, VolumeLabel, StringComparison.OrdinalIgnoreCase))
                return $"Temporary Dev Drive build exclusions are only allowed on a volume labeled {VolumeLabel}.";
        }
        else
        {
            var parent = folder!.TrimEnd('\\');
            parent = parent[..parent.LastIndexOf('\\')];
            if (!userTempFolders.Any(t => t.TrimEnd('\\').Equals(parent, StringComparison.OrdinalIgnoreCase)))
                return "Temporary build exclusions are only allowed directly inside the signed-in user's own Temp folder.";
        }
        if (!(dirExists ?? Directory.Exists)(folder))
            return $"{folder} doesn't exist.";
        if (isReparsePoint is not null && isReparsePoint(folder))
            return $"{folder} is a link; it's never excluded.";
        return null;
    }

    private static string? TryReadVolumeLabel(string root)
    {
        try { return new DriveInfo(root).VolumeLabel; }
        catch { return null; }
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

    /// <summary>
    /// True only for a persistent RPCD Dev Drive VHDX directly inside <c>devdrive</c> with name <c>rpcd-persistent-devdrive-&lt;id&gt;.vhdx</c>.
    /// </summary>
    public static bool IsRpcdPersistentDevDriveVhdx(string? path, string? allowedFolder = null)
    {
        if (!DefenderPaths.IsLocalPath(path)) return false;
        var root = (allowedFolder ?? DefaultPersistentVhdxFolder()).TrimEnd('\\');
        if (!DefenderPaths.IsLocalPath(root)) return false;
        var trimmed = path!.TrimEnd('\\');
        var sep = trimmed.LastIndexOf('\\');
        if (sep <= 0) return false;
        var dir = trimmed[..sep];
        var file = trimmed[(sep + 1)..];
        if (!dir.Equals(root, StringComparison.OrdinalIgnoreCase)) return false;
        if (!file.StartsWith(PersistentVhdxPrefix, StringComparison.OrdinalIgnoreCase)
            || !file.EndsWith(".vhdx", StringComparison.OrdinalIgnoreCase))
            return false;
        var suffix = file[PersistentVhdxPrefix.Length..^".vhdx".Length];
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

    /// <summary>Builds the fixed diskpart script for creating and attaching the VHDX.</summary>
    public static string BuildDiskpartCreateScript(string vhdxPath, int sizeGb)
    {
        var maxMb = Math.Clamp(sizeGb, MinSizeGb, MaxSizeGb) * 1024;
        return $"create vdisk file=\"{vhdxPath}\" maximum={maxMb} type=expandable\r\nselect vdisk file=\"{vhdxPath}\"\r\nattach vdisk\r\n";
    }

    /// <summary>Builds the fixed diskpart script for detaching the VHDX.</summary>
    public static string BuildDiskpartDetachScript(string vhdxPath) =>
        $"select vdisk file=\"{vhdxPath}\"\r\ndetach vdisk\r\n";

    /// <summary>Builds the Agent's Storage PowerShell script to initialize, partition, and format the attached VHDX as a Dev Drive.</summary>
    public static string BuildFormatDevDriveScript(string vhdxPath, string? volumeLabel = null)
    {
        var q = "'" + vhdxPath.Replace("'", "''") + "'";
        var label = "'" + (volumeLabel ?? VolumeLabel).Replace("'", "''") + "'";
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
/// Uses a fixed, Agent-built <c>diskpart</c> script (present on every Windows edition; no Hyper-V needed). Only one temporary
/// Dev Drive exists at a time.
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
        if (Directory.EnumerateFiles(_folder, $"{DevDriveRules.VhdxPrefix}*.vhdx").Any())
            return new(false, Error: "A temporary Dev Drive is already in use. Wait for that comparison to finish, then try again.");
        var vhdxPath = Path.Combine(_folder, $"{DevDriveRules.VhdxPrefix}{Guid.NewGuid():N}.vhdx");

        try
        {
            if (!await RunDiskpartAsync(DevDriveRules.BuildDiskpartCreateScript(vhdxPath, clampedGb), ct).ConfigureAwait(false))
            {
                // diskpart may have attached the disk before failing; detach and delete whatever it left.
                await RemoveAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false);
                return new(false, Error: "diskpart could not create the temporary Dev Drive VHDX.");
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
                {
                    // The app runs as the standard user: without this grant it can't build on the drive, so the mount is no use to it.
                    Log($"icacls grant failed (exit {acl.ExitCode}): {acl.StdErr.Trim()}");
                    await RemoveAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false);
                    return new(false, Error: AclError(acl.StdErr));
                }
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

        if (File.Exists(vhdxPath))
            await RunDiskpartAsync(DevDriveRules.BuildDiskpartDetachScript(vhdxPath), ct).ConfigureAwait(false);

        var deleted = TryDeleteFile(vhdxPath);
        Log($"Removed temporary Dev Drive VHDX {vhdxPath} (deleted={deleted})");
        return deleted;
    }

    /// <summary>Creates, attaches, and formats a persistent dynamically expanding Dev Drive VHDX (kept across runs until undone).</summary>
    public async Task<DevDriveMountResult> CreatePersistentAsync(int sizeGb, string? grantUserSid, CancellationToken ct)
    {
        var clampedGb = Math.Clamp(sizeGb <= 0 ? DevDriveRules.DefaultSizeGb : sizeGb, DevDriveRules.MinSizeGb, DevDriveRules.MaxSizeGb);
        if (grantUserSid is not null && !DevDriveRules.IsValidUserSid(grantUserSid))
            return new(false, Error: "Invalid user SID.");

        var persistentFolder = DevDriveRules.DefaultPersistentVhdxFolder();
        Directory.CreateDirectory(persistentFolder);
        var vhdxPath = Path.Combine(persistentFolder, $"{DevDriveRules.PersistentVhdxPrefix}{Guid.NewGuid():N}.vhdx");

        try
        {
            if (!await RunDiskpartAsync(DevDriveRules.BuildDiskpartCreateScript(vhdxPath, clampedGb), ct).ConfigureAwait(false))
            {
                await RemovePersistentAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false);
                return new(false, Error: "diskpart could not create the persistent Dev Drive VHDX.");
            }

            var fmt = await _launcher.RunAsync(
                SystemCommandRunner.PowerShell,
                SystemCommandRunner.PowerShellArgs(DevDriveRules.BuildFormatDevDriveScript(vhdxPath, DevDriveRules.PersistentVolumeLabel)),
                TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);

            var driveLetter = fmt.StdOut?.Trim();
            if (fmt.ExitCode != 0 || string.IsNullOrWhiteSpace(driveLetter) || driveLetter.Length != 1 || !char.IsAsciiLetter(driveLetter[0]))
            {
                await RemovePersistentAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false);
                var err = string.IsNullOrWhiteSpace(fmt.StdErr) ? "Format-Volume -DevDrive failed." : fmt.StdErr.Trim();
                return new(false, Error: err);
            }

            var driveRoot = $"{char.ToUpperInvariant(driveLetter[0])}:\\";
            if (!string.IsNullOrWhiteSpace(grantUserSid))
            {
                var icacls = Path.Combine(Environment.SystemDirectory, "icacls.exe");
                var acl = await _launcher.RunAsync(
                    File.Exists(icacls) ? icacls : "icacls.exe",
                    [driveRoot, "/grant", $"*{grantUserSid}:(OI)(CI)M", "/Q"],
                    TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                if (acl.ExitCode != 0)
                {
                    Log($"icacls grant failed on persistent Dev Drive (exit {acl.ExitCode}): {acl.StdErr.Trim()}");
                    await RemovePersistentAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false);
                    return new(false, Error: AclError(acl.StdErr));
                }
            }

            Log($"Mounted persistent Dev Drive {driveRoot} ({vhdxPath})");
            return new(true, vhdxPath, driveLetter.ToUpperInvariant(), driveRoot);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await RemovePersistentAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false);
            Log("CreatePersistent failed: " + ex.Message);
            return new(false, Error: ex.Message);
        }
    }

    public async Task<bool> RemovePersistentAsync(string vhdxPath, CancellationToken ct)
    {
        if (!DevDriveRules.IsRpcdPersistentDevDriveVhdx(vhdxPath))
            return false;

        if (File.Exists(vhdxPath))
            await RunDiskpartAsync(DevDriveRules.BuildDiskpartDetachScript(vhdxPath), ct).ConfigureAwait(false);

        var deleted = TryDeleteFile(vhdxPath);
        Log($"Removed persistent Dev Drive VHDX {vhdxPath} (deleted={deleted})");
        return deleted;
    }

    private static string AclError(string? stdErr) =>
        "Couldn't give your account access to the Dev Drive" + (string.IsNullOrWhiteSpace(stdErr) ? "." : ": " + stdErr.Trim());

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
}
