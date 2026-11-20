using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// The machine-wide changes the suggestions and undo make that need administrator rights: allowlisted HKLM policy values (and the empty
/// keys they created), the browsers' extension blocklists, the page file, and Defender exclusions. The app never runs as administrator,
/// so it has the Agent make these (<see cref="AgentMachineTweaks"/>, over the admin pipe); the Agent does them with
/// <see cref="WindowsMachineTweaks"/> after <see cref="MachineTweakRules"/> allowed the request. Each throws with the reason when it can't.
/// </summary>
public interface IMachineTweaks
{
    /// <summary>An HKLM value on <see cref="RegistryAllowlist"/>. Creates its key if needed (and removes it again when the write fails).</summary>
    void WriteDword(RegistrySetting setting, int value);
    /// <summary>Deletes an HKLM value on <see cref="RegistryAllowlist"/> (no error when it's already absent).</summary>
    void DeleteDword(RegistrySetting setting);
    /// <summary>Deletes an HKLM key <see cref="RegistryKeyCleanup.IsCleanupKey"/> allows, only while it's empty. True = deleted or already gone.</summary>
    bool DeleteKeyIfEmpty(string key);
    /// <summary>Adds an allowlisted extension as a new numbered blocklist value; never overwrites one.</summary>
    void AddExtensionBlock(BrowserKind browser, string valueName, string extensionId);
    /// <summary>Deletes the blocklist value only while it still holds this allowlisted extension.</summary>
    void RemoveExtensionBlock(BrowserKind browser, string valueName, string extensionId);
    Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct);
    /// <summary>Puts back sizes saved by <see cref="PageFileSettings.Encode"/>.</summary>
    Task<ActionOutcome> RestorePageFileAsync(string settings, CancellationToken ct);
    /// <summary>The <see cref="DefenderProbe.Script"/> output (Defender's state and its exclusions, which only an administrator can read).</summary>
    Task<string?> ReadDefenderAsync(CancellationToken ct);
    /// <summary>Adds the exclusions and returns them read back (<see cref="DefenderProbe.Confirmed"/>); Ok = false when Windows refused.</summary>
    Task<(bool Ok, string? Output)> AddDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct);
    Task<bool> RemoveDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct);
    /// <summary>Adds a temporary Defender exclusion for one RPCD build temp folder (<see cref="DevDriveRules.IsRpcdTempBuildFolder"/>).</summary>
    Task<(bool Ok, string? Output)> AddTempBuildDefenderExclusionAsync(string folder, CancellationToken ct) =>
        AddDefenderExclusionsAsync([folder], [], ct);
    /// <summary>Removes a temporary Defender exclusion for one RPCD build temp folder.</summary>
    Task<bool> RemoveTempBuildDefenderExclusionAsync(string folder, CancellationToken ct) =>
        RemoveDefenderExclusionsAsync([folder], [], ct);
    /// <summary>Creates, attaches, and formats a temporary dynamically expanding RPCD Dev Drive VHDX (~50 GB).</summary>
    Task<DevDriveMountResult> CreateTempDevDriveAsync(int sizeGb, string? grantUserSid, CancellationToken ct) =>
        Task.FromResult(new DevDriveMountResult(false, Error: "Dev Drive actions are not supported by this Agent."));
    /// <summary>Detaches and deletes a temporary RPCD Dev Drive VHDX inside the Agent's temp folder.</summary>
    Task<bool> RemoveTempDevDriveAsync(string vhdxPath, CancellationToken ct) =>
        Task.FromResult(false);
}

/// <summary>One <see cref="AdminPipeFraming.OpMachineTweak"/> request: which change (<see cref="Action"/>) and its arguments.</summary>
public sealed record AdminPipeTweak(
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("target")] string? Target = null,
    [property: JsonPropertyName("name")] string? Name = null,
    [property: JsonPropertyName("text")] string? Text = null,
    [property: JsonPropertyName("number")] int? Number = null,
    [property: JsonPropertyName("folders")] IReadOnlyList<string>? Folders = null,
    [property: JsonPropertyName("processes")] IReadOnlyList<string>? Processes = null)
{
    /// <summary>Target = the setting's <see cref="RegistrySetting.Target"/>, Number = the value.</summary>
    public const string RegistryWrite = "registry_write";
    public const string RegistryDelete = "registry_delete";
    /// <summary>Target = the HKLM key path.</summary>
    public const string RegistryKeyDelete = "registry_key_delete";
    /// <summary>Target = "Chrome" or "Edge", Name = the blocklist value name, Text = the extension ID.</summary>
    public const string ExtensionBlockAdd = "extension_block_add";
    public const string ExtensionBlockRemove = "extension_block_remove";
    public const string PageFileAuto = "pagefile_auto";
    /// <summary>Text = the saved settings (<see cref="PageFileSettings.Encode"/>).</summary>
    public const string PageFileRestore = "pagefile_restore";
    public const string DefenderRead = "defender_read";
    public const string DefenderAdd = "defender_add";
    public const string DefenderRemove = "defender_remove";
    /// <summary>Target = RPCD build temp folder under Temp\rpcd-devbench-*.</summary>
    public const string DefenderTempAdd = "defender_temp_add";
    public const string DefenderTempRemove = "defender_temp_remove";
    /// <summary>Number = size in GB (50..64), Text = optional signed-in user SID to grant modify access on the build folder.</summary>
    public const string DevDriveCreate = "devdrive_create";
    /// <summary>Target = VHDX path inside the Agent's devdrive-temp folder.</summary>
    public const string DevDriveRemove = "devdrive_remove";
}

/// <summary>
/// What the Agent agrees to change for the app, checked before <see cref="IMachineTweaks"/> is called. A request can only make the
/// changes the suggestions and undo make: only allowlisted HKLM values and keys, only allowlisted extensions, only page file sizes in the
/// journal's format, and only Defender exclusions for code folders and Visual Studio's build tools. The Agent never runs a script the
/// app sent: it builds the PowerShell itself from the checked lists.
/// </summary>
public static class MachineTweakRules
{
    public const int MaxDefenderFolders = 64;
    public const int MaxDefenderProcesses = 16;
    public const int MaxPageFileSettings = 8 * 1024;

    /// <summary>The reason the Agent refuses <paramref name="t"/>, or null when it's allowed.</summary>
    public static string? Refusal(AdminPipeTweak t, DefenderPaths? paths = null)
    {
        switch (t.Action)
        {
            case AdminPipeTweak.RegistryWrite:
                if (MachineSetting(t.Target) is null) return "That registry value isn't one the Agent changes.";
                return t.Number is null ? "No value was sent." : null;

            case AdminPipeTweak.RegistryDelete:
                return MachineSetting(t.Target) is null ? "That registry value isn't one the Agent changes." : null;

            case AdminPipeTweak.RegistryKeyDelete:
                return RegistryKeyCleanup.IsCleanupKey(RegistryRoot.LocalMachine, t.Target) ? null : "That registry key isn't one the Agent removes.";

            case AdminPipeTweak.ExtensionBlockAdd or AdminPipeTweak.ExtensionBlockRemove:
                if (Browser(t.Target) is not { } browser) return "That isn't a browser this app manages.";
                if (BrowserExtensions.Known(browser, t.Text) is null) return "That extension isn't one this app may block.";
                return BrowserExtensions.IsEntryName(t.Name) ? null : "That isn't a blocklist entry name.";

            case AdminPipeTweak.PageFileAuto or AdminPipeTweak.DefenderRead:
                return null;

            case AdminPipeTweak.PageFileRestore:
                if (t.Text is not { Length: > 0 and <= MaxPageFileSettings }) return "The saved page file settings are unreadable.";
                return PageFileSettings.TryDecode(t.Text) is null ? "The saved page file settings are unreadable." : null;

            case AdminPipeTweak.DefenderAdd or AdminPipeTweak.DefenderRemove:
                var adding = t.Action == AdminPipeTweak.DefenderAdd;
                var p = paths ?? DefenderPaths.Current();
                var folders = t.Folders ?? [];
                var procs = t.Processes ?? [];
                if (folders.Count + procs.Count == 0) return "No exclusions were sent.";
                if (folders.Count > MaxDefenderFolders || procs.Count > MaxDefenderProcesses) return "Too many exclusions at once.";
                foreach (var f in folders)
                    if (p.FolderRefusal(f, mustExist: adding) is { } why) return why;
                foreach (var x in procs)
                    if (!p.IsBuildTool(x, mustExist: adding)) return $"{x} isn't a Visual Studio build tool.";
                return null;

            case AdminPipeTweak.DefenderTempAdd or AdminPipeTweak.DefenderTempRemove:
                var addingTemp = t.Action == AdminPipeTweak.DefenderTempAdd;
                var tp = paths ?? DefenderPaths.Current();
                return DevDriveRules.TempBuildFolderRefusal(t.Target, mustExist: addingTemp, tp.DirectoryExists);

            case AdminPipeTweak.DevDriveCreate:
                if (t.Number is { } gb && (gb < DevDriveRules.MinSizeGb || gb > DevDriveRules.MaxSizeGb))
                    return $"Temporary Dev Drive size must be between {DevDriveRules.MinSizeGb} and {DevDriveRules.MaxSizeGb} GB.";
                if (!string.IsNullOrEmpty(t.Text) && !DevDriveRules.IsValidUserSid(t.Text))
                    return "Invalid user SID for temporary Dev Drive.";
                return null;

            case AdminPipeTweak.DevDriveRemove:
                return DevDriveRules.IsRpcdDevDriveVhdx(t.Target)
                    ? null
                    : "Dev Drive removal is only allowed for RPCD VHDX files inside the Agent's devdrive-temp folder.";

            default:
                return $"Unknown change '{t.Action}'.";
        }
    }

    /// <summary>The allowlisted HKLM setting named <paramref name="target"/>, or null (per-account values are the app's own to change).</summary>
    public static RegistrySetting? MachineSetting(string? target) =>
        RegistryAllowlist.Find(target) is { Root: RegistryRoot.LocalMachine } s ? s : null;

    public static BrowserKind? Browser(string? name) =>
        string.Equals(name, nameof(BrowserKind.Chrome), StringComparison.Ordinal) ? BrowserKind.Chrome
        : string.Equals(name, nameof(BrowserKind.Edge), StringComparison.Ordinal) ? BrowserKind.Edge
        : null;

    /// <summary>Makes the change <paramref name="t"/> names (after <see cref="Refusal"/> allowed it). The text is what the app needs back.</summary>
    public static async Task<(bool Ok, string? Text)> ApplyAsync(IMachineTweaks backend, AdminPipeTweak t, CancellationToken ct)
    {
        switch (t.Action)
        {
            case AdminPipeTweak.RegistryWrite: backend.WriteDword(MachineSetting(t.Target)!, t.Number!.Value); return (true, null);
            case AdminPipeTweak.RegistryDelete: backend.DeleteDword(MachineSetting(t.Target)!); return (true, null);
            case AdminPipeTweak.RegistryKeyDelete: return (true, backend.DeleteKeyIfEmpty(t.Target!) ? "deleted" : "kept");
            case AdminPipeTweak.ExtensionBlockAdd: backend.AddExtensionBlock(Browser(t.Target)!.Value, t.Name!, t.Text!); return (true, null);
            case AdminPipeTweak.ExtensionBlockRemove: backend.RemoveExtensionBlock(Browser(t.Target)!.Value, t.Name!, t.Text!); return (true, null);
            case AdminPipeTweak.PageFileAuto:
                var auto = await backend.EnableAutoPageFileAsync(ct).ConfigureAwait(false);
                return (auto.Success, auto.Message);
            case AdminPipeTweak.PageFileRestore:
                var restore = await backend.RestorePageFileAsync(t.Text!, ct).ConfigureAwait(false);
                return (restore.Success, restore.Message);
            case AdminPipeTweak.DefenderRead:
                var json = await backend.ReadDefenderAsync(ct).ConfigureAwait(false);
                return (json is not null, json);
            case AdminPipeTweak.DefenderAdd:
                return await backend.AddDefenderExclusionsAsync(t.Folders ?? [], t.Processes ?? [], ct).ConfigureAwait(false);
            case AdminPipeTweak.DefenderRemove:
                return (await backend.RemoveDefenderExclusionsAsync(t.Folders ?? [], t.Processes ?? [], ct).ConfigureAwait(false), null);
            case AdminPipeTweak.DefenderTempAdd:
                return await backend.AddTempBuildDefenderExclusionAsync(t.Target!, ct).ConfigureAwait(false);
            case AdminPipeTweak.DefenderTempRemove:
                return (await backend.RemoveTempBuildDefenderExclusionAsync(t.Target!, ct).ConfigureAwait(false), null);
            case AdminPipeTweak.DevDriveCreate:
                var mounted = await backend.CreateTempDevDriveAsync(t.Number ?? DevDriveRules.DefaultSizeGb, t.Text, ct).ConfigureAwait(false);
                return (mounted.Ok, mounted.ToJson());
            case AdminPipeTweak.DevDriveRemove:
                return (await backend.RemoveTempDevDriveAsync(t.Target!, ct).ConfigureAwait(false), null);
            default:
                throw new InvalidOperationException($"Unknown change '{t.Action}'.");
        }
    }
}

/// <summary>
/// Which folders and programs the Agent agrees to exclude from Defender scanning. The app finds code folders under the signed-in user's
/// profile and the Agent may run as SYSTEM, so these rules go by the shape of the path, not by whose profile it is.
/// </summary>
public sealed record DefenderPaths(IReadOnlyList<string> SystemFolders, IReadOnlyList<string> ProgramFiles, Func<string, bool> DirectoryExists, Func<string, bool> FileExists)
{
    /// <summary>The build tools the fix excludes, relative to a Visual Studio edition folder (the same list the app looks for).</summary>
    public static readonly IReadOnlyList<string> BuildToolPaths =
        [@"Common7\IDE\devenv.exe", @"MSBuild\Current\Bin\MSBuild.exe", @"MSBuild\Current\Bin\amd64\MSBuild.exe", @"MSBuild\Current\Bin\Roslyn\VBCSCompiler.exe"];

    /// <summary>Folders under a user's profile that are never excluded themselves (their subfolders can be, except Downloads and AppData).</summary>
    private static readonly string[] ProfileFolders = ["Desktop", "Documents", "Downloads", "OneDrive", "source", "AppData", "Pictures", "Music", "Videos"];
    private static readonly string[] ProfileTrees = ["Downloads", "AppData"];

    public static DefenderPaths Current()
    {
        static string F(Environment.SpecialFolder f) => Environment.GetFolderPath(f);
        return new(
            new[] { F(Environment.SpecialFolder.Windows), F(Environment.SpecialFolder.ProgramFiles), F(Environment.SpecialFolder.ProgramFilesX86), F(Environment.SpecialFolder.CommonApplicationData) }
                .Where(x => x.Length > 0).ToList(),
            new[] { F(Environment.SpecialFolder.ProgramFiles), F(Environment.SpecialFolder.ProgramFilesX86) }.Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Directory.Exists, File.Exists);
    }

    /// <summary>A full local path like <c>D:\work\app</c>: drive letter, no wildcards, no <c>.</c> or <c>..</c> parts, no doubled separators.</summary>
    public static bool IsLocalPath(string? path)
    {
        if (path is not { Length: >= 3 and < 260 } || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\') return false;
        if (path.Any(c => char.IsControl(c) || c is '/' or '*' or '?' or '"' or '<' or '>' or '|') || path.IndexOf(':', 2) >= 0) return false;
        var parts = path[3..].TrimEnd('\\').Split('\\');
        return parts.All(s => s.Length > 0 && s != "." && s != ".." && s.Trim() == s && !s.EndsWith('.'));
    }

    private static string[] Parts(string path) => path.TrimEnd('\\').Split('\\');

    private static bool Same(string a, string b) => a.TrimEnd('\\').Equals(b.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    private static bool IsUnder(string path, string root) =>
        Same(path, root) || path.TrimEnd('\\').StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

    /// <summary>Why <paramref name="folder"/> can't be excluded, or null when it can.</summary>
    public string? FolderRefusal(string? folder, bool mustExist)
    {
        if (!IsLocalPath(folder)) return "That isn't a full local folder path.";
        var parts = Parts(folder!);
        if (parts.Length < 2) return "A whole drive is never excluded.";
        if (SystemFolders.Any(s => IsUnder(folder!, s))) return $"{folder} is a Windows or program folder; it's never excluded.";
        if (parts[1].Equals("Users", StringComparison.OrdinalIgnoreCase))
        {
            // C:\Users, C:\Users\<name>, and the profile's own top folders: far too broad.
            if (parts.Length <= 3) return $"{folder} is a whole user profile; it's never excluded.";
            if (parts.Length == 4 && ProfileFolders.Contains(parts[3], StringComparer.OrdinalIgnoreCase)) return $"{folder} is too broad to exclude.";
            if (ProfileTrees.Contains(parts[3], StringComparer.OrdinalIgnoreCase)) return $"{folder} holds downloads or app data; it's never excluded.";
        }
        if (mustExist && !DirectoryExists(folder!)) return $"{folder} doesn't exist.";
        return null;
    }

    /// <summary><c>&lt;Program Files&gt;\Microsoft Visual Studio\&lt;version&gt;\&lt;edition&gt;\</c> plus one of <see cref="BuildToolPaths"/>.</summary>
    public bool IsBuildTool(string? path, bool mustExist)
    {
        if (!IsLocalPath(path)) return false;
        foreach (var pf in ProgramFiles)
        {
            var vs = pf.TrimEnd('\\') + @"\Microsoft Visual Studio\";
            if (!path!.StartsWith(vs, StringComparison.OrdinalIgnoreCase)) continue;
            var rest = Parts(path[vs.Length..]);
            if (rest.Length < 3) continue;
            var tool = string.Join('\\', rest.Skip(2));
            if (BuildToolPaths.Any(t => t.Equals(tool, StringComparison.OrdinalIgnoreCase))) return !mustExist || FileExists(path);
        }
        return false;
    }
}

/// <summary>The custom page file sizes as the change journal keeps them: base64 of a JSON array of {Name, InitialSize, MaximumSize}.</summary>
public static class PageFileSettings
{
    /// <summary>One Win32_PageFileSetting (the names match what the earlier PowerShell version wrote).</summary>
    public sealed record Size(string Name, uint InitialSize, uint MaximumSize)
    {
        public static bool IsValidName(string? name) => name is { Length: > 3 and < 260 } && name[1] == ':' && char.IsAsciiLetter(name[0])
            && name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) && name.IndexOfAny(Path.GetInvalidPathChars()) < 0;
    }

    public static string Encode(IReadOnlyList<Size> rows) =>
        Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(rows)));

    /// <summary>The saved sizes, or null when the text isn't one this app saved (or names something other than a page file).</summary>
    public static IReadOnlyList<Size>? TryDecode(string? settings)
    {
        if (string.IsNullOrEmpty(settings) || settings.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '='))) return null;
        try
        {
            var json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(settings)).Trim();
            if (!json.StartsWith('[')) json = "[" + json + "]"; // one setting was saved as a single object
            var rows = JsonSerializer.Deserialize<List<Size>>(json) ?? [];
            return rows.Count == 0 || rows.Any(r => !Size.IsValidName(r.Name)) ? null : rows;
        }
        catch (Exception ex) when (ex is FormatException or JsonException) { return null; }
    }
}

/// <summary>
/// The app's side: each change goes to the Agent over the admin pipe (<see cref="IElevatedCommandBridge.MachineTweakAsync"/>).
/// Without the Agent the setters throw <see cref="AdminRequiredException"/> and change nothing; the outcomes say what to do.
/// </summary>
public sealed class AgentMachineTweaks(IElevatedCommandBridge? bridge, ILogger? log = null) : IMachineTweaks
{
    public void WriteDword(RegistrySetting setting, int value) => Send(new(AdminPipeTweak.RegistryWrite, Target: setting.Target, Number: value));
    public void DeleteDword(RegistrySetting setting) => Send(new(AdminPipeTweak.RegistryDelete, Target: setting.Target));
    public bool DeleteKeyIfEmpty(string key) => Send(new(AdminPipeTweak.RegistryKeyDelete, Target: key)) == "deleted";
    public void AddExtensionBlock(BrowserKind browser, string valueName, string extensionId) =>
        Send(new(AdminPipeTweak.ExtensionBlockAdd, Target: browser.ToString(), Name: valueName, Text: extensionId));
    public void RemoveExtensionBlock(BrowserKind browser, string valueName, string extensionId) =>
        Send(new(AdminPipeTweak.ExtensionBlockRemove, Target: browser.ToString(), Name: valueName, Text: extensionId));

    public Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct) => OutcomeAsync(new(AdminPipeTweak.PageFileAuto), ct);
    public Task<ActionOutcome> RestorePageFileAsync(string settings, CancellationToken ct) => OutcomeAsync(new(AdminPipeTweak.PageFileRestore, Text: settings), ct);

    /// <summary>Null without the Agent (or with one from before this): the app then reads what it can itself.</summary>
    public async Task<string?> ReadDefenderAsync(CancellationToken ct)
    {
        if (bridge is not { IsConnected: true }) return null;
        try
        {
            var r = await bridge.MachineTweakAsync(new(AdminPipeTweak.DefenderRead), ct).ConfigureAwait(false);
            return r.Ok ? r.StdOut : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.Info("[machine-tweaks] Defender read in the Agent: " + ex.Message); return null; }
    }

    public async Task<(bool Ok, string? Output)> AddDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct)
    {
        var r = await bridge.RequireAgent().MachineTweakAsync(new(AdminPipeTweak.DefenderAdd, Folders: folders, Processes: processes), ct).ConfigureAwait(false);
        if (!r.Ok) log.Warn("[machine-tweaks] Defender exclusions not added: " + r.Error);
        return (r.Ok, r.Ok ? r.StdOut : null);
    }

    public async Task<bool> RemoveDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct)
    {
        var r = await bridge.RequireAgent().MachineTweakAsync(new(AdminPipeTweak.DefenderRemove, Folders: folders, Processes: processes), ct).ConfigureAwait(false);
        if (!r.Ok) log.Warn("[machine-tweaks] Defender exclusions not removed: " + r.Error);
        return r.Ok;
    }

    public async Task<(bool Ok, string? Output)> AddTempBuildDefenderExclusionAsync(string folder, CancellationToken ct)
    {
        var r = await bridge.RequireAgent().MachineTweakAsync(new(AdminPipeTweak.DefenderTempAdd, Target: folder), ct).ConfigureAwait(false);
        if (!r.Ok) log.Warn("[machine-tweaks] Temporary Defender build exclusion not added: " + r.Error);
        return (r.Ok, r.Ok ? r.StdOut : null);
    }

    public async Task<bool> RemoveTempBuildDefenderExclusionAsync(string folder, CancellationToken ct)
    {
        var r = await bridge.RequireAgent().MachineTweakAsync(new(AdminPipeTweak.DefenderTempRemove, Target: folder), ct).ConfigureAwait(false);
        if (!r.Ok) log.Warn("[machine-tweaks] Temporary Defender build exclusion not removed: " + r.Error);
        return r.Ok;
    }

    public async Task<DevDriveMountResult> CreateTempDevDriveAsync(int sizeGb, string? grantUserSid, CancellationToken ct)
    {
        var r = await bridge.RequireAgent().MachineTweakAsync(new(AdminPipeTweak.DevDriveCreate, Number: sizeGb, Text: grantUserSid), ct).ConfigureAwait(false);
        if (!r.Ok)
        {
            log.Warn("[machine-tweaks] Temporary Dev Drive not created: " + r.Error);
            return new(false, Error: r.Error ?? "The Agent could not create a temporary Dev Drive.");
        }
        return DevDriveMountResult.FromJson(r.StdOut) ?? new(false, Error: "The Agent returned an unreadable Dev Drive response.");
    }

    public async Task<bool> RemoveTempDevDriveAsync(string vhdxPath, CancellationToken ct)
    {
        var r = await bridge.RequireAgent().MachineTweakAsync(new(AdminPipeTweak.DevDriveRemove, Target: vhdxPath), ct).ConfigureAwait(false);
        if (!r.Ok) log.Warn("[machine-tweaks] Temporary Dev Drive not removed: " + r.Error);
        return r.Ok;
    }

    private async Task<ActionOutcome> OutcomeAsync(AdminPipeTweak t, CancellationToken ct)
    {
        try
        {
            var r = await bridge.RequireAgent().MachineTweakAsync(t, ct).ConfigureAwait(false);
            return new(r.Ok, (r.Ok ? r.StdOut : r.Error) is { Length: > 0 } m ? m : r.Ok ? "Done." : "The Agent didn't make the change.");
        }
        catch (AdminRequiredException ex) { return new(false, ex.Message); }
    }

    /// <summary>The callers are synchronous (registry-style setters); the pipe call runs on the thread pool so no caller's context is captured.</summary>
    private string? Send(AdminPipeTweak t)
    {
        var b = bridge.RequireAgent();
        var r = Task.Run(() => b.MachineTweakAsync(t)).GetAwaiter().GetResult();
        if (!r.Ok) throw new InvalidOperationException(r.Error ?? "The Agent didn't make the change.");
        return r.StdOut;
    }
}

internal static class AgentBridgeExtensions
{
    public static IElevatedCommandBridge RequireAgent(this IElevatedCommandBridge? bridge) =>
        bridge is { IsConnected: true } b ? b : throw new AdminRequiredException("The Agent isn't connected. " + ElevationService.AdminRepairHint);
}

/// <summary>The changes themselves, in the Agent (elevated helper or agent service). Callers check <see cref="MachineTweakRules"/> first.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsMachineTweaks(ILogger? log = null, IProcessLauncher? launcher = null) : IMachineTweaks
{
    private readonly IProcessLauncher _launcher = launcher ?? new SystemProcessLauncher();
    private void Log(string m) => log.Info("[machine-tweaks] " + m);

    private static RegistryKey Hklm() => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

    private static RegistrySetting Allowed(RegistrySetting s) =>
        MachineTweakRules.MachineSetting(s.Target) ?? throw new InvalidOperationException($"{s.Target} isn't a registry value the Agent changes.");

    public void WriteDword(RegistrySetting setting, int value)
    {
        var s = Allowed(setting);
        using var root = Hklm();
        var created = RegistryKeyCleanup.TopmostMissing(s.Key, path => KeyExists(root, path));
        var k = root.CreateSubKey(s.Key, writable: true) ?? throw new UnauthorizedAccessException($"Can't open {s.Key}.");
        try { k.SetValue(s.Name, value, RegistryValueKind.DWord); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            k.Dispose();
            RemoveCreatedKeys(root, s.Key, created);
            throw;
        }
        finally { k.Dispose(); }
        Log($"{s.Target} set to {value}" + (created is null ? "" : $" (created {created})"));
    }

    public void DeleteDword(RegistrySetting setting)
    {
        var s = Allowed(setting);
        using var root = Hklm();
        using var k = root.OpenSubKey(s.Key, writable: true);
        k?.DeleteValue(s.Name, throwOnMissingValue: false);
        Log($"{s.Target} deleted");
    }

    public bool DeleteKeyIfEmpty(string key)
    {
        using var root = Hklm();
        return DeleteKeyIfEmpty(root, key);
    }

    /// <summary>A key that can't be opened for reading counts as existing (never recorded as created, so never deleted).</summary>
    private static bool KeyExists(RegistryKey root, string key)
    {
        try { using var k = root.OpenSubKey(key); return k is not null; }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return true; }
    }

    private void RemoveCreatedKeys(RegistryKey root, string key, string? created)
    {
        foreach (var k in RegistryKeyCleanup.DeleteOrder(key, created))
        {
            try { if (!DeleteKeyIfEmpty(root, k)) break; }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException or InvalidOperationException or ArgumentException)
            {
                Log($"Couldn't remove the key {k} created by a refused write: {ex.Message}");
                break;
            }
        }
    }

    private bool DeleteKeyIfEmpty(RegistryKey root, string key)
    {
        if (!RegistryKeyCleanup.IsCleanupKey(RegistryRoot.LocalMachine, key)) { Log($"{key} isn't a key the Agent may remove"); return false; }
        var path = RegistryKeyCleanup.Chain(key)[^1];
        using (var k = root.OpenSubKey(path))
        {
            if (k is null) return true;
            if (k.SubKeyCount > 0 || k.ValueCount > 0) return false;
        }
        var cut = path.LastIndexOf('\\');
        using var parent = root.OpenSubKey(path[..cut], writable: true);
        if (parent is null) return true;
        parent.DeleteSubKey(path[(cut + 1)..], throwOnMissingSubKey: false);
        Log($@"HKLM\{path} removed (empty; created by this app)");
        return true;
    }

    public void AddExtensionBlock(BrowserKind browser, string valueName, string extensionId)
    {
        if (BrowserExtensions.Known(browser, extensionId) is not { } known) throw new InvalidOperationException($"{extensionId} isn't an extension this app may block.");
        if (!BrowserExtensions.IsEntryName(valueName)) throw new InvalidOperationException($"'{valueName}' isn't a blocklist entry name.");
        var keyPath = BrowserExtensions.BlocklistKey(browser);
        using var root = Hklm();
        var created = RegistryKeyCleanup.TopmostMissing(keyPath, path => KeyExists(root, path));
        var key = root.CreateSubKey(keyPath, writable: true) ?? throw new UnauthorizedAccessException("Can't open the blocklist key.");
        try
        {
            if (key.GetValue(valueName) is not null) throw new InvalidOperationException($"Blocklist entry {valueName} already exists.");
            key.SetValue(valueName, known.Id, RegistryValueKind.String);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            key.Dispose();
            RemoveCreatedKeys(root, keyPath, created);
            throw;
        }
        finally { key.Dispose(); }
        Log($@"HKLM\{keyPath}\{valueName} = {known.Id} ({known.Name})" + (created is null ? "" : $" (created {created})"));
    }

    public void RemoveExtensionBlock(BrowserKind browser, string valueName, string extensionId)
    {
        if (BrowserExtensions.Known(browser, extensionId) is not { } known) throw new InvalidOperationException($"{extensionId} isn't an extension this app may block.");
        if (!BrowserExtensions.IsEntryName(valueName)) throw new InvalidOperationException($"'{valueName}' isn't a blocklist entry name.");
        using var root = Hklm();
        using var key = root.OpenSubKey(BrowserExtensions.BlocklistKey(browser), writable: true);
        if (key?.GetValue(valueName) is not string data || !data.Trim().Equals(known.Id, StringComparison.OrdinalIgnoreCase)) return;
        key.DeleteValue(valueName, throwOnMissingValue: false);
        Log($@"HKLM\{BrowserExtensions.BlocklistKey(browser)}\{valueName} ({known.Name}) deleted");
    }

    public Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            SetAutomaticPageFile(true);
            Log("Automatic page file: on");
            return new ActionOutcome(true, "Windows will manage the page file size from the next restart.");
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            Log($"Automatic page file: {ex.Message}");
            return new ActionOutcome(false, "Windows didn't allow changing the page file setting.");
        }
    }, ct);

    public Task<ActionOutcome> RestorePageFileAsync(string settings, CancellationToken ct) => Task.Run(() =>
    {
        if (PageFileSettings.TryDecode(settings) is not { } rows) return new ActionOutcome(false, "The saved page file settings are unreadable.");
        try
        {
            SetAutomaticPageFile(false);
            foreach (var row in rows)
            {
                ManagementObject? existing = null;
                try
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PageFileSetting"))
                    using (var results = searcher.Get())
                    {
                        foreach (ManagementObject o in results)
                        {
                            if (existing is null && string.Equals(o["Name"] as string, row.Name, StringComparison.OrdinalIgnoreCase)) existing = o;
                            else o.Dispose();
                        }
                    }
                    if (existing is null)
                    {
                        using var cls = new ManagementClass("Win32_PageFileSetting");
                        existing = cls.CreateInstance();
                        existing["Name"] = row.Name;
                    }
                    existing["InitialSize"] = row.InitialSize;
                    existing["MaximumSize"] = row.MaximumSize;
                    existing.Put();
                }
                finally { existing?.Dispose(); }
            }
            Log($"Page file sizes restored: {rows.Count} setting(s)");
            return new ActionOutcome(true, "Custom page file size restored (takes effect after a restart).");
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            Log($"Restore page file: {ex.Message}");
            return new ActionOutcome(false, "Windows didn't allow restoring the page file setting.");
        }
    }, ct);

    private static void SetAutomaticPageFile(bool automatic)
    {
        using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
        using var results = searcher.Get();
        foreach (ManagementObject cs in results)
            using (cs) { cs["AutomaticManagedPagefile"] = automatic; cs.Put(); }
    }

    public async Task<string?> ReadDefenderAsync(CancellationToken ct)
    {
        var r = await PowerShellAsync(DefenderProbe.Script, ct).ConfigureAwait(false);
        return r.ExitCode == 0 ? r.StdOut : null;
    }

    public async Task<(bool Ok, string? Output)> AddDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct)
    {
        var r = await PowerShellAsync(DefenderProbe.AddScript(folders, processes), ct).ConfigureAwait(false);
        Log($"Defender exclusions add ({folders.Count} folder(s), {processes.Count} program(s)): exit {r.ExitCode}");
        return r.ExitCode == 0 ? (true, r.StdOut) : (false, null);
    }

    public async Task<bool> RemoveDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct)
    {
        var r = await PowerShellAsync(DefenderProbe.RemoveScript(folders, processes), ct).ConfigureAwait(false);
        Log($"Defender exclusions remove ({folders.Count} folder(s), {processes.Count} program(s)): exit {r.ExitCode}");
        return r.ExitCode == 0;
    }

    public Task<(bool Ok, string? Output)> AddTempBuildDefenderExclusionAsync(string folder, CancellationToken ct) =>
        AddDefenderExclusionsAsync([folder], [], ct);

    public Task<bool> RemoveTempBuildDefenderExclusionAsync(string folder, CancellationToken ct) =>
        RemoveDefenderExclusionsAsync([folder], [], ct);

    public Task<DevDriveMountResult> CreateTempDevDriveAsync(int sizeGb, string? grantUserSid, CancellationToken ct) =>
        new WindowsDevDriveManager(log, _launcher).CreateAndMountAsync(sizeGb, grantUserSid, ct);

    public Task<bool> RemoveTempDevDriveAsync(string vhdxPath, CancellationToken ct) =>
        new WindowsDevDriveManager(log, _launcher).RemoveAsync(vhdxPath, ct);

    private async Task<ProcessResult> PowerShellAsync(string script, CancellationToken ct)
    {
        var r = await _launcher.RunAsync(SystemCommandRunner.PowerShell, SystemCommandRunner.PowerShellArgs(script), TimeSpan.FromMinutes(2), ct).ConfigureAwait(false);
        if (r.ExitCode != 0) Log($"PowerShell exit {r.ExitCode}: {r.StdErr.Trim()}");
        return r;
    }
}
