using System.Text.Json;
using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>
/// #3 / #8 / #10: which pre-installed apps this app may remove, and how. Ticked: retired Microsoft apps, Power Automate, Journal on a PC without a pen,
/// and the Lenovo Now / Brother PowerENGAGE promoters. Opt-in: consumer apps (one card each) and the Xbox apps (one card for the group).
/// </summary>
public enum AppGroup { Retired, Consumer, Xbox, Vendor, Narrator }

/// <summary>
/// One Store (Appx) package on the removal allowlist. <see cref="Name"/> + <see cref="PublisherId"/> = the package family name; both must
/// match before anything is removed (a package with the same name from another publisher is left alone).
/// </summary>
/// <param name="Id">Stable id used in suggestion ids and workflow fix ids.</param>
/// <param name="What">One sentence for the card: what the app is and why it can go.</param>
/// <param name="Lose">What the client loses.</param>
/// <param name="StoreId">Microsoft Store product id ("9WZDNCRFJ3Q2"), only when its apps.microsoft.com listing was checked to be this app from
/// Microsoft. Undo reinstalls it with winget from the msstore source (see <see cref="StoreReinstall"/>). Null = removal stays permanent.</param>
public sealed record RemovableAppx(string Id, string Name, string PublisherId, string Label, AppGroup Group, string What, string Lose, string? StoreId = null)
{
    public string FamilyName => $"{Name}_{PublisherId}";
}

/// <summary>A scheduled task this app may disable: an exact path, or (vendor folders only) every task in <see cref="Folder"/> whose name starts with <see cref="Name"/>.</summary>
/// <param name="Folder">Task folder with leading and trailing backslash ("\" = root, "\Microsoft\XblGameSave\").</param>
public sealed record TaskRule(string Folder, string Name, bool NamePrefix = false)
{
    public bool Matches(string path)
    {
        var (folder, name) = ScheduledTaskAllowlist.Split(path);
        if (folder is null || !folder.Equals(Folder, StringComparison.OrdinalIgnoreCase)) return false;
        return NamePrefix ? name.StartsWith(Name, StringComparison.OrdinalIgnoreCase) : name.Equals(Name, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// A desktop (Win32) program on the removal allowlist, found in the Uninstall registry keys by exact DisplayName and a Publisher fragment.
/// It's only ever removed with its own vendor uninstaller under Program Files (fixed silent arguments, never the registry's command line),
/// or, for Windows Installer entries, with <c>msiexec /x {ProductCode}</c> where the product code is the entry's own key name.
/// </summary>
/// <param name="UninstallerExe">The only uninstaller file name accepted ("unins000.exe").</param>
/// <param name="UninstallerFolder">A folder fragment the uninstaller path must contain ("\Lenovo\").</param>
/// <param name="SilentArgs">The arguments passed to it (ours, not the registry's).</param>
/// <param name="AllowMsi">Windows Installer entries may be removed with msiexec /x {key name} /qn /norestart.</param>
public sealed record RemovableProgram(string Id, string Label, IReadOnlyList<string> DisplayNames, IReadOnlyList<string> Publishers,
    string? UninstallerExe, string? UninstallerFolder, IReadOnlyList<string> SilentArgs, bool AllowMsi, IReadOnlyList<TaskRule> Tasks, string What, string Lose, string ReinstallFrom)
{
    public bool Matches(UninstallEntry p) =>
        DisplayNames.Any(d => d.Equals(p.DisplayName.Trim(), StringComparison.OrdinalIgnoreCase))
        && p.Publisher is { } pub && Publishers.Any(f => pub.Contains(f, StringComparison.OrdinalIgnoreCase));
}

/// <summary>An installed Store package found by the Host (all architectures/resource packs of one family merged).</summary>
/// <param name="ForUser">Registered for the account this app runs as.</param>
/// <param name="Provisioned">Provisioned: Windows installs it for every new account.</param>
/// <param name="SizeBytes">Install folder plus this account's app data; null = couldn't measure.</param>
public sealed record InstalledAppx(string Name, string PublisherId, bool ForUser, bool Provisioned, long? SizeBytes = null)
{
    public string FamilyName => $"{Name}_{PublisherId}";
}

/// <summary>An Uninstall registry entry that matched a <see cref="RemovableProgram"/>.</summary>
/// <param name="Hive">"HKLM64", "HKLM32" or "HKCU" (where the entry was found; used to read it back).</param>
/// <param name="KeyName">The Uninstall subkey name (an MSI product code for Windows Installer entries).</param>
public sealed record UninstallEntry(string Hive, string KeyName, string DisplayName, string? Publisher, string? QuietUninstallString, string? UninstallString,
    bool WindowsInstaller, long? SizeBytes = null, string? Version = null);

/// <summary>Everything the app-removal rules look at. Built by the Host (registry reads + cached folder sizes); null fields = couldn't read.</summary>
/// <param name="Settings">Allowlisted DWORDs (ContentDeliveryManager, GameDVR) by journal target; value null = absent. Missing key = unreadable.</param>
/// <param name="ScheduledTasks">Allowlisted task paths that exist on this PC.</param>
/// <param name="NarratorInUse">Narrator is running or set to start at sign-in / on the sign-in screen; null = couldn't tell (treated as in use).</param>
public sealed record AppRemovalInfo(
    IReadOnlyList<InstalledAppx> Packages,
    IReadOnlyList<UninstallEntry> Programs,
    IReadOnlyDictionary<string, int?> Settings,
    IReadOnlyList<string> ScheduledTasks,
    bool? NarratorInUse = null)
{
    public static readonly AppRemovalInfo Empty = new([], [], new Dictionary<string, int?>(), []);
}

/// <summary>A vendor uninstall command this app built and validated. <see cref="Msi"/>: <see cref="Path"/> is the product code ("{GUID}").</summary>
public sealed record UninstallCommand(bool Msi, string Path, IReadOnlyList<string> Arguments)
{
    public string Display => Msi ? "msiexec.exe " + string.Join(' ', Arguments) : $"\"{Path}\" {string.Join(' ', Arguments)}";
}

/// <summary>The only scheduled tasks this app disables (and re-enables on undo).</summary>
public static class ScheduledTaskAllowlist
{
    /// <summary>Xbox cloud-save sync task (#8).</summary>
    public static readonly TaskRule XblGameSave = new(@"\Microsoft\XblGameSave\", "XblGameSaveTask");
    /// <summary>Brother PowerENGAGE: runs every 6 hours (msiexec /f repair, then PowerENGAGE.exe scheduled-run) (#10).</summary>
    public static readonly TaskRule PowerEngage = new(@"\", "PowerENGAGE");
    /// <summary>Lenovo Now's promotion tasks (#10): every task in \Lenovo\ whose name starts with "LenovoNow". Exact names weren't verified.</summary>
    public static readonly TaskRule LenovoNow = new(@"\Lenovo\", "LenovoNow", NamePrefix: true);

    public static readonly IReadOnlyList<TaskRule> All = [XblGameSave, PowerEngage, LenovoNow];

    public static bool IsAllowed(string? path) => path is not null && Split(path).Folder is not null && All.Any(r => r.Matches(path));

    /// <summary>"\Microsoft\XblGameSave\XblGameSaveTask" → ("\Microsoft\XblGameSave\", "XblGameSaveTask"). Folder null when it isn't a plain task path.</summary>
    public static (string? Folder, string Name) Split(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !path.StartsWith('\\') || path.EndsWith('\\') || path.Contains("..", StringComparison.Ordinal)
            || path.Contains('/') || path.Contains('\'') || path.Contains('"') || path.Contains('*') || path.Contains('?') || path.Any(char.IsControl))
            return (null, "");
        var i = path.LastIndexOf('\\');
        return (path[..(i + 1)], path[(i + 1)..]);
    }

    private static string Q(string s) => "'" + s.Replace("'", "''") + "'";

    /// <summary>Prints the task's state ("Ready", "Disabled", "Running", "Queued") or "Missing".</summary>
    public static string StateScript(string path)
    {
        var (folder, name) = Split(path);
        if (folder is null || !IsAllowed(path)) throw new InvalidOperationException($"{path} isn't a scheduled task this app may change.");
        return "$ErrorActionPreference='Stop';" +
            $"$t=Get-ScheduledTask -TaskPath {Q(folder)} -TaskName {Q(name)} -ErrorAction SilentlyContinue;" +
            "if($null -eq $t){'Missing'}else{[string]$t.State}";
    }

    /// <summary>Disables (or enables) the task, then prints its state like <see cref="StateScript"/>.</summary>
    public static string SetScript(string path, bool enabled)
    {
        var (folder, name) = Split(path);
        if (folder is null || !IsAllowed(path)) throw new InvalidOperationException($"{path} isn't a scheduled task this app may change.");
        return "$ErrorActionPreference='Stop';" +
            $"{(enabled ? "Enable" : "Disable")}-ScheduledTask -TaskPath {Q(folder)} -TaskName {Q(name)} | Out-Null;" +
            $"$t=Get-ScheduledTask -TaskPath {Q(folder)} -TaskName {Q(name)} -ErrorAction SilentlyContinue;" +
            "if($null -eq $t){'Missing'}else{[string]$t.State}";
    }

    /// <summary>"Missing" = the task doesn't exist; other non-empty values are Task Scheduler states.</summary>
    public const string Missing = "Missing";

    public static bool IsEnabledState(string? state) => state is "Ready" or "Running" or "Queued";
}

public static class AppRemoval
{
    public const string MicrosoftPublisherId = "8wekyb3d8bbwe";
    /// <summary>Publisher id of Windows' own system packages (MicrosoftWindows.*).</summary>
    public const string WindowsPublisherId = "cw5n1h2txyewy";
    public const string StoreReinstall = "reinstall from the Microsoft Store if needed";
    /// <summary>Card / report wording for removed Store apps: how to get them back (instead of "can't be undone").</summary>
    public const string StoreGetBack = "To get it back, reinstall it from the Microsoft Store.";
    public const string StoreGetBackMany = "To get them back, reinstall them from the Microsoft Store.";
    /// <summary>Card / confirm / result wording for retired apps (<see cref="AppGroup.Retired"/> without a Store id): there may be nothing to reinstall.</summary>
    public const string RetiredGetBack = "Microsoft has retired it, so it may not be available to reinstall.";
    /// <summary>Journal label ending for a removed retired app.</summary>
    public const string RetiredLabel = "Microsoft has retired it, so it may not be available to reinstall";

    /// <summary>A retired app (Mail and Calendar, Maps, People, Dev Home, Mixed Reality Portal) that undo can't reinstall: permanent, and the Store may not have it.</summary>
    public static bool IsRetiredPermanent(RemovableAppx a) => a.Group == AppGroup.Retired && !global::RemotePCDiagnostics.Core.Memory.StoreReinstall.CanReinstall(a);

    /// <summary>How to get a removed package back: undo reinstalls it, reinstall it from the Store, or (retired) it may not be available.</summary>
    public static string GetBack(RemovableAppx a) =>
        global::RemotePCDiagnostics.Core.Memory.StoreReinstall.CanReinstall(a) ? StoreUndo : IsRetiredPermanent(a) ? RetiredGetBack : StoreGetBack;
    /// <summary>Workflow chip for removed apps without a verified Store id (replaces the generic "can't be undone").</summary>
    public const string StoreManualChip = "reinstall from Store";
    /// <summary>Workflow chip for removed apps that undo reinstalls from the Microsoft Store (<see cref="StoreReinstall"/>).</summary>
    public const string StoreChip = "undo reinstalls from Store";
    /// <summary>Card / report wording when every app the fix removes has a verified Store id.</summary>
    public const string StoreUndo = "Undo reinstalls it from the Microsoft Store for the signed-in account (needs internet); its settings and data aren't restored.";
    public const string StoreUndoMany = "Undo reinstalls them from the Microsoft Store for the signed-in account (needs internet); their settings and data aren't restored.";
    public static string VendorGetBack(string vendor) => $"To get it back, reinstall it from {vendor}.";
    public static string VendorChip(string vendor) => $"reinstall from {vendor}";

    private static RemovableAppx Ms(string id, string name, string label, AppGroup g, string what, string lose, string? storeId = null) =>
        new(id, name, MicrosoftPublisherId, label, g, what, lose, storeId);

    /// <summary>
    /// The only Store packages this app removes. Family names verified against Microsoft's published names
    /// (<c>Name_8wekyb3d8bbwe</c> for Microsoft apps; Clipchamp's own publisher id). Dropbox's OEM promo (C27EB4BA.DropboxOEM) is left out:
    /// its publisher id couldn't be verified. Never the Store, Photos, Calculator, Notepad, Terminal, Edge, App Installer, codecs or drivers
    /// (see <see cref="NeverRemove"/>).
    /// Store ids (undo reinstalls with winget) only where the apps.microsoft.com listing was checked: same app, Microsoft as developer. Retired apps
    /// (Mail and Calendar, Maps, People, Dev Home, Mixed Reality Portal), Narrator's add-ons, the Xbox overlays / TCUI / Edge Game Assist (not sold
    /// on the Store), and Get Help, Game Bar, Xbox Identity Provider and the Dropbox offer (developer couldn't be confirmed) have none: permanent.
    /// </summary>
    public static readonly IReadOnlyList<RemovableAppx> Packages =
    [
        // Ticked: retired or unsupported Microsoft apps.
        Ms("mail-calendar", "microsoft.windowscommunicationsapps", "Mail and Calendar", AppGroup.Retired,
            "Mail and Calendar is retired: Microsoft stopped supporting it at the end of 2024 and replaced it with the new Outlook.",
            "The old Mail and Calendar apps. Email and calendars stay in the account (the new Outlook or a browser shows them)."),
        Ms("maps", "Microsoft.WindowsMaps", "Maps", AppGroup.Retired,
            "Microsoft retired the Windows Maps app in 2025.", "The Maps app (Bing Maps or Google Maps in a browser still work)."),
        Ms("people", "Microsoft.People", "People", AppGroup.Retired,
            "Microsoft retired the standalone People app; contacts now live in Outlook.", "The old People app. Contacts stay in the account."),
        Ms("devhome", "Microsoft.Windows.DevHome", "Dev Home", AppGroup.Retired,
            "Microsoft retired Dev Home in 2025.", "The Dev Home dashboard (developer tools themselves aren't touched)."),
        Ms("mixed-reality", "Microsoft.MixedReality.Portal", "Mixed Reality Portal", AppGroup.Retired,
            "Microsoft retired Windows Mixed Reality (VR headsets).", "The Mixed Reality Portal for Windows VR headsets."),
        Ms("journal", "Microsoft.MicrosoftJournal", "Microsoft Journal", AppGroup.Retired,
            "Microsoft Journal is a handwriting app for a pen, and this PC has no pen.", "The Journal handwriting app.", "9N318R854RHH"),
        // Opt-in: consumer apps, one card each.
        new("clipchamp", "Clipchamp.Clipchamp", "yxz26nhyzhsrt", "Clipchamp", AppGroup.Consumer,
            "Clipchamp is Microsoft's video editor. It's large, mostly because of the video and AI files it keeps.", "The Clipchamp video editor and any projects saved only inside it.", "9P1J8S7CCWWT"),
        Ms("power-automate", "Microsoft.PowerAutomateDesktop", "Power Automate", AppGroup.Consumer,
            "Power Automate (desktop) records and runs automation flows. Most people never open it.", "Power Automate and any desktop flows saved on this PC.", "9NFTCH6J7FHV"),
        Ms("bing-news", "Microsoft.BingNews", "Microsoft News", AppGroup.Consumer,
            "Microsoft News (Bing News) shows a news feed.", "The News app (news is still in a browser).", "9WZDNCRFHVFW"),
        Ms("bing-weather", "Microsoft.BingWeather", "Weather", AppGroup.Consumer,
            "The Weather app (Bing Weather).", "The Weather app (weather is still in a browser).", "9WZDNCRFJ3Q2"),
        Ms("todo", "Microsoft.Todos", "Microsoft To Do", AppGroup.Consumer,
            "Microsoft To Do keeps task lists.", "The To Do app on this PC. Lists stay in the Microsoft account (to-do.office.com, Outlook).", "9NBLGGH5R558"),
        Ms("get-help", "Microsoft.GetHelp", "Get Help", AppGroup.Consumer,
            "Get Help is Microsoft's support chat app.", "The Get Help app; some Settings troubleshooters open it."),
        Ms("feedback-hub", "Microsoft.WindowsFeedbackHub", "Feedback Hub", AppGroup.Consumer,
            "Feedback Hub sends feedback and bug reports to Microsoft.", "Sending feedback to Microsoft from this PC.", "9NBLGGH4R32N"),
        Ms("solitaire", "Microsoft.MicrosoftSolitaireCollection", "Solitaire Collection", AppGroup.Consumer,
            "Microsoft Solitaire Collection: card games with ads.", "The Solitaire games (and their saved progress on this PC).", "9WZDNCRFHWD2"),
        new("dropbox-oem", "C27EB4BA.DropboxOEM", "xbfy0k16fey96", "Dropbox promotion", AppGroup.Consumer,
            "A Dropbox sign-up offer the PC maker pre-installed (not the Dropbox app itself).", "The pre-installed Dropbox offer. The real Dropbox app, if installed separately, isn't touched."),
        // Ticked when Narrator isn't used: Narrator's add-ons for Office and Outlook on the web (one group). Narrator itself stays.
        new("narrator-word", "MicrosoftWindows.NarratorExtension-Word", WindowsPublisherId, "Narrator for Word", AppGroup.Narrator,
            "Narrator's add-on for reading Word documents.", "Narrator's Word support."),
        new("narrator-ppt", "MicrosoftWindows.NarratorExtension-ppt", WindowsPublisherId, "Narrator for PowerPoint", AppGroup.Narrator,
            "Narrator's add-on for PowerPoint.", "Narrator's PowerPoint support."),
        new("narrator-owa", "MicrosoftWindows.NarratorExtension-OutlookWebApp", WindowsPublisherId, "Narrator for Outlook on the web", AppGroup.Narrator,
            "Narrator's add-on for Outlook on the web.", "Narrator's Outlook on the web support."),
        new("narrator-excel", "MicrosoftWindows.NarratorScript.Excel", WindowsPublisherId, "Narrator for Excel", AppGroup.Narrator,
            "Narrator's script for Excel.", "Narrator's Excel support."),
        new("narrator-outlook", "MicrosoftWindows.NarratorScript.Outlook", WindowsPublisherId, "Narrator for Outlook", AppGroup.Narrator,
            "Narrator's script for Outlook.", "Narrator's Outlook support."),
        // Opt-in: the Xbox apps, as one group.
        Ms("xbox-app", "Microsoft.GamingApp", "Xbox app", AppGroup.Xbox, "The Xbox app (Game Pass, Xbox store).", "The Xbox app.", "9MV0B5HZVK9Z"),
        Ms("xbox-gamebar", "Microsoft.XboxGamingOverlay", "Xbox Game Bar", AppGroup.Xbox, "Xbox Game Bar (Win+G overlay, recording).", "Win+G Game Bar and game clip recording."),
        Ms("xbox-overlay", "Microsoft.XboxGameOverlay", "Xbox Game overlay", AppGroup.Xbox, "The older Xbox game overlay.", "The older in-game overlay."),
        Ms("xbox-speech", "Microsoft.XboxSpeechToTextOverlay", "Xbox speech-to-text overlay", AppGroup.Xbox, "Xbox party chat speech-to-text.", "Speech-to-text in Xbox party chat."),
        Ms("xbox-tcui", "Microsoft.Xbox.TCUI", "Xbox TCUI", AppGroup.Xbox, "Xbox sign-in and friends pop-ups used by games.", "Xbox friends and profile pop-ups in games."),
        Ms("xbox-identity", "Microsoft.XboxIdentityProvider", "Xbox Identity Provider", AppGroup.Xbox, "Xbox Live sign-in for games.", "Signing in to Xbox Live from PC games."),
        Ms("xbox-edge-gameassist", "Microsoft.Edge.GameAssist", "Edge Game Assist", AppGroup.Xbox,
            "Edge Game Assist: an in-game browser widget Microsoft promotes inside Game Bar.", "The Edge browser widget inside Game Bar (Edge itself isn't touched)."),
    ];

    /// <summary>The only desktop programs this app uninstalls (#10).</summary>
    public static readonly IReadOnlyList<RemovableProgram> Programs =
    [
        new("lenovo-now", "Lenovo Now", ["Lenovo Now"], ["Lenovo"], "unins000.exe", @"\Lenovo\", ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"], AllowMsi: false,
            [ScheduledTaskAllowlist.LenovoNow],
            "Lenovo Now is Lenovo's promotions and offers app; the PC, its drivers and Lenovo Vantage don't need it.",
            "Lenovo's offers and promotions app (Lenovo Vantage, drivers and warranty info are separate and stay).", "Lenovo"),
        new("powerengage", "Brother PowerENGAGE", ["Brother PowerENGAGE", "PowerENGAGE"], ["Brother", "Aviata"], null, null, [], AllowMsi: true,
            [ScheduledTaskAllowlist.PowerEngage],
            "Brother PowerENGAGE is a printer marketing and survey helper. Every 6 hours its task re-runs a Windows Installer repair and then the helper.",
            "Brother's PowerENGAGE offers and surveys. Printing, scanning and the Brother driver keep working.", "Brother"),
    ];

    /// <summary>Package names that are never removed, even if someone adds them to <see cref="Packages"/> by mistake (tests check it).</summary>
    public static readonly IReadOnlySet<string> NeverRemove = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.WindowsStore", "Microsoft.StorePurchaseApp", "Microsoft.Windows.Photos", "Microsoft.WindowsCalculator", "Microsoft.WindowsNotepad",
        "Microsoft.WindowsTerminal", "Microsoft.MicrosoftEdge", "Microsoft.MicrosoftEdge.Stable", "Microsoft.DesktopAppInstaller", "Microsoft.SecHealthUI",
        "Microsoft.HEIFImageExtension", "Microsoft.HEVCVideoExtension", "Microsoft.VP9VideoExtensions", "Microsoft.WebMediaExtensions", "Microsoft.WebpImageExtension",
        "Microsoft.RawImageExtension", "Microsoft.AV1VideoExtension", "Microsoft.MPEG2VideoExtension", "Microsoft.AVCEncoderVideoExtension",
        "Microsoft.VCLibs.140.00", "Microsoft.VCLibs.140.00.UWPDesktop", "Microsoft.UI.Xaml.2.8", "Microsoft.NET.Native.Framework.2.2", "Microsoft.NET.Native.Runtime.2.2",
        "Microsoft.WindowsAppRuntime.1.5", "Microsoft.Paint", "Microsoft.ScreenSketch", "Microsoft.WindowsCamera", "Microsoft.WindowsSoundRecorder",
        "Microsoft.Windows.ShellExperienceHost", "Microsoft.Windows.StartMenuExperienceHost", "MicrosoftWindows.Client.WebExperience",
    };

    /// <summary>The allowlisted package with exactly this name and publisher id, or null (never one on <see cref="NeverRemove"/>).</summary>
    public static RemovableAppx? FindPackage(string? name, string? publisherId) =>
        name is null || publisherId is null || NeverRemove.Contains(name) ? null
            : Packages.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && p.PublisherId.Equals(publisherId, StringComparison.OrdinalIgnoreCase));

    public static RemovableAppx? PackageById(string id) => Packages.FirstOrDefault(p => p.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    public static RemovableProgram? ProgramById(string id) => Programs.FirstOrDefault(p => p.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>"Microsoft.BingNews_4.1.24002.0_x64__8wekyb3d8bbwe" → ("Microsoft.BingNews", "8wekyb3d8bbwe"). Null for anything else.</summary>
    public static (string Name, string PublisherId)? ParseFullName(string? fullName)
    {
        var parts = (fullName ?? "").Split('_');
        if (parts.Length != 5 || parts[0].Length == 0 || parts[4].Length != 13) return null;
        return (parts[0], parts[4]);
    }

    // ---- reversible settings ----

    /// <summary>The ContentDeliveryManager values (HKCU) that let Windows silently install promoted apps and show suggestions (#3).</summary>
    public static IReadOnlyList<RegistrySetting> ContentDeliverySettings =>
    [
        RegistryAllowlist.SilentInstalledApps, RegistryAllowlist.OemPreInstalledApps, RegistryAllowlist.PreInstalledApps,
        RegistryAllowlist.SoftLanding, RegistryAllowlist.SystemPaneSuggestions,
    ];

    /// <summary>Game DVR / background capture (HKCU, #8).</summary>
    public static IReadOnlyList<RegistrySetting> XboxSettings => [RegistryAllowlist.GameDvrEnabled, RegistryAllowlist.AppCaptureEnabled];

    /// <summary>Xbox services set to Manual (only when they're Automatic now) with the Xbox group (#8).</summary>
    public static readonly IReadOnlyList<string> XboxServices = ["XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc"];

    // ---- what's offered ----

    public sealed record FoundPackage(RemovableAppx App, InstalledAppx Installed);
    public sealed record FoundProgram(RemovableProgram App, IReadOnlyList<UninstallEntry> Entries, IReadOnlyList<string> Tasks)
    {
        public long? SizeBytes => Entries.All(e => e.SizeBytes is null) ? null : Entries.Sum(e => e.SizeBytes ?? 0);
    }

    /// <summary>Allowlisted packages present on this PC (for this account or provisioned). Journal only when the PC is known to have no pen.</summary>
    public static IReadOnlyList<FoundPackage> FoundPackages(MemorySnapshot s)
    {
        if (s.RemovableApps is not { } info) return [];
        var list = new List<FoundPackage>();
        foreach (var app in Packages)
        {
            if (app.Id == "journal" && s.Devices?.HasPenDigitizer != false) continue;
            var hits = info.Packages.Where(p => (p.ForUser || p.Provisioned) && FindPackage(p.Name, p.PublisherId) == app).ToList();
            if (hits.Count == 0) continue;
            list.Add(new(app, new(app.Name, app.PublisherId, hits.Any(h => h.ForUser), hits.Any(h => h.Provisioned),
                hits.All(h => h.SizeBytes is null) ? null : hits.Sum(h => h.SizeBytes ?? 0))));
        }
        return list;
    }

    public static IReadOnlyList<FoundProgram> FoundPrograms(MemorySnapshot s)
    {
        if (s.RemovableApps is not { } info) return [];
        var list = new List<FoundProgram>();
        foreach (var app in Programs)
        {
            // Only entries with a safe uninstaller (the vendor's own under Program Files, or msiexec /x for its own product code).
            var entries = info.Programs.Where(e => CommandFor(app, e) is not null).ToList();
            if (entries.Count == 0) continue;
            var tasks = info.ScheduledTasks.Where(t => app.Tasks.Any(r => r.Matches(t))).ToList();
            list.Add(new(app, entries, tasks));
        }
        return list;
    }

    /// <summary>Narrator add-ons present, offered only when Narrator is known not to be in use (not running, not set to start).</summary>
    public static IReadOnlyList<FoundPackage> FoundNarrator(MemorySnapshot s) =>
        s.RemovableApps is { NarratorInUse: false } && s.App("Narrator") is null
            ? FoundPackages(s).Where(f => f.App.Group == AppGroup.Narrator).ToList() : [];

    public static MemorySuggestion? NarratorCard(MemorySnapshot s)
    {
        var found = FoundNarrator(s);
        if (found.Count == 0) return null;
        var bytes = found.All(x => x.Installed.SizeBytes is null) ? (long?)null : found.Sum(x => x.Installed.SizeBytes ?? 0);
        var names = string.Join(", ", found.Select(x => x.App.Label));
        var reinstall = global::RemotePCDiagnostics.Core.Memory.StoreReinstall.CanReinstallAll(found.Select(x => x.App));
        var getBack = reinstall ? StoreUndoMany : StoreGetBackMany;
        return new MemorySuggestion("remove-narrator-addons", "Remove Narrator's Office add-ons",
            $"Windows includes {MemoryText.Plural(found.Count, "add-on")} that let the Narrator screen reader read Office and Outlook ({names}). Narrator isn't used on this PC. "
            + $"{(bytes is > 0 ? $"Together they take {MemoryText.Size(bytes.Value)}." : "Their size couldn't be measured.")} {getBack}",
            null, SuggestionRisk.Low, SuggestionKind.Automated,
            [$"Removes {names} for every account on this PC. Narrator itself stays and still works.",
             "Turns off the Win+Ctrl+Enter shortcut that starts Narrator by accident (this account). Narrator can still be started from Settings > Accessibility.",
             "You lose: Narrator's extra support for Word, Excel, PowerPoint and Outlook.",
             Frees(bytes),
             reinstall ? "Undo turns the Win+Ctrl+Enter shortcut back on and reinstalls the add-ons from the Microsoft Store." : "Undo turns the Win+Ctrl+Enter shortcut back on."],
            [new(MemoryActionType.RemoveNarratorAddons, "", "Remove Narrator's add-ons",
                $"Remove Narrator's Office add-ons? Narrator stays, but loses its Office support. {getBack} Needs administrator rights.")],
            Category, null, DefaultOn: true, UndoChip: reinstall ? StoreChip : StoreManualChip, SavingText: bytes is > 0 ? $"~{MemoryText.Size(bytes.Value)} disk" : null,
            Undo: reinstall ? UndoSupport.Reinstall : null);
    }

    public static bool OfferContentDelivery(MemorySnapshot s) =>
        s.RemovableApps is { } info && ContentDeliverySettings.Any(r => info.Settings.TryGetValue(r.Target, out var v) && v != 0);

    private static string SizeText(long? bytes) => bytes is > 0 ? $"It takes {MemoryText.Size(bytes.Value)} on this PC." : "Its size couldn't be measured.";
    private static string Frees(long? bytes) => bytes is not > 0 ? "Frees its disk space (size couldn't be measured)." : bytes < 1L << 20 ? "Frees less than 1 MB of disk space." : $"Frees about {MemoryText.Size(bytes.Value)} of disk space.";

    public const string Category = "Remove apps";

    /// <summary>Power Automate is the one consumer app that is ticked by default (a deliberate product choice); the other consumer apps stay opt-in.</summary>
    public const string PowerAutomateId = "power-automate";

    /// <summary>App-removal cards: one per app (ticked or opt-in), one for the Xbox group, and the ContentDeliveryManager settings.</summary>
    public static IEnumerable<MemorySuggestion> Suggestions(MemorySnapshot s)
    {
        foreach (var f in FoundPackages(s).Where(f => f.App.Group is not (AppGroup.Xbox or AppGroup.Narrator)))
        {
            var a = f.App;
            var retired = a.Group == AppGroup.Retired;
            var reinstall = global::RemotePCDiagnostics.Core.Memory.StoreReinstall.CanReinstall(a);
            var getBack = GetBack(a);
            List<string> steps =
            [
                $"Removes {a.Label} ({a.Name}) for every account on this PC and stops Windows adding it for new accounts.",
                $"You lose: {a.Lose}",
                Frees(f.Installed.SizeBytes),
            ];
            if (reinstall) steps.Add("Undo reinstalls it from the Microsoft Store for the account signed in at the time (other accounts can get it from the Store).");
            yield return new MemorySuggestion($"remove-app-{a.Id}", $"Remove {a.Label}",
                $"{a.What} {SizeText(f.Installed.SizeBytes)} {getBack}",
                null, retired ? SuggestionRisk.Low : SuggestionRisk.Medium, SuggestionKind.Automated,
                steps,
                [new(MemoryActionType.RemoveApp, a.Id, $"Remove {a.Label}",
                    $"Remove {a.Label}? {getBack} Needs administrator rights.")],
                // Retired apps: no chip of our own, so the fix list shows the plain "can't be undone" (they may not be in the Store any more).
                Category, null, DefaultOn: retired || a.Id == PowerAutomateId, UndoChip: reinstall ? StoreChip : IsRetiredPermanent(a) ? null : StoreManualChip, SavingText: f.Installed.SizeBytes is > 0 ? $"~{MemoryText.Size(f.Installed.SizeBytes.Value)} disk" : null,
                Undo: reinstall ? UndoSupport.Reinstall : null);
        }

        if (NarratorCard(s) is { } narrator) yield return narrator;

        var xbox = FoundPackages(s).Where(f => f.App.Group == AppGroup.Xbox).ToList();
        if (xbox.Count > 0)
        {
            var bytes = xbox.All(x => x.Installed.SizeBytes is null) ? (long?)null : xbox.Sum(x => x.Installed.SizeBytes ?? 0);
            var names = string.Join(", ", xbox.Select(x => x.App.Label));
            var reinstall = global::RemotePCDiagnostics.Core.Memory.StoreReinstall.CanReinstallAll(xbox.Select(x => x.App));
            var getBack = reinstall ? StoreUndoMany : StoreGetBackMany;
            yield return new MemorySuggestion("remove-xbox", "Remove the Xbox apps and turn off Game DVR",
                $"Windows comes with {MemoryText.Plural(xbox.Count, "Xbox app")} ({names}) and background game recording, which matter only for Xbox and Game Pass games. "
                + $"{(bytes is > 0 ? $"Together they take {MemoryText.Size(bytes.Value)}." : "Their size couldn't be measured.")} {getBack}",
                null, SuggestionRisk.Medium, SuggestionKind.Automated,
                [$"Removes {names} for every account on this PC.",
                 "Turns off Game DVR and background recording (this account), sets the Xbox services to start only when needed, and turns off the Xbox cloud-save task.",
                 "You lose: Game Pass and Xbox games, Win+G Game Bar, game clips, Xbox sign-in and cloud saves in PC games. Ordinary (non-Xbox) games still work.",
                 Frees(bytes),
                 reinstall ? "Undo turns Game DVR, the services and the task back on and reinstalls the apps from the Microsoft Store." : "Undo turns Game DVR, the services and the task back on."],
                [new(MemoryActionType.RemoveXboxApps, "", "Remove the Xbox apps",
                    $"Remove the Xbox apps? Xbox and Game Pass games stop working. {getBack} Needs administrator rights.")],
                Category, null, DefaultOn: false, UndoChip: reinstall ? StoreChip : StoreManualChip, SavingText: bytes is > 0 ? $"~{MemoryText.Size(bytes.Value)} disk" : null,
                Undo: reinstall ? UndoSupport.Reinstall : null);
        }

        foreach (var p in FoundPrograms(s))
        {
            var getBack = VendorGetBack(p.App.ReinstallFrom);
            var tasks = p.Tasks.Count > 0 ? $" Also turns off its scheduled {(p.Tasks.Count == 1 ? "task" : "tasks")} ({string.Join(", ", p.Tasks)}); undo turns {(p.Tasks.Count == 1 ? "it" : "them")} back on if {(p.Tasks.Count == 1 ? "it's" : "they're")} still there." : "";
            yield return new MemorySuggestion($"remove-app-{p.App.Id}", $"Uninstall {p.App.Label}",
                $"{p.App.What} {SizeText(p.SizeBytes)} {getBack}",
                null, SuggestionRisk.Low, SuggestionKind.Automated,
                [$"Runs {p.App.Label}'s own uninstaller silently ({string.Join("; ", p.Entries.Select(e => CommandFor(p.App, e)!.Display))}).{tasks}",
                 $"You lose: {p.App.Lose}",
                 Frees(p.SizeBytes)],

                [new(MemoryActionType.RemoveApp, p.App.Id, $"Uninstall {p.App.Label}",
                    $"Uninstall {p.App.Label}? {getBack} Needs administrator rights.")],
                Category, null, DefaultOn: true, UndoChip: VendorChip(p.App.ReinstallFrom), SavingText: p.SizeBytes is > 0 ? $"~{MemoryText.Size(p.SizeBytes.Value)} disk" : null);
        }

        if (OfferContentDelivery(s))
            yield return new MemorySuggestion("stop-silent-app-installs", "Stop Windows installing promoted apps by itself",
                "Windows quietly downloads promoted Store apps and games, re-adds PC-maker apps, and shows app suggestions in Start and tips. Turning this off keeps removed apps from coming back.",
                null, SuggestionRisk.Low, SuggestionKind.Automated,
                ["Turns off silent app installs, PC-maker and pre-installed app suggestions, tips and Start-menu suggestions (ContentDeliveryManager, this account).",
                 "You lose: suggested apps in Start and Windows tips. Apps you install yourself aren't affected.",
                 "Undo turns them back on."],
                [new(MemoryActionType.StopSilentAppInstalls, "", "Stop promoted app installs")],
                Category, "Applies to apps Windows would add from now on.");
    }

    // ---- uninstall command validation ----

    /// <summary>Program Files folders an uninstaller may live in.</summary>
    public static IReadOnlyList<string> ProgramFilesRoots()
    {
        string?[] roots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetEnvironmentVariable("ProgramW6432"), @"C:\Program Files", @"C:\Program Files (x86)",
        ];
        return roots.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r!.Replace('/', '\\').TrimEnd('\\')).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>The executable path at the start of an uninstall command line ("\"C:\x\unins000.exe\" /SILENT" → C:\x\unins000.exe).</summary>
    public static string? ExePath(string? command)
    {
        var c = (command ?? "").Trim();
        if (c.Length == 0) return null;
        if (c[0] == '"')
        {
            var end = c.IndexOf('"', 1);
            return end > 1 ? c[1..end] : null;
        }
        var exe = c.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? c[..(exe + 4)] : null;
    }

    /// <summary>True when <paramref name="path"/> is a plain absolute path to <paramref name="exeName"/> inside Program Files, under a folder containing <paramref name="folder"/>.</summary>
    public static bool IsVendorUninstaller(string? path, string exeName, string? folder, IReadOnlyList<string>? roots = null)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = path.Replace('/', '\\');
        if (p.Contains("..", StringComparison.Ordinal) || p.StartsWith(@"\\", StringComparison.Ordinal) || p.Contains('%') || p.Contains('"')
            || p.IndexOfAny(Path.GetInvalidPathChars()) >= 0 || p.Length < 4 || p[1] != ':' || p[2] != '\\')
            return false;
        if (!p.Split('\\').Last().Equals(exeName, StringComparison.OrdinalIgnoreCase)) return false;
        if (folder is not null && !p.Contains(folder, StringComparison.OrdinalIgnoreCase)) return false;
        return (roots ?? ProgramFilesRoots()).Any(r => p.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The command that uninstalls one entry, or null when there's no safe one: Windows Installer entries (when allowed) use
    /// msiexec /x with the entry's own product code; others must point at the vendor's uninstaller under Program Files and get our fixed silent arguments.
    /// </summary>
    public static UninstallCommand? CommandFor(RemovableProgram app, UninstallEntry e, IReadOnlyList<string>? roots = null)
    {
        if (!app.Matches(e)) return null;
        if (e.WindowsInstaller)
        {
            if (!app.AllowMsi || !IsProductCode(e.KeyName)) return null;
            var code = "{" + Guid.Parse(e.KeyName).ToString().ToUpperInvariant() + "}";
            return new(true, code, ["/x", code, "/qn", "/norestart"]);
        }
        if (app.UninstallerExe is null) return null;
        var exe = ExePath(e.QuietUninstallString) ?? ExePath(e.UninstallString);
        return IsVendorUninstaller(exe, app.UninstallerExe, app.UninstallerFolder, roots) ? new(false, exe!, app.SilentArgs) : null;
    }

    /// <summary>"{3CE8B8E8-B33B-453C-BB7A-821ED6E18A24}" (braces required, as Windows Installer names its Uninstall keys).</summary>
    public static bool IsProductCode(string? keyName) =>
        keyName is { Length: 38 } k && k[0] == '{' && k[^1] == '}' && Guid.TryParseExact(k, "B", out _);

    /// <summary>A command the Host may run: one this class would build for some allowlisted program (re-checked on the Host side).</summary>
    public static bool IsAllowedCommand(UninstallCommand c, IReadOnlyList<string>? roots = null)
    {
        if (c.Msi) return IsProductCode(c.Path) && c.Arguments.SequenceEqual(new[] { "/x", c.Path, "/qn", "/norestart" }) && Programs.Any(p => p.AllowMsi);
        return Programs.Any(p => p.UninstallerExe is not null && IsVendorUninstaller(c.Path, p.UninstallerExe, p.UninstallerFolder, roots) && c.Arguments.SequenceEqual(p.SilentArgs));
    }

    // ---- Appx removal script ----

    private static bool SafeToken(string s) => s.Length > 0 && s.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-');

    /// <summary>
    /// Removes the packages for all users (<c>Remove-AppxPackage -AllUsers</c>) and their provisioned copies (<c>Remove-AppxProvisionedPackage -Online</c>),
    /// then reads back and prints "LEFT:" + the family names still present (comma separated; empty = all gone). Only allowlisted packages.
    /// </summary>
    public static string RemoveScript(IReadOnlyList<RemovableAppx> apps)
    {
        if (apps.Count == 0 || apps.Any(a => FindPackage(a.Name, a.PublisherId) != a || !SafeToken(a.Name) || !SafeToken(a.PublisherId)))
            throw new InvalidOperationException("Only allowlisted packages can be removed.");
        var list = string.Join(",", apps.Select(a => $"'{a.Name}|{a.PublisherId}'"));
        return "$ErrorActionPreference='Continue';$ProgressPreference='SilentlyContinue';" +
            $"$apps=@({list});" +
            "$prov=@(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue);" +
            "foreach($x in $apps){$n,$p=$x.Split('|');" +
            "Get-AppxPackage -AllUsers -Name $n -ErrorAction SilentlyContinue | Where-Object { $_.PublisherId -eq $p } | ForEach-Object { try { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop } catch { Write-Error $_ } };" +
            "$prov | Where-Object { $_.DisplayName -eq $n -and $_.PublisherId -eq $p } | ForEach-Object { try { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop | Out-Null } catch { Write-Error $_ } }};" +
            "$prov=@(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue);$left=@();" +
            "foreach($x in $apps){$n,$p=$x.Split('|');" +
            "if(@(Get-AppxPackage -AllUsers -Name $n -ErrorAction SilentlyContinue | Where-Object { $_.PublisherId -eq $p }).Count -gt 0 -or @($prov | Where-Object { $_.DisplayName -eq $n -and $_.PublisherId -eq $p }).Count -gt 0){$left+=($n+'_'+$p)}};" +
            "'LEFT:'+($left -join ',')";
    }

    /// <summary>Family names still installed from <see cref="RemoveScript"/>'s output; null when the line is missing (the script didn't finish).</summary>
    public static IReadOnlyList<string>? ParseLeft(string? output)
    {
        var line = (output ?? "").Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("LEFT:", StringComparison.Ordinal));
        return line is null ? null : line[5..].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    // ---- journal labels and undo ----

    /// <param name="reinstall">Journaled as <see cref="ChangeKind.StoreReinstall"/>: undo reinstalls it from the Microsoft Store.</param>
    public static string RemovedLabel(RemovableAppx a, long? bytes, bool reinstall = false) =>
        $"{a.Label} removed ({a.Name}{(bytes is > 0 ? ", " + MemoryText.Size(bytes.Value) : "")}) — "
        + (reinstall ? "undo reinstalls it from the Microsoft Store for the signed-in account; its settings and data aren't restored"
            : IsRetiredPermanent(a) ? RetiredLabel : "reinstall from the Microsoft Store to get it back");

    public static string UninstalledLabel(RemovableProgram p, UninstallEntry e) =>
        $"{e.DisplayName}{(e.Version is { Length: > 0 } v ? " " + v : "")} uninstalled{(e.SizeBytes is > 0 ? $" ({MemoryText.Size(e.SizeBytes.Value)})" : "")} — reinstall from {p.ReinstallFrom} to get it back";

    /// <summary>What one click changed that undo can put back: registry values, service start types, scheduled tasks and (when every
    /// package the click removed has a Store id) the removed packages' family names, which undo reinstalls from the Microsoft Store.</summary>
    public sealed record Undo(IReadOnlyList<RegistryUndo.Item> Registry, IReadOnlyList<RegistryUndo.Item> Services, IReadOnlyList<string> Tasks,
        IReadOnlyList<string>? Reinstall = null)
    {
        public bool IsEmpty => Registry.Count + Services.Count + Tasks.Count + (Reinstall?.Count ?? 0) == 0;
        public string Encode() => JsonSerializer.Serialize(this);

        public static Undo Decode(string? json)
        {
            try { return (string.IsNullOrEmpty(json) ? null : JsonSerializer.Deserialize<Undo>(json)) ?? new([], [], []); }
            catch (JsonException) { return new([], [], []); }
        }
    }

    public static string TaskLabel(string path) => $"Scheduled task {path} turned off (was on)";
}
