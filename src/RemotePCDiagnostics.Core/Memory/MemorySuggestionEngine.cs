using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>Processes the app never offers to close (Windows core, security, shell, this app and its web view).</summary>
public static class ProtectedProcesses
{
    public static readonly IReadOnlySet<string> Names = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "winlogon", "lsass", "LsaIso", "services", "svchost",
        "MsMpEng", "MpDefenderCoreService", "NisSrv", "SecurityHealthService", "SecurityHealthSystray", "smartscreen",
        "explorer", "dwm", "fontdrvhost", "sihost", "ctfmon", "conhost", "RuntimeBroker", "StartMenuExperienceHost",
        "ShellExperienceHost", "SearchHost", "SearchIndexer", "TextInputHost", "audiodg", "spoolsv", "Memory Compression",
        "WUDFHost", "dllhost", "taskhostw", "osqueryd", "osqueryi", "msedgewebview2", "ApplicationFrameHost", "SystemSettings",
        "LockApp", "WmiPrvSE", "unsecapp", "dasHost", "MemTestHelper",
    };

    public static bool IsProtected(string processName) =>
        Names.Contains(processName) || ServiceProtection.IsProtected(processName) || ServiceProtection.IsSelfComponent(processName);
}

/// <summary>The only external commands an automated suggestion may run.</summary>
public static class MemoryCommandAllowlist
{
    public sealed record Command(string FileName, IReadOnlyList<string> Arguments);
    public static readonly Command BuildServerShutdown = new("dotnet", ["build-server", "shutdown"]);

    /// <summary>#14: only %SystemRoot%\System32\wsl.exe --shutdown (never "wsl" from PATH, never other arguments).</summary>
    public static readonly Command WslShutdown = new(WslPath(), ["--shutdown"]);

    public static string WslPath()
    {
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(win)) win = @"C:\Windows";
        return win.Replace('/', '\\').TrimEnd('\\') + @"\System32\wsl.exe";
    }

    public static bool IsWslShutdown(string? fileName, IReadOnlyList<string> args) =>
        string.Equals(fileName, WslShutdown.FileName, StringComparison.OrdinalIgnoreCase) && args.Count == 1 && args[0] == "--shutdown";

    public static bool IsAllowed(string fileName, IReadOnlyList<string> args) =>
        (IsTrustedDotnet(fileName ?? "") && args.Count == 2 && args[0] == "build-server" && args[1] == "shutdown") || IsWslShutdown(fileName, args);

    /// <summary>"dotnet"/"dotnet.exe" (resolved from PATH), or exactly dotnet.exe in an SDK folder under Program Files.
    /// Any other path (relative, UNC, another folder, "..") is refused.</summary>
    private static bool IsTrustedDotnet(string fileName)
    {
        if (fileName.Equals("dotnet", StringComparison.OrdinalIgnoreCase) || fileName.Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase))
            return true;
        var f = fileName.Replace('/', '\\');
        if (f.Contains("..", StringComparison.Ordinal) || f.StartsWith(@"\\", StringComparison.Ordinal)) return false;
        return TrustedDotnetPaths().Contains(f, StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> TrustedDotnetPaths()
    {
        string?[] roots =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetEnvironmentVariable("ProgramW6432"), @"C:\Program Files", @"C:\Program Files (x86)",
        ];
        return roots.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r!.Replace('/', '\\').TrimEnd('\\') + @"\dotnet\dotnet.exe").Distinct(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Settings pages an "Open settings" button may launch.</summary>
    public static bool IsAllowedSettingsUri(string uri) =>
        uri.StartsWith("ms-settings:", StringComparison.OrdinalIgnoreCase) || uri.StartsWith("windowsdefender:", StringComparison.OrdinalIgnoreCase) ||
        BrowserPrefs.SettingsUrl.Values.Contains(uri, StringComparer.OrdinalIgnoreCase);
}

/// <summary>A service that's often safe to stop on a laptop, with what it does and what you lose.</summary>
/// <param name="DefaultOn">False = opt-in: the service workflow lists the fix unticked (the tech ticks it by hand).</param>
public sealed record ServiceCandidate(string What, string Lose, bool OfferDisable = false, Func<MemorySnapshot, bool>? NeededWhen = null, bool DefaultOn = true);

/// <summary>Pure rules: snapshot in, suggestions out (sorted by estimated saving).</summary>
public static class MemorySuggestionEngine
{
    public const long Mb = 1L << 20, Gb = 1L << 30;
    public const long CloseAppMin = 300 * Mb;
    public const int MaxCloseSuggestions = 6;
    public const long VsRestartBytes = 1536 * Mb;
    public const long VsExtensionMinBytes = 100 * Mb;
    public static readonly TimeSpan VsLongRun = TimeSpan.FromHours(8);
    public static readonly TimeSpan FastStartupUptime = TimeSpan.FromHours(4);
    public static readonly TimeSpan LongUptime = TimeSpan.FromDays(3);

    /// <summary>Electron/web-wrapper chat and media apps; each runs its own copy of Chromium.</summary>
    public static readonly IReadOnlySet<string> ElectronApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "ChatGPT", "Grok", "Antigravity", "slack", "ms-teams", "msteams", "Teams", "Discord", "Spotify", "Code", "Notion", "WhatsApp", "Codex", "MicrosoftOfficeHub" };

    /// <summary>
    /// Vendor tray helpers that start at sign-in but aren't needed for the device to work (graphics settings/overlay, printer
    /// status pop-ups, scan-button and vendor update helpers). Offered for "don't start with Windows" even when small or not running.
    /// Not Electron: their suggestions never talk about a built-in browser.
    /// Adobe: AdobeGCInvoker-1.0 (AGCInvokerUtility.exe, licensing check), Acrobat Assistant 8.0 (acrotray.exe, Acrobat's PDF-printer
    /// tray helper) and AdobeAAMUpdater-1.0 (UpdaterStartupUtility.exe, the old Creative Cloud updater).
    /// </summary>
    public static readonly IReadOnlySet<string> StartupTrayHelpers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "RadeonSoftware", "BrStMonW", "BrCcBoot", "LenovoVantage", "AGCInvokerUtility", "acrotray", "UpdaterStartupUtility" };

    /// <summary>
    /// Microsoft Teams startup entries: new Teams (ms-teams, packaged task MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask), Teams (free)
    /// (msteams, MicrosoftTeams_8wekyb3d8bbwe\TeamsStartupTask) and classic Teams (Teams, Run value com.squirrel.Teams.Teams).
    /// Offered, but opt-in in the service workflow: people who rely on Teams chats and calls would miss them until they open Teams.
    /// </summary>
    public static readonly IReadOnlySet<string> TeamsApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "ms-teams", "msteams", "Teams" };

    /// <summary>Typical sign-in memory of Teams that this saves, for the card text.</summary>
    public const string TeamsStartupSaving = "about 450–850 MB";

    /// <summary>Startup apps offered regardless of their memory use.</summary>
    public static bool AlwaysOfferStartup(string exeName) => ElectronApps.Contains(exeName) || StartupTrayHelpers.Contains(exeName);

    public static readonly IReadOnlyList<string> BuildServerProcesses = ["VBCSCompiler", "MSBuild", "MSBuildTaskHost"];

    private static bool Running(MemorySnapshot s, params string[] names) => names.Any(n => s.App(n) is not null);

    /// <summary>Windows Search is only worth setting to Manual on a small PC whose memory is nearly full.</summary>
    public const long WSearchMaxRamBytes = 8 * Gb;
    public const int WSearchMinUsedPercent = 85;

    /// <summary>
    /// The indexer uses only tens of MB once the first index is built, while Manual slows Start-menu and File Explorer search and
    /// makes classic Outlook's instant search slow or incomplete (it uses the index). So: needed unless RAM ≤ 8 GB, ≥ 85% in use, classic
    /// Outlook known not to be installed (unknown counts as installed) and not running.
    /// </summary>
    public static bool WSearchNeeded(MemorySnapshot s) =>
        !(s.Memory.TotalBytes is > 0 and <= WSearchMaxRamBytes && s.Memory.UsedPercent >= WSearchMinUsedPercent
          && s.Devices?.HasClassicOutlook == false && !Running(s, "OUTLOOK"));

    public static readonly IReadOnlyDictionary<string, ServiceCandidate> ServiceCandidates = new Dictionary<string, ServiceCandidate>(StringComparer.OrdinalIgnoreCase)
    {
        ["Spooler"] = new("Print Spooler handles printing.", "You can't print until it's started again.", NeededWhen: s => s.Devices?.HasPrinter != false),
        ["Fax"] = new("Fax sends and receives faxes.", "Faxing from this PC.", OfferDisable: true),
        ["WSearch"] = new("Windows Search keeps an index of your files so Start-menu and File Explorer searches are fast. Offered only because this PC has 8 GB of memory or less and it's nearly full; once its index is built it usually uses only tens of MB, so the saving is small.",
            "Start-menu and File Explorer searches get slower, and if classic Outlook is used on this PC later, its search becomes slow or incomplete (Outlook warns about it). Undo sets it back to its previous start type.",
            NeededWhen: WSearchNeeded, DefaultOn: false),
        ["SysMain"] = new("SysMain (Superfetch) preloads apps you use often into memory.", "Apps may open a little slower right after startup."),
        ["DiagTrack"] = new("Connected User Experiences and Telemetry sends usage data to Microsoft.", "Nothing you'll notice.", OfferDisable: true),
        ["XblAuthManager"] = new("Xbox Live sign-in for games.", "Xbox sign-in in games until it starts again.", OfferDisable: true, NeededWhen: s => Running(s, "XboxPcApp", "GamingServices")),
        ["XblGameSave"] = new("Xbox Live cloud saves for games.", "Cloud game saves until it starts again.", OfferDisable: true, NeededWhen: s => Running(s, "XboxPcApp", "GamingServices")),
        ["XboxNetApiSvc"] = new("Xbox Live networking for games.", "Xbox multiplayer networking.", OfferDisable: true, NeededWhen: s => Running(s, "XboxPcApp", "GamingServices")),
        ["XboxGipSvc"] = new("Xbox accessory (controller) management.", "Xbox controller accessory updates.", OfferDisable: true, NeededWhen: s => Running(s, "XboxPcApp", "GamingServices")),
        ["bthserv"] = new("Bluetooth Support finds and connects Bluetooth devices.", "Bluetooth devices can't connect.", NeededWhen: s => s.Devices?.HasBluetoothDevices != false),
        ["RemoteRegistry"] = new("Remote Registry lets other computers change this PC's settings.", "Nothing for most people (it's a security risk when on).", OfferDisable: true),
        ["WbioSrvc"] = new("Windows Biometric runs fingerprint and face sign-in.", "Fingerprint / face sign-in.", NeededWhen: s => s.Devices?.HasFingerprintReader != false),
        ["lfsvc"] = new("Geolocation tells apps where the PC is.", "Location for Maps, weather and Find my device."),
        ["RetailDemo"] = new("Retail Demo is for store display PCs.", "Nothing.", OfferDisable: true),
        ["WpcMonSvc"] = new("Parental Controls enforces family safety limits.", "Family Safety limits on this PC.", NeededWhen: _ => false),
        ["PhoneSvc"] = new("Phone Service manages telephony state for calling apps.", "Phone calls through Phone Link."),
        ["MapsBroker"] = new("Downloaded Maps Manager updates offline maps.", "Offline map updates.", OfferDisable: true),
        ["TeamViewer"] = new("TeamViewer waits for incoming remote-control connections.", "Others can't connect to this PC with TeamViewer until it's started."),
        ["AnyDesk"] = new("AnyDesk waits for incoming remote-control connections.", "Others can't connect to this PC with AnyDesk until it's started."),
        ["vmms"] = new("Hyper-V Virtual Machine Management.", "Hyper-V virtual machines.", NeededWhen: s => Running(s, "vmwp", "vmmem", "vmmemWSL")),
        ["vmcompute"] = new("Hyper-V Host Compute (containers, WSL 2, Docker).", "WSL 2, Docker and Windows containers.", NeededWhen: s => Running(s, "vmwp", "vmmem", "vmmemWSL", "wsl", "wslservice", "Docker Desktop")),
        ["WSLService"] = new("Windows Subsystem for Linux.", "Linux (WSL) until it starts again.", NeededWhen: s => Running(s, "wsl", "vmmemWSL", "Docker Desktop")),
        ["LxssManager"] = new("Windows Subsystem for Linux (older WSL).", "Linux (WSL) until it starts again.", NeededWhen: s => Running(s, "wsl", "vmmemWSL", "Docker Desktop")),
        ["com.docker.service"] = new("Docker Desktop's background service.", "Docker containers.", NeededWhen: s => Running(s, "Docker Desktop", "com.docker.backend")),
        ["UDCService"] = new("Lenovo Universal Device Client (NotifyMe) sends device telemetry and promotional notifications.", "Lenovo promotional notifications and telemetry.", OfferDisable: true),
        // #14: offered through AiVmServices (Manual only, when a signed-in user may start it so Claude can start it itself).
        [AiVmServices.ClaudeService] = AiVmServices.Candidate(AiVmServices.ClaudeService),
        ["BrYNSvc"] = new("Brother status monitor background service.", "Automatic printer ink/toner pop-up alerts (printing still works normally)."),
        ["USBAppControl"] = new("Brother iPrint&Scan USB monitor.", "Pushing the physical scan button on a USB-connected Brother scanner."),
        ["WorkflowAppControl"] = new("Brother iPrint&Scan workflow monitor.", "Brother iPrint&Scan background workflow triggers."),
        ["BrLogRx"] = new("Brother diagnostic log receiver telemetry service.", "Brother background diagnostic log collection.", OfferDisable: true),
        ["SQLWriter"] = new("SQL Server VSS Writer (installed with Visual Studio LocalDB).", "Volume shadow copy backups of live SQL Server databases."),
        // Adobe: service names, not exe names (Acrobat's updater runs armsvc.exe but the service is AdobeARMservice).
        ["AdobeARMservice"] = new("Adobe Acrobat Update Service checks for Acrobat and Reader updates in the background.",
            "Background update checks only: Acrobat and Reader still check for and install updates when they're opened."),
        ["AGSService"] = new("Adobe Genuine Software Integrity Service checks in the background that installed Adobe apps are licensed.",
            "Nothing you'll notice: the licensing check happens when an Adobe app starts instead."),
        ["AGMService"] = new("Adobe Genuine Monitor Service watches installed Adobe apps for licensing in the background.",
            "Nothing you'll notice: the licensing check happens when an Adobe app starts instead."),
        ["AdobeUpdateService"] = new("Adobe Update Service installs Creative Cloud app updates in the background.",
            "Automatic Creative Cloud app updates until the Creative Cloud app is opened (it still updates apps from there)."),
    };

    /// <summary>Vendor updater/telemetry helper services matched by name fragment.</summary>
    public static readonly IReadOnlyList<(string Fragment, string What)> VendorServiceFragments =
    [
        ("LenovoVantage", "a Lenovo Vantage helper service"),
        ("ImController", "a Lenovo Vantage system interface helper"),
        ("CodexSandboxService", "the OpenAI Codex background sandbox VM service"),
        ("SoftwareUpdateNotification", "Brother's background software update checker"),
        ("gupdate", "Google's updater"),
        ("GoogleUpdater", "Google's updater"),
        ("edgeupdate", "Microsoft Edge's updater"),
        ("VSInstallerElevationService", "the Visual Studio installer helper"),
    ];

    /// <summary>Hardware hotkey, power, or thermal services that should never be flagged by vendor name matching.</summary>
    public static readonly IReadOnlyList<string> HardwareHelperFragments =
    [
        "FnAndFunctionKeys", "function keys", "Hotkey", "PMService", "LITSSvc", "PowerMgr", "Thermal",
    ];

    public static ServiceCandidate? CandidateFor(ServiceInfo s)
    {
        if (ServiceProtection.IsProtected(s.Name) || ServiceProtection.IsSelfComponent(s.Name)) return null;
        if (HardwareHelperFragments.Any(f => s.Name.Contains(f, StringComparison.OrdinalIgnoreCase) || s.DisplayName.Contains(f, StringComparison.OrdinalIgnoreCase)))
            return null;
        if (AiVmServices.Is(s.Name)) return AiVmServices.Candidate(s.Name);
        if (ServiceCandidates.TryGetValue(s.Name, out var c)) return c;
        if (IsVisualStudioCollector(s.Name))
            return new("Visual Studio's diagnostics collector supports profiling and diagnostic data collection.",
                "It will not start automatically at Windows startup. Manual permits on-demand starts; diagnostic tools may require you to start it. Its current running state is unchanged.");
        if (s.Name.StartsWith("TeamViewer", StringComparison.OrdinalIgnoreCase)) return ServiceCandidates["TeamViewer"];
        foreach (var (frag, what) in VendorServiceFragments)
            if (s.Name.Contains(frag, StringComparison.OrdinalIgnoreCase))
            {
                var needed = s.Label.Contains("Critical", StringComparison.OrdinalIgnoreCase)
                    ? " Despite \"Critical\" in its name, Windows and your hardware do not need it — only that vendor's app uses it, and it starts on demand when you open the app."
                    : " Windows does not need it running in the background; it starts on demand when the app is opened.";
                return new($"\"{s.Label}\" is {what}.{needed} It checks for updates or sends usage data in the background.", "Automatic updates for that app until it's started again (the app can still update itself when opened).");
            }
        return null;
    }

    public static bool IsVisualStudioCollector(string name) =>
        name.StartsWith("VSStandardCollectorService", StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<MemorySuggestion> Build(MemorySnapshot s)
    {
        var list = new List<MemorySuggestion>();
        var startup = s.Startup ?? [];

        // Browsers: memory saver / sleeping tabs.
        foreach (var b in s.Browsers ?? [])
        {
            if (!b.Installed || b.MemorySaverOn != false) continue;
            var usage = s.App(BrowserPrefs.ProcessName(b.Kind));
            var name = BrowserPrefs.Label(b.Kind);
            var feature = BrowserPrefs.FeatureName(b.Kind);
            var why = usage is null ? $"{feature} is off in {name}." : $"{name} is using {MemoryText.Size(usage.MemoryBytes)} across {MemoryText.Plural(usage.Instances, "process", "processes")} and {feature} is off.";
            var actions = new List<MemoryAction> { new(MemoryActionType.OpenSettings, BrowserPrefs.SettingsUrl[b.Kind], $"Open {name} settings") };
            if (!b.Running && b.CanWrite) actions.Insert(0, new(MemoryActionType.EnableBrowserMemorySaver, b.Kind.ToString(), $"Turn on {feature}"));
            list.Add(new($"browser-{b.Kind}".ToLowerInvariant(), $"Turn on {feature} in {name}", why + " It puts tabs you aren't using to sleep and frees their memory.",
                usage is null ? null : usage.MemoryBytes / 4, SuggestionRisk.Low, actions.Count > 1 ? SuggestionKind.Automated : SuggestionKind.Guided,
                [$"Open {BrowserPrefs.SettingsUrl[b.Kind]} in {name}", $"Turn on {feature}"], actions, "Browsers",
                b.Running ? $"{name} is open, so it can only be changed from inside {name}." : null));
        }

        // Visual Studio.
        var devenv = s.App("devenv");
        if (devenv is not null && (devenv.MemoryBytes >= VsRestartBytes || devenv.RunningFor >= VsLongRun))
        {
            var ranFor = devenv.RunningFor is { } rf ? $" and has been open for {(int)rf.TotalHours} hours" : "";
            list.Add(new("vs-restart", "Restart Visual Studio", $"Visual Studio is using {MemoryText.Size(devenv.MemoryBytes)}{ranFor}. It tends to grow over a long session; a restart gives memory back.",
                Math.Max(0, devenv.MemoryBytes - 600 * Mb), SuggestionRisk.Low, SuggestionKind.Guided,
                ["Save your work (File > Save All)", "Close Visual Studio and open your solution again"], [], "Visual Studio"));
        }
        if (s.VisualStudio is { } vs && devenv is not null)
        {
            if (vs.LiveShareInstalled)
                list.Add(new("vs-liveshare", "Turn off Live Share in Visual Studio", "Live Share is installed and loads its own background services when Visual Studio starts. If you don't co-edit with others, you don't need it.",
                    null, SuggestionRisk.Low, SuggestionKind.Guided,
                    ["In Visual Studio, open Extensions > Manage Extensions > Installed", "Find \"Live Share\" and click Disable", "Restart Visual Studio"], [], "Visual Studio"));
            var uniqueExts = vs.Extensions
                .GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(x => x.SizeBytes).First())
                .ToList();
            var heavy = uniqueExts.Where(e => e.SizeBytes >= VsExtensionMinBytes).OrderByDescending(e => e.SizeBytes).Take(5).ToList();
            if (heavy.Count > 0)
                list.Add(new("vs-extensions", "Turn off Visual Studio extensions you don't use",
                    $"{MemoryText.Plural(uniqueExts.Count, "extension")} installed. Largest on disk: {string.Join(", ", heavy.Select(e => $"{e.Name} ({MemoryText.Size(e.SizeBytes)})"))}. Review large extensions you don't use; installed size does not measure their memory use.",
                    null, SuggestionRisk.Low, SuggestionKind.Guided,
                    ["In Visual Studio, open Extensions > Manage Extensions > Installed", "Click Disable on extensions you don't use (Disable is reversible; avoid Uninstall)", "Restart Visual Studio"], [], "Visual Studio"));
        }

        // Build servers.
        var builds = BuildServerProcesses.Select(n => s.App(n)).OfType<AppUsage>().ToList();
        if (builds.Count > 0)
        {
            var bytes = builds.Sum(b => b.MemoryBytes);
            list.Add(new("build-servers", "Shut down idle .NET build servers",
                $"{string.Join(", ", builds.Select(b => $"{b.Name} ({MemoryText.Size(b.MemoryBytes)})"))} stay in memory after a build to make the next one faster.",
                bytes, SuggestionRisk.Low, SuggestionKind.Automated, ["Runs \"dotnet build-server shutdown\". They start again on your next build."],
                [new(MemoryActionType.ShutdownBuildServers, "dotnet", "Shut down build servers")], "Developer tools", "Don't use this while a build is running."));
        }

        // Close apps (user apps with a window; never protected, services or this app).
        var closable = s.Apps.Where(a => a.HasWindow && !a.IsService && a.MemoryBytes >= CloseAppMin && !ProtectedProcesses.IsProtected(a.Name))
            .OrderByDescending(a => a.MemoryBytes).Take(MaxCloseSuggestions);
        foreach (var a in closable)
        {
            var electron = ElectronApps.Contains(a.Name);
            var why = $"{a.Label} is using {MemoryText.Size(a.MemoryBytes)}" + (a.Instances > 1 ? $" across {MemoryText.Plural(a.Instances, "process", "processes")}." : ".");
            if (electron) why += " It runs its own copy of a web browser, so it uses a lot of memory even when idle.";
            var steps = new List<string> { "Save your work in it first", "Close it from here or from its window" };
            if (electron) steps.Add("In its settings, turn off \"Open at login\" / \"Run at startup\" and \"Hardware acceleration\" if you don't need them");
            list.Add(new($"close-{a.Name}".ToLowerInvariant(), $"Close {a.Label}", why, a.MemoryBytes, SuggestionRisk.Medium, SuggestionKind.Automated, steps,
                [new(MemoryActionType.CloseApp, a.Name, $"Close {a.Label}", $"Close {a.Label}? Unsaved work in it may be lost.")], "Close apps"));
        }

        // Startup apps (Win32 Run keys + Packaged UWP StartupTasks).
        foreach (var e in startup.Where(e => e.Enabled))
        {
            var app = s.App(e.ExeName);
            if (!AlwaysOfferStartup(e.ExeName) && (app is null || app.MemoryBytes < 150 * Mb)) continue;
            var label = MemoryText.FriendlyAppName(e.ExeName);
            var helper = StartupTrayHelpers.Contains(e.ExeName) ? $" It's a vendor helper that sits in the tray; the device works without it, and opening {label} still works." : "";
            var teams = TeamsApps.Contains(e.ExeName);
            if (teams)
                helper = $" For people who only open Teams to join meetings, not starting it at sign-in saves {TeamsStartupSaving} of memory."
                    + " You won't get Teams chat or call notifications until you open Teams. Undo turns it back on.";
            list.Add(new($"startup-{e.Name}".ToLowerInvariant(), $"Stop {label} from starting with Windows",
                (app is null ? $"{label} is set to start every time you sign in." : $"{label} starts every time you sign in and is using {MemoryText.Size(app.MemoryBytes)} right now.") + helper,
                app?.MemoryBytes, SuggestionRisk.Low, SuggestionKind.Automated, ["Same as Task Manager > Startup apps > Disable. Undo turns it back on."],
                [new(MemoryActionType.DisableStartup, e.Name, "Don't start with Windows")], "Startup apps", "Takes effect the next time you sign in.", DefaultOn: !teams));
        }

        // Fast Startup / uptime.
        if (s.Uptime is { } up && ((s.FastStartup == true && up >= FastStartupUptime) || up >= LongUptime))
        {
            var hours = (int)up.TotalHours;
            var fs = s.FastStartup == true
                ? " Fast Startup is on, so \"Shut down\" doesn't fully clear memory. \"Restart\" does."
                : "";
            var restartActions = new List<MemoryAction>
            {
                new(MemoryActionType.RestartPc, "", "Restart in 60 seconds",
                    "Restart this PC in 60 seconds? Windows warns the person at the PC first; unsaved work in open apps may be lost. This app reopens after sign-in."),
            };
            if (s.FastStartup == true)
                restartActions.Add(new(MemoryActionType.DisableFastStartup, "", "Turn off Fast Startup",
                    "Turn off Fast Startup? Every Shut down will then fully reset Windows (startup takes a few seconds longer). Needs administrator rights."));
            list.Add(new("restart", "Restart the PC (Restart, not Shut down)", $"Windows has been running for {(hours >= 48 ? $"{hours / 24} days" : $"{hours} hours")}.{fs} A restart clears leaked memory and leftover background processes.",
                null, SuggestionRisk.Medium, SuggestionKind.Automated,
                ["Save work in open apps first", "The restart is scheduled with a 60-second warning and can be cancelled from the Remediation actions"], restartActions, "Windows",
                s.FastStartup == true ? "Turning off Fast Startup is a PC-wide power setting; Restart alone already clears memory." : null));
        }

        // Defender scanning code and build folders: one click when we found the folders and can read Defender's exclusions.
        if (s.Defender is { HasWork: true } dfn)
        {
            var shown = dfn.MissingFolders.Take(6).ToList();
            var more = dfn.MissingFolders.Count - shown.Count;
            var hog = s.App("MsMpEng") is { } msmp && msmp.MemoryBytes >= 250 * Mb ? $" Defender is using {MemoryText.Size(msmp.MemoryBytes)} right now." : "";
            var steps = new List<string>();
            if (dfn.MissingFolders.Count > 0) steps.Add("Folders: " + string.Join("; ", shown) + (more > 0 ? $" (+{more} more)" : ""));
            if (dfn.MissingProcesses.Count > 0) steps.Add("Build tools: " + string.Join(", ", dfn.MissingProcesses.Select(Path.GetFileName).Distinct(StringComparer.OrdinalIgnoreCase)));
            steps.Add("Only code folders found from Visual Studio, VS Code, Rider and Windows Search, plus the NuGet package cache. Never Downloads, Desktop, Documents or a whole drive.");
            steps.Add("Undo removes exactly these exclusions.");
            list.Add(new("defender-exclusions", "Stop Defender rescanning code and build folders",
                $"Microsoft Defender scans every file a build writes. Excluding {MemoryText.Plural(dfn.ProjectFolders.Count, "code folder", "code folders")}, the NuGet package cache and the build tools makes builds noticeably faster.{hog}",
                null, SuggestionRisk.Medium, SuggestionKind.Automated, steps,
                [new(MemoryActionType.AddDefenderExclusions, "", "Add exclusions",
                    "Add these Defender exclusions? Files in these folders and files opened by these build tools won't be scanned for malware. Needs administrator rights.")],
                "Windows", "Applies right away."));
        }
        else if (s.Defender is null && s.App("MsMpEng") is { } def && def.MemoryBytes >= 250 * Mb && Running(s, "devenv", "MSBuild", "VBCSCompiler", "Code"))
            list.Add(new("defender-exclusions", "Exclude your code and build folders from Defender scanning",
                $"Microsoft Defender is using {MemoryText.Size(def.MemoryBytes)} while developer tools are running. Builds create lots of files it rescans.",
                null, SuggestionRisk.Medium, SuggestionKind.Guided,
                ["Windows Security > Virus & threat protection > Manage settings", "Exclusions > Add or remove exclusions > Add an exclusion > Folder", "Add only your own source/build folders (e.g. C:\\src), never a whole drive"],
                [new(MemoryActionType.OpenSettings, "windowsdefender://threatsettings", "Open Windows Security")], "Windows"));

        // Info: memory pressure.
        var m = s.Memory;
        if (m.TotalBytes > 0 && m.UsedPercent >= 85)
        {
            var topApps = s.Apps.Where(a => a.HasWindow && !a.IsService && a.MemoryBytes > 0 && !ProtectedProcesses.IsProtected(a.Name))
                .OrderByDescending(a => a.MemoryBytes).ThenBy(a => a.Label, StringComparer.OrdinalIgnoreCase).Take(5).ToList();
            bool StartsWithWindows(AppUsage app) => startup.Any(e => e.Enabled && e.ExeName.Equals(app.Name, StringComparison.OrdinalIgnoreCase));
            var appText = topApps.Count > 0
                ? " Largest open apps by current RAM use: " + string.Join("; ", topApps.Select(a => $"{a.Label}: {MemoryText.Size(a.MemoryBytes)}" + (StartsWithWindows(a) ? " (starts with Windows)" : ""))) + ". Save your work, then close apps you aren't using."
                    + (topApps.Any(StartsWithWindows) ? " Apps marked 'starts with Windows' may return at the next sign-in unless you disable their startup entry. Closing an app does not change its startup setting." : "")
                    + " Startup flags reflect detected enabled entries; other app restart mechanisms may not be detected."
                : " Save your work and use Task Manager to review memory use; no open user apps could be identified in this scan.";
            list.Add(new("low-ram", "Memory is almost full", $"{m.UsedPercent}% of {MemoryText.Size(m.TotalBytes)} is in use; only {MemoryText.Size(m.AvailableBytes)} is available. Memory pressure can cause Windows to use the slower page file."
                    + appText
                    + (s.Slots is { Total: > 0 } slots ? " " + slots.Text : ""),
                null, SuggestionRisk.Low, SuggestionKind.Info, [], [], "Windows"));
        }
        if (m.CommitBytes is { } cb && m.CommitLimitBytes is > 0 and var cl && cb >= cl * 0.8)
        {
            // A fixed-size page file can be switched to Windows-managed (grows as needed) with one click; already managed = info only.
            var fixedSize = s.AutoPageFile == false;
            list.Add(new("commit", "Page file is under pressure", $"Committed memory is {MemoryText.Size(cb)} of a {MemoryText.Size(cl)} limit ({(int)(100.0 * cb / cl)}%). Apps may fail to start if it fills up."
                    + (fixedSize ? " The page file has a fixed size on this PC." : ""),
                null, SuggestionRisk.Low, fixedSize ? SuggestionKind.Automated : SuggestionKind.Info,
                fixedSize ? ["Closing apps is the fastest fix", "Letting Windows manage the page file lets it grow when needed (takes effect after a restart)"] : ["Closing apps is the fastest fix"],
                fixedSize ? [new(MemoryActionType.AutoManagePageFile, "", "Let Windows manage the page file",
                    "Let Windows manage the page file size? Takes effect after the next restart. The current custom size isn't kept. Needs administrator rights.")] : [],
                "Windows"));
        }
        if (s.App("Memory Compression") is { } mc && mc.MemoryBytes >= 500 * Mb)
            list.Add(new("compression", "Windows is compressing memory", $"Memory compression holds {MemoryText.Size(mc.MemoryBytes)}. That's Windows squeezing memory because RAM is tight; it's normal, but a sign more RAM or fewer open apps would help.",
                null, SuggestionRisk.Low, SuggestionKind.Info, [], [], "Windows"));

        // Low priority Windows extras.
        if (m.TotalBytes > 0 && m.UsedPercent >= 70 && s.TransparencyOn != false)
            list.Add(new("transparency", "Turn off transparency effects", "Transparency and animation effects use a little extra graphics memory. A small saving, but free.",
                null, SuggestionRisk.Low, SuggestionKind.Automated, ["Same as Settings > Personalization > Colors > Transparency effects: Off (this account only). Undo turns it back on."],
                [new(MemoryActionType.DisableTransparency, "", "Turn off transparency"),
                 new(MemoryActionType.OpenSettings, "ms-settings:personalization-colors", "Open Colors settings")], "Windows extras"));
        // Hibernation file: Fast Startup needs only about half of a full hiberfil.sys.
        if (s.Hibernate is { OfferReduce: true } hib)
        {
            var laptop = hib.HasBattery != false;
            var steps = new List<string>
            {
                "Runs \"powercfg /h /type reduced\": hiberfil.sys keeps only what Fast Startup needs (about 20% of RAM instead of about 40%).",
                "Fast Startup keeps working. Hibernate (and hybrid sleep) is no longer available.",
            };
            if (laptop) steps.Add("On a laptop: when the battery runs critically low Windows shuts down instead of hibernating, so unsaved work is lost, and it won't switch from sleep to hibernate to save battery.");
            steps.Add("Undo makes it full size again (powercfg /h /type full).");
            list.Add(new("hiberfile-reduced", "Shrink the hibernation file (hiberfil.sys)",
                $"Windows keeps {MemoryText.Size(hib.FileBytes!.Value)} on the system drive for hibernation. Fast Startup only needs about half of that, so about {MemoryText.Size(hib.EstimatedSavingBytes!.Value)} of disk space can be freed.",
                null, laptop ? SuggestionRisk.Medium : SuggestionRisk.Low, SuggestionKind.Automated, steps,
                [new(MemoryActionType.ReduceHibernateFile, "", "Shrink hiberfil.sys",
                    "Shrink hiberfil.sys? Hibernate won't be available until you undo this. Needs administrator rights.")],
                "Storage", "Frees the space right away.", hib.DefaultOn));
        }
        if (WindowsFeeds.OfferWidgets(s))
        {
            var running = WindowsFeeds.RunningWidgets(s);
            var bytes = running.Sum(x => x.MemoryBytes);
            var now = running.Count > 0 ? $" Right now its processes use {MemoryText.Size(bytes)}, plus the hidden web views they run." : "";
            list.Add(new("widgets", "Turn off Widgets",
                $"The Widgets board on the taskbar (weather, news and the Microsoft Start feed) keeps running in the background even if it's never opened.{now}",
                running.Count > 0 ? bytes : null, SuggestionRisk.Low, SuggestionKind.Automated,
                ["Turns off the Widgets board on the taskbar for everyone on this PC (a Windows policy). You lose the weather and news panel and Win+W.",
                 "Ends the running Widgets processes, so their memory is freed now.",
                 "Undo turns it back on. Takes full effect after a restart."],
                [new(MemoryActionType.DisableWidgets, "", "Turn off Widgets",
                    "Turn off Widgets for everyone on this PC? The weather and news board leaves the taskbar (fully after a restart). Needs administrator rights.")],
                "Windows extras", "Takes full effect after a restart."));
        }
        else if (s.Feeds is null && s.App("Widgets") is { } w)
            list.Add(new("widgets", "Turn off Widgets", $"Widgets is running and using {MemoryText.Size(w.MemoryBytes)}.", w.MemoryBytes, SuggestionRisk.Low, SuggestionKind.Guided,
                ["Settings > Personalization > Taskbar", "Turn off Widgets (and Copilot if you don't use it)"],
                [new(MemoryActionType.OpenSettings, "ms-settings:taskbar", "Open Taskbar settings")], "Windows extras"));
        if (WindowsFeeds.OfferHighlights(s))
        {
            var host = s.App("SearchHost") is { } sh ? $" The Search box (SearchHost) is using {MemoryText.Size(sh.MemoryBytes)} right now." : "";
            list.Add(new("search-highlights", "Turn off Search highlights",
                $"The Search box downloads Bing pictures and trending searches every day and shows them in the taskbar and the Search window.{host}",
                null, SuggestionRisk.Low, SuggestionKind.Automated,
                ["Removes the Bing pictures and trending searches from the Search box (a Windows policy for everyone on this PC, plus this account's Settings toggle).",
                 "Searching still works, including web results; only the daily highlights go away.",
                 "Undo turns it back on. Takes full effect after a restart."],
                [new(MemoryActionType.DisableSearchHighlights, "", "Turn off Search highlights",
                    "Turn off Search highlights for everyone on this PC? Bing pictures and trending searches leave the Search box. Needs administrator rights.")],
                "Windows extras", "Takes full effect after a restart."));
        }
        // #23 Office start screen: per account (HKCU), only the installed Office 16 apps where it's still on.
        if (OfficeStartScreen.Offer(s))
        {
            var on = OfficeStartScreen.StillOn(s);
            var apps = OfficeStartScreen.Join(on.Select(x => x.App).ToList());
            list.Add(new("office-start-screen", "Skip the Office start screen",
                $"{apps} {(on.Count == 1 ? "opens" : "open")} to a Start screen (templates and recent files) before you can start typing. Skipping it opens a blank document, workbook or presentation right away: about 0.5–1.5 seconds sooner, and a little less memory.",
                null, SuggestionRisk.Low, SuggestionKind.Automated,
                [$"{apps} will open straight to a blank document, workbook or presentation (the \"Show the Start screen when this application starts\" option is turned off).",
                 "You lose the Start screen's templates and recent-files list; recent files are still under File > Open, and templates under File > New.",
                 "Applies to the Windows account this app runs as. Takes effect the next time each app opens.",
                 "Undo brings the start screen back."],
                [new(MemoryActionType.SkipOfficeStartScreen, "", "Skip the Office start screen",
                    $"Skip the start screen in {apps}? They'll open straight to a blank document. Undo brings the start screen back.")],
                "Office", "Takes effect the next time Word, Excel or PowerPoint opens."));
        }

        // #14 idle WSL 2 VM (live page only; not in the service workflow).
        if (WslShutdown.Suggest(s) is { } wsl) list.Add(wsl);

        // Services.
        foreach (var su in s.Services ?? [])
        {
            var svc = su.Info;
            // #14 Claude / Codex VM services: their own card, Manual only (no "Stop now": it would cut off a running Claude or Codex task).
            if (AiVmServices.Is(svc.Name))
            {
                if (CandidateFor(svc) is not null && AiVmServices.Suggest(su, s) is { } ai) list.Add(ai);
                continue;
            }
            if (IsVisualStudioCollector(svc.Name))
            {
                if (!svc.IsAutomatic || CandidateFor(svc) is not { } collector) continue;
                list.Add(new($"svc-{svc.Name}".ToLowerInvariant(), $"Set \"{svc.Label}\" to Manual",
                    $"{collector.What} {collector.Lose}", null, SuggestionRisk.Medium, SuggestionKind.Automated,
                    ["Changes startup type only; does not stop or restart the service. Undo restores the previous startup type."],
                    [new(MemoryActionType.SetServiceManual, svc.Name, "Set to Manual")], "Services"));
                continue;
            }
            if (!svc.IsRunning || CandidateFor(svc) is not { } c || c.NeededWhen?.Invoke(s) == true) continue;
            var mem = su.ProcessMemoryBytes is not { } pm ? "Its memory use couldn't be read."
                : su.Shared ? $"It runs in a shared process with {MemoryText.Plural(su.ServicesInProcess - 1, "other service")} ({MemoryText.Size(pm)} together), so its own share can't be measured exactly."
                : $"It's using {MemoryText.Size(pm)}.";
            var actions = new List<MemoryAction> { new(MemoryActionType.StopService, svc.Name, "Stop now", $"Stop \"{svc.Label}\" until the next restart?") };
            if (svc.IsAutomatic) actions.Add(new(MemoryActionType.SetServiceManual, svc.Name, "Don't start automatically", $"Set \"{svc.Label}\" to start only when needed (Manual)?"));
            if (c.OfferDisable && !svc.IsDisabled) actions.Add(new(MemoryActionType.SetServiceDisabled, svc.Name, "Disable", $"Disable \"{svc.Label}\"? It won't run until you undo this."));
            list.Add(new($"svc-{svc.Name}".ToLowerInvariant(), $"Stop \"{svc.Label}\"", $"{c.What} {mem} You lose: {c.Lose}",
                su.Shared ? null : su.ProcessMemoryBytes, SuggestionRisk.Medium, SuggestionKind.Automated,
                ["Stop now lasts until the next restart (Start it again from Services).", "\"Don't start automatically\" / Disable can be undone here; the original setting is remembered."],
                actions, "Services", su.Shared ? "Shared process: stopping it may show little or no change in free memory." : null, c.DefaultOn));
        }

        return list.OrderByDescending(x => x.SavingBytes ?? -1).ThenBy(x => x.Kind).ThenBy(x => x.Title, StringComparer.Ordinal).ToList();
    }

    /// <summary>Honest "potential savings": only the Close-app suggestions, which free their memory immediately.</summary>
    public static long PotentialCloseSavings(IEnumerable<MemorySuggestion> list) =>
        list.Where(x => x.Actions.Any(a => a.Type == MemoryActionType.CloseApp)).Sum(x => x.SavingBytes ?? 0);
}
