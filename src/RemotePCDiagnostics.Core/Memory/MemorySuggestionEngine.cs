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

    public static bool IsAllowed(string fileName, IReadOnlyList<string> args) =>
        IsTrustedDotnet(fileName ?? "") && args.Count == 2 && args[0] == "build-server" && args[1] == "shutdown";

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
public sealed record ServiceCandidate(string What, string Lose, bool OfferDisable = false, Func<MemorySnapshot, bool>? NeededWhen = null);

/// <summary>Pure rules: snapshot in, suggestions out (sorted by estimated saving).</summary>
public static class MemorySuggestionEngine
{
    public const long Mb = 1L << 20, Gb = 1L << 30;
    public const long CloseAppMin = 300 * Mb;
    public const int MaxCloseSuggestions = 6;
    public const long VsRestartBytes = 1536 * Mb;
    public static readonly TimeSpan VsLongRun = TimeSpan.FromHours(8);
    public static readonly TimeSpan FastStartupUptime = TimeSpan.FromHours(4);
    public static readonly TimeSpan LongUptime = TimeSpan.FromDays(3);

    /// <summary>Electron/web-wrapper chat and media apps; each runs its own copy of Chromium.</summary>
    public static readonly IReadOnlySet<string> ElectronApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "ChatGPT", "Grok", "Antigravity", "slack", "ms-teams", "Teams", "Discord", "Spotify", "Code", "Notion", "WhatsApp" };

    public static readonly IReadOnlyList<string> BuildServerProcesses = ["VBCSCompiler", "MSBuild", "MSBuildTaskHost"];

    private static bool Running(MemorySnapshot s, params string[] names) => names.Any(n => s.App(n) is not null);

    public static readonly IReadOnlyDictionary<string, ServiceCandidate> ServiceCandidates = new Dictionary<string, ServiceCandidate>(StringComparer.OrdinalIgnoreCase)
    {
        ["Spooler"] = new("Print Spooler handles printing.", "You can't print until it's started again.", NeededWhen: s => s.Devices?.HasPrinter != false),
        ["Fax"] = new("Fax sends and receives faxes.", "Faxing from this PC.", OfferDisable: true),
        ["WSearch"] = new("Windows Search keeps an index of your files so searches are fast.", "Start-menu and File Explorer searches get slower; Outlook search may be affected."),
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
    };

    /// <summary>Vendor updater/telemetry helper services matched by name fragment.</summary>
    public static readonly IReadOnlyList<(string Fragment, string What)> VendorServiceFragments =
    [
        ("Lenovo", "a Lenovo Vantage / Lenovo helper service"),
        ("AdobeARMservice", "Adobe's updater"),
        ("AdobeUpdateService", "Adobe's updater"),
        ("gupdate", "Google's updater"),
        ("GoogleUpdater", "Google's updater"),
        ("edgeupdate", "Microsoft Edge's updater"),
        ("VSStandardCollectorService", "Visual Studio's diagnostics collector"),
        ("VSInstallerElevationService", "the Visual Studio installer helper"),
    ];

    public static ServiceCandidate? CandidateFor(ServiceInfo s)
    {
        if (ServiceProtection.IsProtected(s.Name) || ServiceProtection.IsSelfComponent(s.Name)) return null;
        if (ServiceCandidates.TryGetValue(s.Name, out var c)) return c;
        if (s.Name.StartsWith("TeamViewer", StringComparison.OrdinalIgnoreCase)) return ServiceCandidates["TeamViewer"];
        foreach (var (frag, what) in VendorServiceFragments)
            if (s.Name.Contains(frag, StringComparison.OrdinalIgnoreCase))
                return new($"{s.Label} is {what}. It checks for updates or sends usage data in the background.", "Automatic updates for that app until it's started again (the app can still update itself when opened).");
        return null;
    }

    public static IReadOnlyList<MemorySuggestion> Build(MemorySnapshot s)
    {
        var list = new List<MemorySuggestion>();
        var startup = s.Startup ?? [];
        StartupEntry? StartupFor(string proc) => startup.FirstOrDefault(e => e.Enabled && e.ExeName.Equals(proc, StringComparison.OrdinalIgnoreCase));

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
            var heavy = vs.Extensions.OrderByDescending(e => e.SizeBytes).Take(5).ToList();
            if (heavy.Count > 0)
                list.Add(new("vs-extensions", "Turn off Visual Studio extensions you don't use",
                    $"{MemoryText.Plural(vs.Extensions.Count, "extension")} installed. Largest: {string.Join(", ", heavy.Select(e => $"{e.Name} ({MemoryText.Size(e.SizeBytes)})"))}. Each enabled extension loads into Visual Studio's memory.",
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

        // Startup apps (per-user only).
        foreach (var e in startup.Where(e => e.Enabled))
        {
            var app = s.App(e.ExeName);
            if (app is null ? !ElectronApps.Contains(e.ExeName) : app.MemoryBytes < 150 * Mb && !ElectronApps.Contains(e.ExeName)) continue;
            var label = MemoryText.FriendlyAppName(e.ExeName);
            list.Add(new($"startup-{e.Name}".ToLowerInvariant(), $"Stop {label} from starting with Windows",
                app is null ? $"{label} is set to start every time you sign in." : $"{label} starts every time you sign in and is using {MemoryText.Size(app.MemoryBytes)} right now.",
                null, SuggestionRisk.Low, SuggestionKind.Automated, ["Same as Task Manager > Startup apps > Disable, for your account only. Undo turns it back on."],
                [new(MemoryActionType.DisableStartup, e.Name, "Don't start with Windows")], "Startup apps", "Takes effect the next time you sign in."));
        }

        // Fast Startup / uptime.
        if (s.Uptime is { } up && ((s.FastStartup == true && up >= FastStartupUptime) || up >= LongUptime))
        {
            var hours = (int)up.TotalHours;
            var fs = s.FastStartup == true
                ? " Fast Startup is on, so \"Shut down\" doesn't fully clear memory. \"Restart\" does."
                : "";
            list.Add(new("restart", "Restart the PC (Restart, not Shut down)", $"Windows has been running for {(hours >= 48 ? $"{hours / 24} days" : $"{hours} hours")}.{fs} A restart clears leaked memory and leftover background processes.",
                null, SuggestionRisk.Low, SuggestionKind.Guided,
                ["Save your work and close your apps", "Start > Power > Restart"], [], "Windows",
                s.FastStartup == true ? "Turning Fast Startup off changes a PC-wide power setting, so it's left to you: Control Panel > Power Options > Choose what the power buttons do." : null));
        }

        // Defender scanning build folders.
        if (s.App("MsMpEng") is { } def && def.MemoryBytes >= 250 * Mb && Running(s, "devenv", "MSBuild", "VBCSCompiler", "Code"))
            list.Add(new("defender-exclusions", "Exclude your code and build folders from Defender scanning",
                $"Microsoft Defender is using {MemoryText.Size(def.MemoryBytes)} while developer tools are running. Builds create lots of files it rescans.",
                null, SuggestionRisk.Medium, SuggestionKind.Guided,
                ["Windows Security > Virus & threat protection > Manage settings", "Exclusions > Add or remove exclusions > Add an exclusion > Folder", "Add only your own source/build folders (e.g. C:\\src), never a whole drive"],
                [new(MemoryActionType.OpenSettings, "windowsdefender://threatsettings", "Open Windows Security")], "Windows"));

        // Info: memory pressure.
        var m = s.Memory;
        if (m.TotalBytes > 0 && m.UsedPercent >= 85)
            list.Add(new("low-ram", "Memory is almost full", $"{m.UsedPercent}% of {MemoryText.Size(m.TotalBytes)} is in use; only {MemoryText.Size(m.AvailableBytes)} is available. Windows starts using the much slower page file.",
                null, SuggestionRisk.Low, SuggestionKind.Info, [], [], "Windows"));
        if (m.CommitBytes is { } cb && m.CommitLimitBytes is > 0 and var cl && cb >= cl * 0.8)
            list.Add(new("commit", "Page file is under pressure", $"Committed memory is {MemoryText.Size(cb)} of a {MemoryText.Size(cl)} limit ({(int)(100.0 * cb / cl)}%). Apps may fail to start if it fills up.",
                null, SuggestionRisk.Low, SuggestionKind.Info, ["Closing apps is the fastest fix", "Let Windows manage the page file size (System > About > Advanced system settings > Performance > Advanced)"], [], "Windows"));
        if (s.App("Memory Compression") is { } mc && mc.MemoryBytes >= 500 * Mb)
            list.Add(new("compression", "Windows is compressing memory", $"Memory compression holds {MemoryText.Size(mc.MemoryBytes)}. That's Windows squeezing memory because RAM is tight; it's normal, but a sign more RAM or fewer open apps would help.",
                null, SuggestionRisk.Low, SuggestionKind.Info, [], [], "Windows"));

        // Low priority Windows extras.
        if (m.TotalBytes > 0 && m.UsedPercent >= 70)
            list.Add(new("transparency", "Turn off transparency effects", "Transparency and animation effects use a little extra graphics memory. A small saving, but free.",
                null, SuggestionRisk.Low, SuggestionKind.Guided, ["Settings > Personalization > Colors", "Turn off \"Transparency effects\""],
                [new(MemoryActionType.OpenSettings, "ms-settings:personalization-colors", "Open Colors settings")], "Windows extras"));
        if (s.App("Widgets") is { } w)
            list.Add(new("widgets", "Turn off Widgets", $"Widgets is running and using {MemoryText.Size(w.MemoryBytes)}.", w.MemoryBytes, SuggestionRisk.Low, SuggestionKind.Guided,
                ["Settings > Personalization > Taskbar", "Turn off Widgets (and Copilot if you don't use it)"],
                [new(MemoryActionType.OpenSettings, "ms-settings:taskbar", "Open Taskbar settings")], "Windows extras"));

        // Services.
        foreach (var su in s.Services ?? [])
        {
            var svc = su.Info;
            if (!svc.IsRunning || CandidateFor(svc) is not { } c || c.NeededWhen?.Invoke(s) == true) continue;
            var mem = su.ProcessMemoryBytes is not { } pm ? "Its memory use couldn't be read."
                : su.Shared ? $"It runs in a shared process with {MemoryText.Plural(su.ServicesInProcess - 1, "other service")} ({MemoryText.Size(pm)} together), so its own share can't be measured exactly."
                : $"It's using {MemoryText.Size(pm)}.";
            var actions = new List<MemoryAction> { new(MemoryActionType.StopService, svc.Name, "Stop now", $"Stop {svc.Label} until the next restart?") };
            if (svc.IsAutomatic) actions.Add(new(MemoryActionType.SetServiceManual, svc.Name, "Don't start automatically", $"Set {svc.Label} to start only when needed (Manual)?"));
            if (c.OfferDisable && !svc.IsDisabled) actions.Add(new(MemoryActionType.SetServiceDisabled, svc.Name, "Disable", $"Disable {svc.Label}? It won't run until you undo this."));
            list.Add(new($"svc-{svc.Name}".ToLowerInvariant(), $"Stop {svc.Label}", $"{c.What} {mem} You lose: {c.Lose}",
                su.Shared ? null : su.ProcessMemoryBytes, SuggestionRisk.Medium, SuggestionKind.Automated,
                ["Stop now lasts until the next restart (Start it again from Services).", "\"Don't start automatically\" / Disable can be undone here; the original setting is remembered."],
                actions, "Services", su.Shared ? "Shared process: stopping it may show little or no change in free memory." : null));
        }

        return list.OrderByDescending(x => x.SavingBytes ?? -1).ThenBy(x => x.Kind).ThenBy(x => x.Title, StringComparer.Ordinal).ToList();
    }

    /// <summary>Honest "potential savings": only the Close-app suggestions, which free their memory immediately.</summary>
    public static long PotentialCloseSavings(IEnumerable<MemorySuggestion> list) =>
        list.Where(x => x.Actions.Any(a => a.Type == MemoryActionType.CloseApp)).Sum(x => x.SavingBytes ?? 0);
}
