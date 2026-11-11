using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class MemorySuggestionTests
{
    [Fact]
    public void LowMemoryListsFiveLargestOpenUserAppsAndAnAction()
    {
        var apps = Enumerable.Range(1, 6).Select(i => new AppUsage("app" + i, 1, i * 100 * Mb, HasWindow: true)).ToList();
        apps.Add(new("MsMpEng", 1, 2 * Gb, HasWindow: true));
        apps.Add(new("service", 1, 2 * Gb, HasWindow: true, IsService: true));
        apps.Add(new("background", 1, 2 * Gb));
        var snapshot = new MemorySnapshot(new(16 * Gb, 500 * Mb), apps);
        var why = Build(snapshot).Single(s => s.Id == "low-ram").Why;
        Assert.DoesNotContain("App1:", why);
        Assert.DoesNotContain("MsMpEng", why);
        Assert.DoesNotContain("service:", why);
        Assert.DoesNotContain("background:", why);
        for (var i = 6; i >= 2; i--)
        {
            Assert.Contains($"App{i}: {i * 100} MB", why);
            if (i > 2) Assert.True(why.IndexOf($"App{i}:", StringComparison.Ordinal) < why.IndexOf($"App{i - 1}:", StringComparison.Ordinal));
        }
        Assert.Contains("Save your work", why);
        Assert.Contains("Task Manager", Build(snapshot with { Apps = [] }).Single(s => s.Id == "low-ram").Why);
    }

    [Fact]
    public void LowMemoryFlagsOnlyMatchingEnabledStartupEntries()
    {
        var snapshot = new MemorySnapshot(new(16 * Gb, 500 * Mb),
            [new("chrome", 5, 900 * Mb, true), new("slack", 2, 600 * Mb, true)],
            Startup: [new("Chrome", "chrome.exe", true), new("Slack", "slack.exe", false)]);
        var why = Build(snapshot).Single(s => s.Id == "low-ram").Why;
        Assert.Contains("Chrome: 900 MB (starts with Windows)", why);
        Assert.Contains("Slack: 600 MB", why);
        Assert.DoesNotContain("Slack: 600 MB (starts with Windows)", why);
        Assert.Contains("next sign-in", why);
        Assert.Contains("Closing an app does not change its startup setting", why);
        Assert.DoesNotContain("(starts with Windows)", Build(snapshot with { Startup = null }).Single(s => s.Id == "low-ram").Why);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void VisualStudioCollectorOffersOnlyManualEvenWhenVisualStudioIsRunning(bool visualStudioRunning)
    {
        var service = new ServiceInfo("VSStandardCollectorService150", "Visual Studio Standard Collector Service 150", "RUNNING", "AUTO_START", "LocalSystem", "");
        var snapshot = new MemorySnapshot(Ram, visualStudioRunning ? [new AppUsage("devenv", 1, 100 * Mb)] : [], Services: [new(service, 171 * Mb)]);
        var suggestions = Build(snapshot);
        var suggestion = Assert.Single(suggestions);
        Assert.Contains("profiling", suggestion.Why, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("updates", suggestion.Why, StringComparison.OrdinalIgnoreCase);
        var fix = Assert.Single(RemotePCDiagnostics.Core.Workflow.FixCatalog.Build([], suggestions));
        Assert.Equal(MemoryActionType.SetServiceManual, fix.MemoryAction);
        Assert.Equal(MemoryActionType.SetServiceManual, Assert.Single(suggestion.Actions).Type);
        Assert.Null(suggestion.SavingBytes);
        Assert.True(fix.NeedsAdmin);
        Assert.Equal(RemotePCDiagnostics.Core.Changes.UndoSupport.Full, fix.Undo);
        Assert.Empty(RemotePCDiagnostics.Core.Workflow.FixCatalog.Recommendations(suggestions));
        Assert.Empty(Build(snapshot with { Services = [new(service with { StartType = "DEMAND_START" }, 171 * Mb)] }));
    }

    private const long Mb = 1L << 20, Gb = 1L << 30;
    private static readonly MemoryReading Ram = new(16 * Gb, 6 * Gb);

    private static MemorySnapshot Snap(params AppUsage[] apps) => new(Ram, apps);
    private static IReadOnlyList<MemorySuggestion> Build(MemorySnapshot s) => MemorySuggestionEngine.Build(s);
    private static ServiceInfo Svc(string name, string status = "RUNNING", string start = "AUTO_START") => new(name, name + " display", status, start, "LocalSystem", "");

    // ---- browsers / prefs
    private const string ChromeOff = """{"performance_tuning":{"high_efficiency_mode":{"state":0}},"other":1}""";
    private const string ChromeOn = """{"performance_tuning":{"high_efficiency_mode":{"state":2}}}""";
    private const string ChromeOld = """{"performance_tuning":{"high_efficiency_mode":{"enabled":false}}}""";
    private const string EdgeOff = """{"performance_tuning":{"sleeping_tabs":{"enabled":false}}}""";

    [Fact]
    public void BrowserPrefs_Read()
    {
        Assert.False(BrowserPrefs.ReadMemorySaver(ChromeOff, BrowserKind.Chrome));
        Assert.True(BrowserPrefs.ReadMemorySaver(ChromeOn, BrowserKind.Chrome));
        Assert.False(BrowserPrefs.ReadMemorySaver(ChromeOld, BrowserKind.Chrome));
        Assert.False(BrowserPrefs.ReadMemorySaver(EdgeOff, BrowserKind.Edge));
        Assert.Null(BrowserPrefs.ReadMemorySaver("{}", BrowserKind.Chrome));
        Assert.Null(BrowserPrefs.ReadMemorySaver("not json", BrowserKind.Edge));
        Assert.Null(BrowserPrefs.ReadMemorySaver(ChromeOff, BrowserKind.Edge));
    }

    [Fact]
    public void BrowserPrefs_Enable_FlipsExistingKeyOnly_KeepsOtherData()
    {
        var on = BrowserPrefs.EnableMemorySaver(ChromeOff, BrowserKind.Chrome)!;
        Assert.True(BrowserPrefs.ReadMemorySaver(on, BrowserKind.Chrome));
        Assert.Contains("\"other\":1", on);
        Assert.True(BrowserPrefs.ReadMemorySaver(BrowserPrefs.EnableMemorySaver(ChromeOld, BrowserKind.Chrome), BrowserKind.Chrome));
        Assert.True(BrowserPrefs.ReadMemorySaver(BrowserPrefs.EnableMemorySaver(EdgeOff, BrowserKind.Edge), BrowserKind.Edge));
        Assert.Null(BrowserPrefs.EnableMemorySaver("{}", BrowserKind.Chrome));
    }

    [Fact]
    public void Browser_Suggestion_AutomatedOnlyWhenClosed()
    {
        var chrome = new AppUsage("chrome", 13, 872 * Mb, HasWindow: true);
        var running = Build(Snap(chrome) with { Browsers = [new(BrowserKind.Chrome, true, true, false, true)] }).Single(x => x.Id == "browser-chrome");
        Assert.Contains("872 MB across 13 processes", running.Why);
        Assert.DoesNotContain(running.Actions, a => a.Type == MemoryActionType.EnableBrowserMemorySaver);
        Assert.Equal(SuggestionKind.Guided, running.Kind);
        var closed = Build(Snap() with { Browsers = [new(BrowserKind.Edge, true, false, false, true)] }).Single(x => x.Id == "browser-edge");
        Assert.Contains(closed.Actions, a => a.Type == MemoryActionType.EnableBrowserMemorySaver);
        Assert.DoesNotContain(Build(Snap() with { Browsers = [new(BrowserKind.Chrome, true, false, true, true), new(BrowserKind.Edge, true, false, null, true)] }), x => x.Id.StartsWith("browser"));
    }

    // ---- close apps / protected
    [Theory]
    [InlineData("csrss"), InlineData("winlogon"), InlineData("lsass"), InlineData("services"), InlineData("svchost"), InlineData("MsMpEng"),
     InlineData("explorer"), InlineData("dwm"), InlineData("RemotePCDiagnostics.Host"), InlineData("msedgewebview2"), InlineData("WinDefend"), InlineData("System")]
    public void Protected_NeverOfferedToClose(string name)
    {
        Assert.True(ProtectedProcesses.IsProtected(name));
        Assert.DoesNotContain(Build(Snap(new AppUsage(name, 1, 3 * Gb, HasWindow: true))), x => x.Actions.Any(a => a.Type == MemoryActionType.CloseApp));
    }

    [Fact]
    public void CloseApp_OnlyUserAppsWithWindow_GroupedWithCounts_SortedBySaving()
    {
        var list = Build(Snap(
            new AppUsage("ChatGPT", 5, 1 * Gb, HasWindow: true),
            new AppUsage("slack", 6, 700 * Mb, HasWindow: true),
            new AppUsage("bgthing", 1, 900 * Mb, HasWindow: false),
            new AppUsage("svcapp", 1, 900 * Mb, HasWindow: true, IsService: true),
            new AppUsage("small", 1, 100 * Mb, HasWindow: true)));
        var closes = list.Where(x => x.Actions.Any(a => a.Type == MemoryActionType.CloseApp)).ToList();
        Assert.Equal(["close-chatgpt", "close-slack"], closes.Select(x => x.Id));
        Assert.Contains("across 5 processes", closes[0].Why);
        Assert.Contains("own copy of a web browser", closes[0].Why);
        Assert.NotNull(closes[0].Actions[0].Confirm);
        Assert.Equal(1 * Gb + 700 * Mb, MemorySuggestionEngine.PotentialCloseSavings(list));
        var order = list.ToList(); Assert.True(order.IndexOf(closes[0]) < order.IndexOf(closes[1]));
    }

    // ---- VS / build servers
    [Theory]
    [InlineData(7, false)]
    [InlineData(99, false)]
    [InlineData(100, true)]
    public void SmallVisualStudioExtensionsDoNotProduceRecommendations(int sizeMb, bool expected)
    {
        var snapshot = Snap(new AppUsage("devenv", 1, 500 * Mb)) with
        {
            VisualStudio = new(false, [new("Markdown Editor v2", sizeMb * Mb)])
        };
        Assert.Equal(expected, Build(snapshot).Any(s => s.Id == "vs-extensions"));
    }

    [Fact]
    public void VisualStudio_Rules()
    {
        var dev = new AppUsage("devenv", 1, 2 * Gb, HasWindow: true, RunningFor: TimeSpan.FromHours(9));
        var list = Build(Snap(dev) with { VisualStudio = new(true, [new("ReSharper", 300 * Mb), new("ReSharper", 250 * Mb), new("Tiny", 1 * Mb)]) });
        Assert.Contains(list, x => x.Id == "vs-extensions" && x.Why.StartsWith("2 extensions installed."));
        Assert.Contains(list, x => x.Id == "vs-restart" && x.Why.Contains("9 hours"));
        Assert.Contains(list, x => x.Id == "vs-liveshare" && x.Kind == SuggestionKind.Guided && x.Actions.Count == 0);
        Assert.Contains(list, x => x.Id == "vs-extensions" && x.Why.Contains("ReSharper"));
        // VS not running → no VS suggestions; small and fresh → no restart.
        Assert.DoesNotContain(Build(Snap() with { VisualStudio = new(true, []) }), x => x.Id.StartsWith("vs-"));
        Assert.DoesNotContain(Build(Snap(new AppUsage("devenv", 1, 500 * Mb, true, RunningFor: TimeSpan.FromHours(1)))), x => x.Id == "vs-restart");
    }

    [Fact]
    public void BuildServers_Suggested_WithAllowlistedCommand()
    {
        var s = Build(Snap(new AppUsage("VBCSCompiler", 1, 400 * Mb), new AppUsage("MSBuild", 3, 600 * Mb))).Single(x => x.Id == "build-servers");
        Assert.Equal(1000 * Mb, s.SavingBytes);
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.DoesNotContain(Build(Snap()), x => x.Id == "build-servers");
        Assert.True(MemoryCommandAllowlist.IsAllowed("dotnet", ["build-server", "shutdown"]));
        Assert.True(MemoryCommandAllowlist.IsAllowed(@"C:\Program Files\dotnet\dotnet.exe", ["build-server", "shutdown"]));
        Assert.False(MemoryCommandAllowlist.IsAllowed("dotnet", ["build-server", "shutdown", "--x"]));
        Assert.False(MemoryCommandAllowlist.IsAllowed("powershell", ["build-server", "shutdown"]));
        Assert.False(MemoryCommandAllowlist.IsAllowed("dotnet", ["run"]));
        Assert.True(MemoryCommandAllowlist.IsAllowedSettingsUri("ms-settings:taskbar"));
        Assert.False(MemoryCommandAllowlist.IsAllowedSettingsUri("https://evil.example"));
        Assert.False(MemoryCommandAllowlist.IsAllowedSettingsUri("cmd.exe"));
    }

    // ---- startup
    [Theory]
    [InlineData("\"C:\\Users\\b\\AppData\\Local\\slack\\slack.exe\" --process-start-args --startup", "slack")]
    [InlineData("C:\\Program Files\\Spotify\\Spotify.exe /minimized", "Spotify")]
    [InlineData("Discord.exe", "Discord")]
    [InlineData("\"C:\\Users\\b\\AppData\\Local\\Microsoft\\Teams\\Update.exe\" --processStart \"Teams.exe\" --process-start-args \"--profile=AAD\"", "Teams")]
    [InlineData("C:\\Users\\b\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe", "Discord")]
    [InlineData("\"C:\\Tools\\Update.exe\" /silent", "Update")]
    [InlineData("", "")]
    public void Startup_ExeName(string cmd, string exe) => Assert.Equal(exe, StartupParsing.ExeName(cmd));

    [Fact]
    public void Startup_Approved_Bytes()
    {
        Assert.True(StartupParsing.IsEnabled(null));
        Assert.True(StartupParsing.IsEnabled([2, 0, 0, 0]));
        Assert.True(StartupParsing.IsEnabled([6, 0]));
        Assert.False(StartupParsing.IsEnabled([3, 0]));
        var d = StartupParsing.DisabledValue(new DateTime(2026, 10, 30, 0, 0, 0, DateTimeKind.Utc));
        Assert.Equal(12, d.Length);
        Assert.False(StartupParsing.IsEnabled(d));
    }

    [Fact]
    public void Startup_SuggestedForHeavyOrElectron_NotWhenDisabled()
    {
        var snap = Snap(new AppUsage("Discord", 4, 400 * Mb, true)) with
        {
            Startup = [new("Discord", "\"C:\\x\\Discord.exe\"", true), new("Tiny", "C:\\t\\tiny.exe", true), new("Spotify", "\"C:\\s\\Spotify.exe\"", false)],
        };
        var ids = Build(snap).Select(x => x.Id).ToList();
        Assert.Contains("startup-discord", ids);
        Assert.DoesNotContain("startup-tiny", ids);
        Assert.DoesNotContain("startup-spotify", ids);
    }

    [Fact]
    public void TrayHelpers_OfferedAtStartup_ButNeverDescribedAsABrowser()
    {
        Assert.Empty(MemorySuggestionEngine.ElectronApps.Intersect(MemorySuggestionEngine.StartupTrayHelpers));
        foreach (var helper in new[] { "RadeonSoftware", "BrStMonW", "BrCcBoot", "LenovoVantage" })
        {
            Assert.DoesNotContain(helper, MemorySuggestionEngine.ElectronApps);
            Assert.True(MemorySuggestionEngine.AlwaysOfferStartup(helper));
        }

        // Not running: still offered at startup, with the vendor-helper reason and no browser talk.
        var cc4 = new StartupEntry("hklm32:ControlCenter4", @"""C:\Program Files (x86)\ControlCenter4\BrCcBoot.exe"" /autorun", true, StartupScope.LocalMachine32);
        var sug = Build(Snap() with { Startup = [cc4] }).Single(x => x.Id == "startup-hklm32:controlcenter4");
        Assert.Contains("vendor helper", sug.Why);
        Assert.DoesNotContain("browser", sug.Why);

        // A big window of a tray helper offered as "Close app" doesn't claim a built-in browser either.
        var close = Build(Snap(new AppUsage("RadeonSoftware", 1, 900 * Mb, HasWindow: true))).Single(x => x.Id == "close-radeonsoftware");
        Assert.DoesNotContain("web browser", close.Why);
        Assert.DoesNotContain(close.Steps, st => st.Contains("Hardware acceleration"));

        // Real Electron apps keep both behaviours.
        var slack = Build(Snap(new AppUsage("slack", 3, 900 * Mb, HasWindow: true))).Single(x => x.Id == "close-slack");
        Assert.Contains("web browser", slack.Why);
        Assert.True(MemorySuggestionEngine.AlwaysOfferStartup("Spotify"));
        Assert.False(MemorySuggestionEngine.AlwaysOfferStartup("notepad"));
    }

    // New Teams (packaged task), Teams (free) (packaged task) and classic Teams (squirrel Run value).
    public static TheoryData<string, string, string, StartupScope> TeamsStartupEntries => new()
    {
        { @"uwp:MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask", @"MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask", "Microsoft Teams", StartupScope.PackagedUwp },
        { @"uwp:MicrosoftTeams_8wekyb3d8bbwe\TeamsStartupTask", @"MicrosoftTeams_8wekyb3d8bbwe\TeamsStartupTask", "Microsoft Teams (free)", StartupScope.PackagedUwp },
        { "com.squirrel.Teams.Teams", @"C:\Users\b\AppData\Local\Microsoft\Teams\Update.exe --processStart ""Teams.exe"" --process-start-args ""--system-initiated""", "Microsoft Teams (classic)", StartupScope.CurrentUser },
    };

    [Theory]
    [MemberData(nameof(TeamsStartupEntries))]
    public void Teams_EachVariant_OfferedAtStartup_WithFriendlyName_AndOptIn(string name, string command, string friendly, StartupScope scope)
    {
        var entry = new StartupEntry(name, command, true, scope);
        Assert.Contains(entry.ExeName, MemorySuggestionEngine.TeamsApps);
        Assert.True(MemorySuggestionEngine.AlwaysOfferStartup(entry.ExeName));
        Assert.Equal(friendly, MemoryText.FriendlyAppName(entry.ExeName));

        // Not running at scan time: still offered.
        var sug = Build(Snap() with { Startup = [entry] }).Single(x => x.Id == $"startup-{name}".ToLowerInvariant());
        Assert.Equal($"Stop {friendly} from starting with Windows", sug.Title);
        Assert.False(sug.DefaultOn);                                                   // opt-in in the service workflow
        Assert.Contains("450–850 MB", sug.Why);
        Assert.Contains("chat or call notifications until you open Teams", sug.Why);
        Assert.Contains("Undo turns it back on", sug.Why);
        Assert.DoesNotContain("web browser", sug.Why);
        var action = Assert.Single(sug.Actions);
        Assert.Equal(MemoryActionType.DisableStartup, action.Type);
        Assert.Equal(name, action.Target);
        var fix = Assert.Single(RemotePCDiagnostics.Core.Workflow.FixCatalog.Build([], [sug]));
        Assert.False(fix.DefaultOn);
        Assert.Equal(RemotePCDiagnostics.Core.Changes.UndoSupport.Full, fix.Undo);

        // Disabled already: nothing to offer.
        Assert.DoesNotContain(Build(Snap() with { Startup = [entry with { Enabled = false }] }), x => x.Id.StartsWith("startup-"));
    }

    [Fact]
    public void Teams_RunningAtSignIn_ShowsItsMemory_OtherStartupAppsStayTicked()
    {
        var teams = new StartupEntry(@"uwp:MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask", @"MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask", true, StartupScope.PackagedUwp);
        var spotify = new StartupEntry("Spotify", "\"C:\\s\\Spotify.exe\" /minimized", true);
        var list = Build(Snap(new AppUsage("ms-teams", 6, 700 * Mb)) with { Startup = [teams, spotify] });
        var t = list.Single(x => x.Id == @"startup-uwp:msteams_8wekyb3d8bbwe\teamstfwstartuptask");
        Assert.Contains("Microsoft Teams starts every time you sign in and is using 700 MB", t.Why);
        Assert.Equal(700 * Mb, t.SavingBytes);
        Assert.False(t.DefaultOn);
        Assert.True(list.Single(x => x.Id == "startup-spotify").DefaultOn);
    }

    [Theory]
    [InlineData("AdobeARMservice", "Acrobat")]
    [InlineData("AGSService", "licens")]
    [InlineData("AGMService", "licens")]
    [InlineData("AdobeUpdateService", "Creative Cloud")]
    public void Adobe_Services_UseRealServiceNames_AndOfferManualWhenAutomatic(string name, string about)
    {
        Assert.True(MemorySuggestionEngine.ServiceCandidates.ContainsKey(name));
        Assert.False(MemorySuggestionEngine.ServiceCandidates.ContainsKey("ArmsSvc"));   // armsvc.exe is the exe; the service is AdobeARMservice

        var auto = Build(Snap() with { Services = [new(Svc(name), 6 * Mb)] }).Single(x => x.Id == $"svc-{name}".ToLowerInvariant());
        Assert.Contains(about, auto.Why);
        Assert.DoesNotContain("is Adobe's updater", auto.Why);                           // its own text, not the generic vendor wording
        Assert.True(auto.DefaultOn);
        Assert.Contains(auto.Actions, a => a.Type == MemoryActionType.SetServiceManual && a.Target == name);
        var fix = Assert.Single(RemotePCDiagnostics.Core.Workflow.FixCatalog.Build([], [auto]));
        Assert.Equal(MemoryActionType.SetServiceManual, fix.MemoryAction);
        Assert.Equal(name, fix.MemoryTarget);
        Assert.True(fix.DefaultOn);

        // Already Manual: only "Stop now", which the service workflow intentionally doesn't list.
        var manual = Build(Snap() with { Services = [new(Svc(name, start: "DEMAND_START"), 6 * Mb)] }).Single(x => x.Id == $"svc-{name}".ToLowerInvariant());
        Assert.Equal(MemoryActionType.StopService, Assert.Single(manual.Actions).Type);
        Assert.Empty(RemotePCDiagnostics.Core.Workflow.FixCatalog.Build([], [manual]));
    }

    [Fact]
    public void Adobe_AcrobatAndLicensingText_SaysWhatStillHappens()
    {
        Assert.Contains("still check for and install updates when they're opened", MemorySuggestionEngine.ServiceCandidates["AdobeARMservice"].Lose);
        Assert.Contains("when an Adobe app starts", MemorySuggestionEngine.ServiceCandidates["AGSService"].Lose);
        Assert.Contains("when an Adobe app starts", MemorySuggestionEngine.ServiceCandidates["AGMService"].Lose);
    }

    [Theory]
    [InlineData("hklm32:AdobeGCInvoker-1.0", @"""C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient\AGCInvokerUtility.exe""", StartupScope.LocalMachine32, "Adobe GC Invoker Utility")]
    [InlineData("hklm32:Acrobat Assistant 8.0", @"""C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrotray.exe""", StartupScope.LocalMachine32, "Adobe AcroTray")]
    [InlineData("hklm32:AdobeAAMUpdater-1.0", @"""C:\Program Files (x86)\Common Files\Adobe\OOBE\PDApp\UWA\UpdaterStartupUtility.exe""", StartupScope.LocalMachine32, "Adobe Updater Startup Utility")]
    public void Adobe_TrayHelpers_OfferedAtStartup_WithoutBrowserWording(string name, string command, StartupScope scope, string friendly)
    {
        var entry = new StartupEntry(name, command, true, scope);
        Assert.Contains(entry.ExeName, MemorySuggestionEngine.StartupTrayHelpers);
        Assert.DoesNotContain(entry.ExeName, MemorySuggestionEngine.ElectronApps);
        Assert.Equal(friendly, MemoryText.FriendlyAppName(entry.ExeName));
        var sug = Build(Snap() with { Startup = [entry] }).Single(x => x.Id == $"startup-{name}".ToLowerInvariant());
        Assert.Equal($"Stop {friendly} from starting with Windows", sug.Title);
        Assert.Contains("vendor helper", sug.Why);
        Assert.DoesNotContain("browser", sug.Why);
        Assert.True(sug.DefaultOn);
    }

    [Fact]
    public void Startup_PackagedUwp_AndCrossDeviceGuard_AndNewServices()
    {
        var uwp = new StartupEntry("uwp:Microsoft.YourPhone_8wekyb3d8bbwe\\YourPhone.Start", "Microsoft.YourPhone_8wekyb3d8bbwe\\YourPhone.Start", true, StartupScope.PackagedUwp);
        var amd = new StartupEntry("uwp:AdvancedMicroDevicesInc-2.AMDRadeonSoftware_0a9344xs7nr4m\\launcherrsxruntimeTask", "AdvancedMicroDevicesInc-2.AMDRadeonSoftware_0a9344xs7nr4m\\launcherrsxruntimeTask", true, StartupScope.PackagedUwp);
        Assert.Equal("PhoneExperienceHost", uwp.ExeName);
        Assert.Equal("RadeonSoftware", amd.ExeName);

        // Phone Link is offered even with a paired phone: it only stops the automatic start; opening Phone Link starts it as usual.
        var pairedSnap = Snap(new AppUsage("PhoneExperienceHost", 1, 390 * Mb)) with { Startup = [uwp, amd], Devices = new(HasPairedCrossDevice: true, HasPenDigitizer: false) };
        var pairedIds = Build(pairedSnap).Select(x => x.Id).ToList();
        Assert.Contains(pairedIds, id => id.Contains("yourphone"));
        Assert.Contains(pairedIds, id => id.Contains("amdradeonsoftware"));

        var unpairedSnap = pairedSnap with { Devices = new(HasPairedCrossDevice: false, HasPenDigitizer: false) };
        Assert.Contains(Build(unpairedSnap).Select(x => x.Id), id => id.Contains("yourphone"));

        // UDCService, BrYNSvc are flagged when running; CoworkVMService, CodexSandboxService when a signed-in user may start them (#14).
        var svcSnap = Snap() with
        {
            Services =
            [
                new(Svc("UDCService"), 35 * Mb),
                new(Svc("BrYNSvc"), 14 * Mb),
                new(Svc("CoworkVMService"), 26 * Mb, 1, UsersCanStart: true),
                new(Svc("CodexSandboxService.OpenAI.Codex_2p2nqf0c97628"), 8 * Mb, 1, UsersCanStart: true),
            ],
        };
        var svcIds = Build(svcSnap).Select(x => x.Id).ToList();
        Assert.Contains("svc-udcservice", svcIds);
        Assert.Contains("svc-brynsvc", svcIds);
        Assert.Contains("svc-coworkvmservice", svcIds);
        Assert.Contains("svc-codexsandboxservice.openai.codex_2p2nqf0c97628", svcIds);
    }

    // ---- Windows / info
    [Fact]
    public void FastStartup_Uptime_AndInfoRules()
    {
        Assert.Contains(Build(Snap() with { Uptime = TimeSpan.FromHours(8), FastStartup = true }), x => x.Id == "restart" && x.Kind == SuggestionKind.Automated && x.Why.Contains("8 hours")
            && x.Actions.Any(a => a.Type == MemoryActionType.RestartPc) && x.Actions.Any(a => a.Type == MemoryActionType.DisableFastStartup));
        Assert.DoesNotContain(Build(Snap() with { Uptime = TimeSpan.FromHours(2), FastStartup = true }), x => x.Id == "restart");
        Assert.DoesNotContain(Build(Snap() with { Uptime = TimeSpan.FromHours(8), FastStartup = false }), x => x.Id == "restart");
        var tight = new MemorySnapshot(new(16 * Gb, 1 * Gb, 30 * Gb, 32 * Gb), [new AppUsage("Memory Compression", 1, 800 * Mb)]);
        var ids = Build(tight).Select(x => x.Id).ToList();
        Assert.Contains("low-ram", ids); Assert.Contains("commit", ids); Assert.Contains("compression", ids); Assert.Contains("transparency", ids);
        Assert.DoesNotContain(Build(Snap()), x => x.Kind == SuggestionKind.Info);
    }

    [Fact]
    public void Defender_OnlyWithDevTools()
    {
        var def = new AppUsage("MsMpEng", 1, 400 * Mb);
        Assert.DoesNotContain(Build(Snap(def)), x => x.Id == "defender-exclusions");
        var s = Build(Snap(def, new AppUsage("devenv", 1, 500 * Mb, true))).Single(x => x.Id == "defender-exclusions");
        Assert.Equal(SuggestionKind.Guided, s.Kind);
        Assert.DoesNotContain(s.Actions, a => a.Type != MemoryActionType.OpenSettings);
    }

    // ---- services
    [Fact]
    public void Services_Rules()
    {
        var snap = Snap() with
        {
            Devices = new(HasPrinter: false, HasBluetoothDevices: true),
            Services =
            [
                new(Svc("Spooler"), 30 * Mb), new(Svc("bthserv"), 20 * Mb, 4), new(Svc("DiagTrack"), 40 * Mb),
                new(Svc("WinDefend"), 200 * Mb), new(Svc("EventLog"), 50 * Mb), new(Svc("Fax", "STOPPED"), 5 * Mb),
                new(Svc("LenovoVantageService"), 80 * Mb), new(new ServiceInfo("LenovoFnAndFunctionKeys", "Lenovo Fn and function keys service", "RUNNING", "AUTO_START", "LocalSystem", ""), 14 * Mb), new(Svc("WbioSrvc"), 10 * Mb), new(Svc("vmcompute"), 10 * Mb),
            ],
        };
        var list = Build(snap);
        var ids = list.Select(x => x.Id).ToList();
        Assert.Contains("svc-spooler", ids);
        Assert.Contains("svc-diagtrack", ids);
        Assert.Contains("svc-lenovovantageservice", ids);
        var lenovo = list.Single(x => x.Id == "svc-lenovovantageservice");
        Assert.Equal("Stop \"LenovoVantageService display\"", lenovo.Title);
        var critSnap = Snap() with { Services = [new(new ServiceInfo("LenovoVantageServices", "Critical Service for Lenovo Vantage", "RUNNING", "AUTO_START", "LocalSystem", ""), 38 * Mb)] };
        var crit = Build(critSnap).Single(x => x.Id == "svc-lenovovantageservices");
        Assert.Equal("Stop \"Critical Service for Lenovo Vantage\"", crit.Title);
        Assert.Contains("Despite \"Critical\" in its name, Windows and your hardware do not need it", crit.Why);
        var imSnap = Snap() with { Services = [new(new ServiceInfo("ImControllerService", "System Interface Foundation Service", "RUNNING", "AUTO_START", "LocalSystem", ""), 24 * Mb)] };
        var im = Build(imSnap).Single(x => x.Id == "svc-imcontrollerservice");
        Assert.DoesNotContain(im.Actions, a => a.Type == MemoryActionType.SetServiceManual);
        Assert.Contains(im.Actions, a => a.Type == MemoryActionType.SetServiceDisabled);
        var imFix = Assert.Single(RemotePCDiagnostics.Core.Workflow.FixCatalog.Build([], [im]));
        Assert.Equal(MemoryActionType.SetServiceDisabled, imFix.MemoryAction);
        Assert.Equal("Disable \"System Interface Foundation Service\"", imFix.Title);
        Assert.DoesNotContain("svc-lenovofnandfunctionkeys", ids); // hardware hotkey service excluded
        Assert.DoesNotContain("svc-bthserv", ids);   // has BT devices
        Assert.DoesNotContain("svc-wbiosrvc", ids);  // fingerprint unknown → not suggested
        Assert.DoesNotContain("svc-windefend", ids); // protected
        Assert.DoesNotContain("svc-eventlog", ids);  // protected
        Assert.DoesNotContain("svc-fax", ids);       // not running
        Assert.Contains("svc-vmcompute", ids);       // no VM/WSL/Docker running
        Assert.DoesNotContain(Build(snap with { Apps = [new AppUsage("vmmemWSL", 1, 2 * Gb)] }), x => x.Id == "svc-vmcompute");
        var diag = list.Single(x => x.Id == "svc-diagtrack");
        Assert.Contains(diag.Actions, a => a.Type == MemoryActionType.SetServiceDisabled);
        Assert.Contains(diag.Actions, a => a.Type == MemoryActionType.SetServiceManual);
        Assert.All(diag.Actions, a => Assert.NotNull(a.Confirm));
        var shared = Build(snap with { Devices = new(false, false) }).Single(x => x.Id == "svc-bthserv");
        Assert.Null(shared.SavingBytes);
        Assert.Contains("shared process", shared.Why);
    }

    // ---- Windows Search: only on small, nearly-full PCs without classic Outlook; opt-in
    private static MemorySnapshot SearchSnap(long totalGb, int usedPercent, bool? outlook, params AppUsage[] apps) =>
        new(new(totalGb * Gb, totalGb * Gb * (100 - usedPercent) / 100), apps, Services: [new(Svc("WSearch"), 40 * Mb)], Devices: new(HasClassicOutlook: outlook));

    [Fact]
    public void WindowsSearch_OfferedOnSmallFullPcWithoutOutlook_OptIn()
    {
        var s = Build(SearchSnap(8, 90, false)).Single(x => x.Id == "svc-wsearch");
        Assert.False(s.DefaultOn);
        Assert.Contains(s.Actions, a => a.Type == MemoryActionType.SetServiceManual);
        Assert.Contains("tens of MB", s.Why);                                 // what it saves: small
        Assert.Contains("File Explorer searches get slower", s.Why);          // what the client loses
        Assert.Contains("Outlook", s.Why);
        Assert.Contains("previous start type", s.Why);                        // undo
        Assert.Contains(Build(SearchSnap(8, 85, false)), x => x.Id == "svc-wsearch");
        Assert.True(Build(Snap() with { Services = [new(Svc("DiagTrack"), 40 * Mb)] }).Single(x => x.Id == "svc-diagtrack").DefaultOn);
    }

    [Theory]
    [InlineData(16, 90, false)]   // plenty of RAM
    [InlineData(8, 70, false)]    // memory not nearly full
    [InlineData(8, 84, false)]
    [InlineData(8, 90, true)]     // classic Outlook installed
    [InlineData(8, 90, null)]     // couldn't tell: Outlook may be installed
    public void WindowsSearch_NotOffered(int totalGb, int usedPercent, bool? outlook) =>
        Assert.DoesNotContain(Build(SearchSnap(totalGb, usedPercent, outlook)), x => x.Id == "svc-wsearch");

    [Fact]
    public void WindowsSearch_NotOffered_WhileOutlookRunning_OrDevicesUnknown()
    {
        Assert.DoesNotContain(Build(SearchSnap(8, 90, false, new AppUsage("OUTLOOK", 1, 300 * Mb, HasWindow: true))), x => x.Id == "svc-wsearch");
        Assert.DoesNotContain(Build(SearchSnap(8, 90, false) with { Devices = null }), x => x.Id == "svc-wsearch");
        Assert.Contains(Build(SearchSnap(8, 90, false, new AppUsage("olk", 1, 300 * Mb, HasWindow: true))), x => x.Id == "svc-wsearch"); // new Outlook doesn't use the index
    }

    [Fact]
    public void ClassicOutlook_ClickToRunProducts()
    {
        string? None(string _) => null;
        Assert.True(ClassicOutlook.InClickToRun("O365ProPlusRetail", None));
        Assert.True(ClassicOutlook.InClickToRun("HomeBusiness2019Retail", None));
        Assert.True(ClassicOutlook.InClickToRun("VisioProRetail, OutlookRetail", None));
        Assert.False(ClassicOutlook.InClickToRun("HomeStudent2019Retail,VisioProRetail", None));
        Assert.False(ClassicOutlook.InClickToRun("O365ProPlusRetail", id => "groove,lync,Outlook"));   // Outlook excluded
        Assert.False(ClassicOutlook.InClickToRun(null, None));
        Assert.False(ClassicOutlook.InClickToRun("", None));
    }

    [Fact]
    public void Services_NothingProtectedEverSuggested()
    {
        var all = ServiceProtection.Protected.Select(n => new ServiceUsage(Svc(n), 100 * Mb)).ToList();
        Assert.DoesNotContain(Build(Snap() with { Services = all, Devices = new(false, false, false) }), x => x.Category == "Services");
    }

    // ---- feedback wording
    [Fact]
    public void Feedback_Wording()
    {
        var before = new MemoryReading(10 * Gb, (long)(5.2 * Gb));
        var after = new MemoryReading(10 * Gb, (long)(6.2 * Gb));
        Assert.Equal("Freed about 1.0 GB. Available RAM 5.2 → 6.2 GB (used 48% → 38%).", MemoryFeedback.Describe(before, after, false));
        Assert.StartsWith("No measurable change.", MemoryFeedback.Describe(before, before with { AvailableBytes = before.AvailableBytes + 10 * Mb }, false));
        Assert.StartsWith("No memory freed: other apps used 300 MB more", MemoryFeedback.Describe(before, before with { AvailableBytes = before.AvailableBytes - 300 * Mb }, false));
        Assert.StartsWith("Takes effect", MemoryFeedback.Describe(before, null, true));
        Assert.StartsWith("Couldn't measure", MemoryFeedback.Describe(null, after, false));
    }

    // ---- service orchestration, undo, logging
    private sealed class FakeSys : IMemorySystem
    {
        public MemorySnapshot Snap = new(Ram, []);
        public Queue<MemoryReading> Readings = new();
        public List<string> Calls = [];
        public Dictionary<string, byte[]?> Approved = new();
        public Dictionary<string, string> StartTypes = new(StringComparer.OrdinalIgnoreCase);
        public string? LocalState = ChromeOff;
        public bool BrowserRunning;
        public MemoryReading ReadMemory() => Readings.Count > 0 ? Readings.Dequeue() : Ram;
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> services, CancellationToken ct) => Task.FromResult(Snap);
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) { Calls.Add("close:" + p); return Task.FromResult(new ActionOutcome(p != "stubborn", p == "stubborn" ? "It didn't close." : $"Closed {p}.")); }
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) { Calls.Add("kill:" + p); return Task.FromResult(new ActionOutcome(true, "Ended.")); }
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) { Calls.Add($"run:{f} {string.Join(' ', a)}"); return Task.FromResult(new ActionOutcome(true, "Build servers shut down.")); }
        public byte[]? GetStartupApproved(string name) => Approved.GetValueOrDefault(name);
        public void SetStartupApproved(string name, byte[]? v) { Calls.Add("approved:" + name); Approved[name] = v; }
        public bool IsBrowserRunning(BrowserKind k) => BrowserRunning;
        public string? ReadBrowserLocalState(BrowserKind k) => LocalState;
        public void WriteBrowserLocalState(BrowserKind k, string json) { Calls.Add("write:" + k); LocalState = json; }
        public void OpenUri(string uri) => Calls.Add("open:" + uri);
        public string GetServiceStartType(string n) => StartTypes.GetValueOrDefault(n, "Automatic");
        public void SetServiceStartType(string n, string t) { Calls.Add($"start-type:{n}={t}"); StartTypes[n] = t; }
        public bool? Transparency = true;
        public bool? GetTransparency() => Transparency;
        public void SetTransparency(bool on) { Calls.Add("transparency:" + on); Transparency = on; }
        public Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct) { Calls.Add("pagefile"); return Task.FromResult(new ActionOutcome(true, "Windows will manage the page file size from the next restart.")); }
    }

    private sealed class SvcBackend : IServiceControlBackend
    {
        public List<string> Calls = [];
        public ServiceState GetState(string name) => ServiceState.Running;
        public bool IsDriver(string name) => false;
        public IReadOnlyList<DependentService> GetRunningDependents(string name) => [];
        public void Start(string name) => Calls.Add("start:" + name);
        public void Stop(string name) => Calls.Add("stop:" + name);
        public Task<bool> WaitForStateAsync(string name, ServiceState t, TimeSpan timeout, CancellationToken ct) => Task.FromResult(true);
    }

    private static (MemorySuggestionService S, FakeSys Sys, List<string> Events) Make(MemorySnapshot snap, IServiceControlBackend? backend = null, RemediationService? remediation = null)
    {
        var sys = new FakeSys { Snap = snap };
        var events = new List<string>();
        var svc = new MemorySuggestionService(sys, null, backend is null ? null : new ServiceActionService(backend, new SessionContext(SessionMode.Remote)),
            new SessionContext(SessionMode.Remote), (l, m) => events.Add(m), settle: TimeSpan.Zero, remediation: remediation);
        return (svc, sys, events);
    }

    // ---- one-click Windows suggestions (Oct 2026)
    private static readonly MemorySnapshot Busy = new(new(16 * Gb, 3 * Gb), []); // 81% used: transparency suggested

    [Fact]
    public async Task Transparency_OneClick_WithUndo()
    {
        var (svc, sys, events) = Make(Busy);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "transparency");
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        var r = await svc.ApplyAsync(s, s.Actions.Single(a => a.Type == MemoryActionType.DisableTransparency));
        Assert.True(r.Success);
        Assert.Equal(false, sys.Transparency);
        Assert.Contains(events, e => e.Contains("DisableTransparency"));
        var u = Assert.Single(svc.Undos, x => x.Type == MemoryActionType.DisableTransparency);
        Assert.True((await svc.UndoAsync(u)).Success);
        Assert.Equal(true, sys.Transparency);
    }

    [Fact]
    public void Transparency_NotSuggestedWhenAlreadyOff() =>
        Assert.DoesNotContain(Build(Busy with { TransparencyOn = false }), x => x.Id == "transparency");

    [Fact]
    public async Task PageFile_FixedSize_OneClick_ManagedIsInfo()
    {
        var tight = new MemorySnapshot(new(16 * Gb, 4 * Gb, 30 * Gb, 32 * Gb), []);
        var info = Build(tight with { AutoPageFile = true }).Single(x => x.Id == "commit");
        Assert.Equal(SuggestionKind.Info, info.Kind);
        Assert.Empty(info.Actions);
        var (svc, sys, _) = Make(tight with { AutoPageFile = false });
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "commit");
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.True((await svc.ApplyAsync(s, s.Actions.Single())).Success);
        Assert.Contains("pagefile", sys.Calls);
    }

    [Fact]
    public async Task Restart_UsesRemediation_FastStartupToo()
    {
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var settings = new FakeSystemSettings();
        var rem = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Remote), settings: settings);
        var snap = Snap() with { Uptime = TimeSpan.FromHours(8), FastStartup = true };
        var (svc, _, _) = Make(snap, remediation: rem);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "restart");
        var r = await svc.ApplyAsync(s, s.Actions.Single(a => a.Type == MemoryActionType.DisableFastStartup));
        Assert.True(r.Success);
        Assert.Contains("fast-startup=0", settings.Calls);
        Assert.Contains(rem.Recent, x => x.Kind == RemediationKind.DisableFastStartup);
        var (noRem, _, _) = Make(snap);
        await noRem.ScanAsync();
        var s2 = noRem.Suggestions.Single(x => x.Id == "restart");
        Assert.False((await noRem.ApplyAsync(s2, s2.Actions.Single(a => a.Type == MemoryActionType.RestartPc))).Success);
    }

    [Fact]
    public void LowRam_MentionsMemorySlots()
    {
        var tight = new MemorySnapshot(new(16 * Gb, 1 * Gb), [], Slots: new MemorySlots(2, 1, 32 * Gb, 16 * Gb));
        Assert.Contains("1 of 2 memory slots used · up to 32.0 GB supported", Build(tight).Single(x => x.Id == "low-ram").Why);
    }

    [Theory]
    [InlineData("""{"Auto":"False","Slots":"2","Used":"1","MaxKB":"33554432","Installed":"17179869184"}""", false, 2, 1)]
    [InlineData("""{"Auto":"True","Slots":"","Used":"0","MaxKB":"","Installed":""}""", true, 0, 0)]
    public void MemoryProbe_Parses(string json, bool auto, int total, int used)
    {
        var (a, slots) = MemoryProbe.Parse(json);
        Assert.Equal(auto, a);
        if (total == 0) Assert.Null(slots);
        else { Assert.Equal((total, used), (slots!.Total, slots.Used)); Assert.Equal(32L * Gb, slots.MaxCapacityBytes); }
    }

    [Fact]
    public async Task Close_MeasuresFeedback_TotalsFreed_LogsEvent()
    {
        var (s, sys, events) = Make(Snap(new AppUsage("ChatGPT", 3, 1 * Gb, true)));
        await s.ScanAsync();
        sys.Readings.Enqueue(new(16 * Gb, 5 * Gb)); sys.Readings.Enqueue(new(16 * Gb, 6 * Gb));
        var sug = s.Suggestions.Single(x => x.Id == "close-chatgpt");
        var r = await s.ApplyAsync(sug, sug.Actions[0]);
        Assert.True(r.Success);
        Assert.Contains("Freed about 1.0 GB", r.Message);
        Assert.Equal(1 * Gb, s.TotalFreedBytes);
        Assert.Contains("close:ChatGPT", sys.Calls);
        Assert.Contains(events, e => e.StartsWith("Memory suggestion applied") && e.Contains("Actor: Remote user") && e.Contains("CloseApp"));
    }

    [Fact]
    public async Task Close_Failure_OffersForceClose_NeverKillsByItself()
    {
        var (s, sys, _) = Make(Snap(new AppUsage("stubborn", 1, 1 * Gb, true)));
        await s.ScanAsync();
        var sug = s.Suggestions.Single(x => x.Id == "close-stubborn");
        var r = await s.ApplyAsync(sug, sug.Actions[0]);
        Assert.False(r.Success);
        Assert.True(r.CanForceClose);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("kill:"));
        var forced = await s.ApplyAsync(sug, new MemoryAction(MemoryActionType.ForceCloseApp, "stubborn", "Force close"));
        Assert.True(forced.Success);
        Assert.Contains("kill:stubborn", sys.Calls);
    }

    [Fact]
    public async Task Close_Protected_RefusedEvenIfRequested()
    {
        var (s, sys, _) = Make(Snap());
        var fake = new MemorySuggestion("x", "x", "", null, SuggestionRisk.High, SuggestionKind.Automated, [], [new(MemoryActionType.CloseApp, "explorer", "Close")]);
        var r = await s.ApplyAsync(fake, fake.Actions[0]);
        Assert.False(r.Success);
        Assert.Empty(sys.Calls);
    }

    [Fact]
    public async Task BuildServers_RunsOnlyAllowlistedCommand()
    {
        var (s, sys, _) = Make(Snap(new AppUsage("VBCSCompiler", 1, 400 * Mb)));
        await s.ScanAsync();
        var sug = s.Suggestions.Single(x => x.Id == "build-servers");
        Assert.True((await s.ApplyAsync(sug, sug.Actions[0])).Success);
        Assert.Equal(["run:dotnet build-server shutdown"], sys.Calls);
    }

    [Fact]
    public async Task Startup_Disable_ThenUndo_RestoresPreviousValue()
    {
        var (s, sys, events) = Make(Snap(new AppUsage("slack", 2, 400 * Mb, true)) with { Startup = [new("com.squirrel.slack.slack", "\"C:\\s\\slack.exe\"", true)] });
        sys.Approved["com.squirrel.slack.slack"] = [2, 0, 0, 0];
        await s.ScanAsync();
        var sug = s.Suggestions.Single(x => x.Id.StartsWith("startup-"));
        var r = await s.ApplyAsync(sug, sug.Actions[0]);
        Assert.Contains("Takes effect", r.Message);
        Assert.False(StartupParsing.IsEnabled(sys.Approved["com.squirrel.slack.slack"]));
        var undo = Assert.Single(s.Undos);
        Assert.True((await s.UndoAsync(undo)).Success);
        Assert.Equal(new byte[] { 2, 0, 0, 0 }, sys.Approved["com.squirrel.slack.slack"]);
        Assert.Empty(s.Undos);
        Assert.Contains(events, e => e.StartsWith("Memory suggestion undone"));
    }

    [Fact]
    public async Task Browser_EnableOnlyWhenClosed_UndoRestoresFile()
    {
        var (s, sys, _) = Make(Snap() with { Browsers = [new(BrowserKind.Chrome, true, false, false, true)] });
        await s.ScanAsync();
        var sug = s.Suggestions.Single(x => x.Id == "browser-chrome");
        var act = sug.Actions.Single(a => a.Type == MemoryActionType.EnableBrowserMemorySaver);
        sys.BrowserRunning = true;
        Assert.False((await s.ApplyAsync(sug, act)).Success);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("write:"));
        sys.BrowserRunning = false;
        Assert.True((await s.ApplyAsync(sug, act)).Success);
        Assert.True(BrowserPrefs.ReadMemorySaver(sys.LocalState, BrowserKind.Chrome));
        await s.UndoAsync(s.Undos.Single());
        Assert.Equal(ChromeOff, sys.LocalState);

        // Subsequent Local State changes (e.g. background_mode) are preserved when Memory Saver is undone.
        Assert.True((await s.ApplyAsync(sug, act)).Success);
        sys.LocalState = BrowserBackground.SetBackgroundMode(sys.LocalState, false);
        await s.UndoAsync(s.Undos.Single());
        Assert.False(BrowserPrefs.ReadMemorySaver(sys.LocalState, BrowserKind.Chrome));
        Assert.True(BrowserBackground.TryReadBackgroundMode(sys.LocalState, out var bg) && bg == false);
        Assert.Contains("\"other\":1", sys.LocalState);
    }

    [Fact]
    public async Task Service_StartType_RecordsOriginal_AndUndoRestores()
    {
        var backend = new SvcBackend();
        var (s, sys, _) = Make(Snap() with { Services = [new(Svc("DiagTrack"), 40 * Mb)] }, backend);
        sys.StartTypes["DiagTrack"] = "AutomaticDelayed";
        await s.ScanAsync();
        var sug = s.Suggestions.Single(x => x.Id == "svc-diagtrack");
        var r = await s.ApplyAsync(sug, sug.Actions.Single(a => a.Type == MemoryActionType.SetServiceDisabled));
        Assert.Contains("was AutomaticDelayed", r.Message);
        Assert.Equal("Disabled", sys.StartTypes["DiagTrack"]);
        var undo = s.Undos.Single();
        Assert.Equal("AutomaticDelayed", undo.Previous);
        await s.UndoAsync(undo);
        Assert.Equal("AutomaticDelayed", sys.StartTypes["DiagTrack"]);
        var stop = await s.ApplyAsync(sug, sug.Actions.Single(a => a.Type == MemoryActionType.StopService));
        Assert.True(stop.Success);
        Assert.Contains("stop:DiagTrack", backend.Calls);
    }

    [Fact]
    public async Task Service_Protected_RefusedEvenIfRequested()
    {
        var backend = new SvcBackend();
        var (s, sys, _) = Make(Snap() with { Services = [new(Svc("WinDefend"), 200 * Mb)] }, backend);
        await s.ScanAsync();
        var fake = new MemorySuggestion("x", "x", "", null, SuggestionRisk.High, SuggestionKind.Automated, [],
            [new(MemoryActionType.StopService, "WinDefend", "Stop"), new(MemoryActionType.SetServiceDisabled, "WinDefend", "Disable")]);
        Assert.False((await s.ApplyAsync(fake, fake.Actions[0])).Success);
        Assert.False((await s.ApplyAsync(fake, fake.Actions[1])).Success);
        Assert.Equal("0 MB", MemoryText.Size(0));
        Assert.Equal("< 1 MB", MemoryText.Size(450_000));
        Assert.Equal("1 MB", MemoryText.Size(1L << 20));
        Assert.Empty(backend.Calls);
        Assert.Empty(sys.Calls);
    }
}
