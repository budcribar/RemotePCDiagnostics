using System.Net;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>Undo for removed Store apps: reinstall from the Microsoft Store with a fixed, validated winget command, then verify.</summary>
public class StoreReinstallTests
{
    private const string Ms = AppRemoval.MicrosoftPublisherId;
    private const string Weather = "Microsoft.BingWeather_8wekyb3d8bbwe";
    private const string WeatherId = "9WZDNCRFJ3Q2";
    private const string XblTask = @"\Microsoft\XblGameSave\XblGameSaveTask";

    private sealed class Sys : IMemorySystem
    {
        public List<InstalledAppx> Packages = [];
        public Dictionary<string, int> Reg = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Tasks = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Services = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Family names the signed-in account has (what Get-AppxPackage would find).</summary>
        public HashSet<string> ForUser = new(StringComparer.OrdinalIgnoreCase);
        public List<WingetCommand> Winget = [];
        public WingetResult WingetResult = WingetResult.Exited(0);
        /// <summary>winget reports success but the package doesn't show up.</summary>
        public bool WingetInstallsNothing;
        public bool? CheckFails;

        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), [], Devices: new DeviceFacts(HasPenDigitizer: false), RemovableApps: ReadRemovableApps()));
        public AppRemovalInfo? ReadRemovableApps() => new(Packages.ToList(), [],
            AppRemoval.ContentDeliverySettings.Concat(AppRemoval.XboxSettings).Append(RegistryAllowlist.NarratorWinEnterLaunch)
                .ToDictionary(r => r.Target, r => r.Target.Contains("ContentDeliveryManager") ? (int?)0 : Reg.TryGetValue(r.Target, out var v) ? v : null),
            Tasks.Keys.ToList(), NarratorInUse: false);
        public Task<IReadOnlyList<string>?> RemoveAppxPackagesAsync(IReadOnlyList<RemovableAppx> apps, CancellationToken ct)
        {
            AppRemoval.RemoveScript(apps); // throws for anything off the allowlist
            Packages.RemoveAll(p => apps.Any(a => a.FamilyName == p.FamilyName));
            foreach (var a in apps) ForUser.Remove(a.FamilyName);
            return Task.FromResult<IReadOnlyList<string>?>([]);
        }
        public Task<WingetResult> RunWingetAsync(WingetCommand command, CancellationToken ct)
        {
            Winget.Add(command);
            if (!StoreReinstall.IsAllowedCommand(command)) throw new InvalidOperationException("not allowed");
            if (WingetResult is { Started: true, ExitCode: 0 } && !WingetInstallsNothing)
                ForUser.Add(AppRemoval.Packages.Single(p => p.StoreId == command.StoreId).FamilyName);
            return Task.FromResult(WingetResult);
        }
        public Task<bool?> IsStorePackageInstalledAsync(RemovableAppx app, CancellationToken ct) =>
            Task.FromResult(CheckFails == true ? null : (bool?)ForUser.Contains(app.FamilyName));
        public Task<string?> GetScheduledTaskStateAsync(string path, CancellationToken ct) =>
            Task.FromResult<string?>(Tasks.TryGetValue(path, out var s) ? s : ScheduledTaskAllowlist.Missing);
        public Task<string?> SetScheduledTaskEnabledAsync(string path, bool enabled, CancellationToken ct)
        {
            if (!Tasks.ContainsKey(path)) return Task.FromResult<string?>(ScheduledTaskAllowlist.Missing);
            Tasks[path] = enabled ? "Ready" : "Disabled";
            return Task.FromResult<string?>(Tasks[path]);
        }
        public string GetServiceStartType(string n) => Services.TryGetValue(n, out var t) ? t : throw new InvalidOperationException("Service not found");
        public void SetServiceStartType(string n, string t) => Services[n] = t;
        public int? ReadDword(RegistrySetting s) => Reg.TryGetValue(s.Target, out var v) ? v : null;
        public void WriteDword(RegistrySetting s, int value) => Reg[s.Target] = value;
        public void DeleteDword(RegistrySetting s) => Reg.Remove(s.Target);
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public byte[]? GetStartupApproved(string n) => null;
        public void SetStartupApproved(string n, byte[]? v) { }
        public bool IsBrowserRunning(BrowserKind k) => false;
        public string? ReadBrowserLocalState(BrowserKind k) => null;
        public void WriteBrowserLocalState(BrowserKind k, string json) { }
        public void OpenUri(string uri) { }
    }

    private static InstalledAppx Pkg(string name, string pub = Ms, long? size = 100L << 20) => new(name, pub, ForUser: true, Provisioned: false, size);
    private static Sys With(params string[] names)
    {
        var sys = new Sys { Packages = names.Select(n => Pkg(n)).ToList() };
        foreach (var n in names) sys.ForUser.Add(n + "_" + Ms);
        return sys;
    }
    private static MemorySnapshot Snap(Sys sys) => new(new(16L << 30, 8L << 30), [], Devices: new DeviceFacts(HasPenDigitizer: false), RemovableApps: sys.ReadRemovableApps());
    private static IReadOnlyList<MemorySuggestion> Build(Sys sys) => MemorySuggestionEngine.Build(Snap(sys));
    private static (MemoryChangeJournal, MemorySuggestionService) Make(Sys sys)
    {
        var j = new MemoryChangeJournal();
        return (j, new MemorySuggestionService(sys, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }
    private static UndoService Undo(MemoryChangeJournal j, Sys sys) => new(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys);

    // ---- the allowlist's Store ids ----

    [Fact]
    public void StoreIds_ArePinned_OnlyVerifiedApps_WellFormed()
    {
        var expected = new Dictionary<string, string>
        {
            ["journal"] = "9N318R854RHH", ["clipchamp"] = "9P1J8S7CCWWT", ["power-automate"] = "9NFTCH6J7FHV", ["bing-news"] = "9WZDNCRFHVFW",
            ["bing-weather"] = "9WZDNCRFJ3Q2", ["todo"] = "9NBLGGH5R558", ["feedback-hub"] = "9NBLGGH4R32N", ["solitaire"] = "9WZDNCRFHWD2",
            ["xbox-app"] = "9MV0B5HZVK9Z",
        };
        Assert.Equal(expected.OrderBy(x => x.Key), AppRemoval.Packages.Where(p => p.StoreId is not null).ToDictionary(p => p.Id, p => p.StoreId!).OrderBy(x => x.Key));
        Assert.All(AppRemoval.Packages.Where(p => p.StoreId is not null), p => { Assert.Matches("^[0-9A-Z]{12}$", p.StoreId!); Assert.True(StoreReinstall.CanReinstall(p)); });
        Assert.Equal(expected.Count, expected.Values.Distinct().Count());
        // Retired apps, Narrator add-ons, the Xbox overlays / TCUI / Edge Game Assist and unconfirmed listings stay permanent.
        foreach (var id in new[] { "mail-calendar", "maps", "people", "devhome", "mixed-reality", "get-help", "dropbox-oem", "narrator-word", "narrator-ppt",
                     "narrator-owa", "narrator-excel", "narrator-outlook", "xbox-gamebar", "xbox-overlay", "xbox-speech", "xbox-tcui", "xbox-identity", "xbox-edge-gameassist" })
        {
            Assert.Null(AppRemoval.PackageById(id)!.StoreId);
            Assert.False(StoreReinstall.CanReinstall(AppRemoval.PackageById(id)!));
        }
    }

    [Theory]
    [InlineData("9WZDNCRFJ3Q2", true)]
    [InlineData("9wzdncrfj3q2", false)]
    [InlineData("9WZDNCRFJ3Q", false)]
    [InlineData("9WZDNCRFJ3Q22", false)]
    [InlineData("9WZDNCRFJ3Q2\n", false)]
    [InlineData(" 9WZDNCRFJ3Q2", false)]
    [InlineData("9WZDNCRF;3Q2", false)]
    [InlineData("9WZDNCRFJ3Q-", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IdValidator(string? id, bool ok) => Assert.Equal(ok, StoreReinstall.IsValidId(id));

    // ---- the command ----

    [Fact]
    public void Command_FixedShape_FromTheAllowlist()
    {
        var c = StoreReinstall.CommandFor(Weather)!;
        Assert.Equal(WeatherId, c.StoreId);
        Assert.Equal(["install", "--id", WeatherId, "--source", "msstore", "--accept-package-agreements", "--accept-source-agreements", "--silent", "--disable-interactivity"], c.Arguments);
        Assert.Equal($"winget install --id {WeatherId} --source msstore --accept-package-agreements --accept-source-agreements --silent --disable-interactivity", c.Display);
        Assert.True(StoreReinstall.IsAllowedCommand(c));
        Assert.Equal(WeatherId, StoreReinstall.CommandFor(Weather, WeatherId)!.StoreId);
        Assert.Equal(WeatherId, StoreReinstall.CommandFor("MICROSOFT.BINGWEATHER_8wekyb3d8bbwe")!.StoreId); // family names are case-insensitive
    }

    [Theory]
    [InlineData("microsoft.windowscommunicationsapps_8wekyb3d8bbwe", null)] // on the list, no Store id (retired)
    [InlineData("Microsoft.WindowsStore_8wekyb3d8bbwe", null)]             // never removed, never reinstalled
    [InlineData("Microsoft.BingWeather_aaaaaaaaaaaaa", null)]              // another publisher
    [InlineData("Microsoft.BingWeather", null)]                            // not a family name
    [InlineData("Contoso.App_8wekyb3d8bbwe", WeatherId)]                   // not on the list, even with a real id
    [InlineData(Weather, "9NBLGGH5R558")]                                  // journal's id isn't the allowlist's (To Do's)
    [InlineData(Weather, "9wzdncrfj3q2")]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void Command_Refused_ForAnythingOffTheAllowlist(string? family, string? journaledId) =>
        Assert.Null(StoreReinstall.CommandFor(family, journaledId));

    [Fact]
    public void Validator_RejectsTamperedCommands()
    {
        var args = StoreReinstall.Arguments(WeatherId);
        Assert.True(StoreReinstall.IsAllowedCommand(new(WeatherId, args)));
        Assert.False(StoreReinstall.IsAllowedCommand(null));
        Assert.False(StoreReinstall.IsAllowedCommand(new("9AAAAAAAAAAA", StoreReinstall.Arguments("9AAAAAAAAAAA")))); // well-formed, not on the list
        Assert.False(StoreReinstall.IsAllowedCommand(new("9wzdncrfj3q2", StoreReinstall.Arguments("9wzdncrfj3q2"))));
        Assert.False(StoreReinstall.IsAllowedCommand(new(WeatherId, args.Concat(["--force"]).ToList())));
        Assert.False(StoreReinstall.IsAllowedCommand(new(WeatherId, args.Select(a => a == "msstore" ? "winget" : a).ToList())));
        Assert.False(StoreReinstall.IsAllowedCommand(new(WeatherId, StoreReinstall.Arguments("9NBLGGH5R558"))));       // id and arguments disagree
        Assert.False(StoreReinstall.IsAllowedCommand(new(WeatherId, args.Select(a => a == "install" ? "uninstall" : a).ToList())));
        Assert.False(StoreReinstall.IsAllowedCommand(new(WeatherId, args.Skip(1).ToList())));
        Assert.False(StoreReinstall.IsAllowedCommand(new(WeatherId + "; calc", StoreReinstall.Arguments(WeatherId + "; calc"))));
    }

    [Fact]
    public void WingetPath_OnlyThePlainLocalAppDataAlias()
    {
        Assert.Equal(@"C:\Users\Ann Lee\AppData\Local\Microsoft\WindowsApps\winget.exe", StoreReinstall.WingetPath(@"C:\Users\Ann Lee\AppData\Local"));
        Assert.Equal(@"C:\Users\Ann\AppData\Local\Microsoft\WindowsApps\winget.exe", StoreReinstall.WingetPath(@"C:\Users\Ann\AppData\Local\"));
        foreach (var bad in new[] { null, "", @"AppData\Local", @"\\server\share\Local", @"C:\Users\..\Windows", @"%LOCALAPPDATA%", @"C:\Users\A""nn", "C:/Users/Ann", @"C:\x*" })
            Assert.Null(StoreReinstall.WingetPath(bad));
    }

    [Fact]
    public void CommandLine_QuotesLikeArgumentList()
    {
        var exe = @"C:\Users\Ann Lee\AppData\Local\Microsoft\WindowsApps\winget.exe";
        Assert.Equal($"\"{exe}\" install --id {WeatherId} --source msstore --accept-package-agreements --accept-source-agreements --silent --disable-interactivity",
            StoreReinstall.CommandLine(exe, StoreReinstall.Arguments(WeatherId)));
        Assert.Equal(@"a ""b c"" ""d\""e"" ""f g\\"" """"", StoreReinstall.CommandLine("a", ["b c", "d\"e", @"f g\", ""]));
        Assert.Equal(@"C:\x\winget.exe x\y", StoreReinstall.CommandLine(@"C:\x\winget.exe", [@"x\y"]));
    }

    // ---- verify ----

    [Fact]
    public void VerifyScript_ExactNameAndPublisher_ForTheSignedInUser_AndParsing()
    {
        var weather = AppRemoval.PackageById("bing-weather")!;
        var script = StoreReinstall.VerifyScript(weather, "S-1-5-21-1004336348-1177238915-682003330-1001");
        Assert.Contains("Get-AppxPackage -User 'S-1-5-21-1004336348-1177238915-682003330-1001' -Name 'Microsoft.BingWeather'", script);
        Assert.Contains("$_.PublisherId -eq '8wekyb3d8bbwe'", script);
        Assert.DoesNotContain("-AllUsers", script);
        Assert.Contains("Get-AppxPackage -Name 'Microsoft.BingWeather'", StoreReinstall.VerifyScript(weather, null));
        Assert.Contains("-User 'S-1-12-1-1-2-3-4'", StoreReinstall.VerifyScript(weather, "S-1-12-1-1-2-3-4")); // Microsoft Entra ID account
        Assert.Throws<InvalidOperationException>(() => StoreReinstall.VerifyScript(weather, "S-1-5-18"));
        Assert.Throws<InvalidOperationException>(() => StoreReinstall.VerifyScript(weather, "S-1-5-21-1-2-3-4'; Remove-Item C:\\ -Recurse; '"));
        Assert.Throws<InvalidOperationException>(() => StoreReinstall.VerifyScript(AppRemoval.PackageById("mail-calendar")!, null));
        Assert.Throws<InvalidOperationException>(() => StoreReinstall.VerifyScript(weather with { Name = "Microsoft.WindowsStore" }, null));

        Assert.True(StoreReinstall.ParseInstalled("warning\r\nINSTALLED:1\r\n"));
        Assert.False(StoreReinstall.ParseInstalled("INSTALLED:0"));
        Assert.Null(StoreReinstall.ParseInstalled("INSTALLED:x"));
        Assert.Null(StoreReinstall.ParseInstalled("Get-AppxPackage : Access is denied"));
        Assert.Null(StoreReinstall.ParseInstalled(null));
    }

    [Fact]
    public void Reason_InPlainWords()
    {
        Assert.Equal("winget ended with code 0x8A150014", StoreReinstall.Reason(WingetResult.Exited(unchecked((int)0x8A150014))));
        Assert.Equal("winget ended with code 1", StoreReinstall.Reason(WingetResult.Exited(1)));
        Assert.Equal("it didn't finish in 10 minutes", StoreReinstall.Reason(WingetResult.TimedOut()));
        Assert.Equal("winget isn't here", StoreReinstall.Reason(WingetResult.NotStarted("winget isn't here")));
        Assert.Equal(TimeSpan.FromMinutes(10), StoreReinstall.Timeout);
    }

    // ---- undoability, cards, defaults ----

    [Fact]
    public void Undoability_Reinstall()
    {
        var rec = StoreReinstall.Record(AppRemoval.PackageById("bing-weather")!, 40L << 20, "x");
        Assert.Equal(UndoSupport.Reinstall, Undoability.Of(rec));
        Assert.Equal("undo reinstalls from Store", Undoability.Chip(UndoSupport.Reinstall));
        Assert.Equal(rec.Label, Undoability.Describe(rec));
        Assert.Equal(UndoSupport.None, Undoability.Of(MemoryActionType.RemoveApp)); // by action type: still permanent
        Assert.Equal(UndoSupport.None, Undoability.Of(Undoability.Permanent("appx|x", "removed", "x")));
        Assert.Throws<InvalidOperationException>(() => StoreReinstall.Record(AppRemoval.PackageById("people")!, null, "x"));
    }

    [Fact]
    public void Cards_ReinstallWording_OnlyWithAStoreId_DefaultsAndRiskUnchanged()
    {
        var sys = With("Microsoft.BingWeather", "Microsoft.MicrosoftJournal", "Microsoft.People");
        var list = Build(sys);
        var weather = list.Single(x => x.Id == "remove-app-bing-weather");
        Assert.Equal(UndoSupport.Reinstall, weather.Undo);
        Assert.Equal(AppRemoval.StoreChip, weather.UndoChip);
        Assert.Contains(AppRemoval.StoreUndo, weather.Why);
        Assert.Contains("settings and data aren't restored", weather.Why);
        Assert.DoesNotContain(AppRemoval.StoreGetBack, weather.Why);
        Assert.Contains(AppRemoval.StoreUndo, weather.Actions[0].Confirm);
        Assert.Contains(weather.Steps, s => s.StartsWith("Undo reinstalls it from the Microsoft Store"));
        Assert.False(weather.DefaultOn);
        Assert.Equal(SuggestionRisk.Medium, weather.Risk);
        var journal = list.Single(x => x.Id == "remove-app-journal");
        Assert.True(journal.DefaultOn);
        Assert.Equal(SuggestionRisk.Low, journal.Risk);
        Assert.Equal(UndoSupport.Reinstall, journal.Undo);
        var people = list.Single(x => x.Id == "remove-app-people");
        Assert.Null(people.Undo);
        Assert.Null(people.UndoChip); // retired: may not be in the Store any more, so no "reinstall from Store" chip
        Assert.Contains(AppRemoval.RetiredGetBack, people.Why);
        Assert.DoesNotContain(AppRemoval.StoreGetBack, people.Why);
        Assert.True(people.DefaultOn);

        var fixes = FixCatalog.Build([], list);
        Assert.Equal(UndoSupport.Reinstall, fixes.Single(f => f.SuggestionId == weather.Id).Undo);
        Assert.Equal("undo reinstalls from Store", fixes.Single(f => f.SuggestionId == weather.Id).UndoChip);
        Assert.Equal(UndoSupport.None, fixes.Single(f => f.SuggestionId == people.Id).Undo);
        Assert.Null(fixes.Single(f => f.SuggestionId == people.Id).UndoChip);
        Assert.Equal("can't be undone", Undoability.Chip(fixes.Single(f => f.SuggestionId == people.Id).Undo));
        Assert.True(fixes.Single(f => f.SuggestionId == weather.Id).NeedsAdmin);
    }

    [Fact]
    public void DesktopPrograms_StayPermanent()
    {
        var sys = new Sys();
        var lenovo = new UninstallEntry("HKLM32", "{X}_is1", "Lenovo Now", "Lenovo Group Ltd.", "\"C:\\Program Files (x86)\\Lenovo\\LenovoNow\\unins000.exe\" /SILENT", null, false, 441L << 20);
        var snap = Snap(sys) with { RemovableApps = sys.ReadRemovableApps()! with { Programs = [lenovo] } };
        var card = MemorySuggestionEngine.Build(snap).Single(x => x.Id == "remove-app-lenovo-now");
        Assert.Null(card.Undo);
        Assert.Equal("reinstall from Lenovo", card.UndoChip);
        Assert.Equal(UndoSupport.None, FixCatalog.Build([], [card]).Single().Undo);
    }

    [Fact]
    public async Task MixedRemoval_SomeWithoutStoreId_StaysPermanent()
    {
        var sys = With("Microsoft.GamingApp", "Microsoft.XboxGamingOverlay"); // Xbox app has an id, Game Bar doesn't
        var card = Build(sys).Single(x => x.Id == "remove-xbox");
        Assert.Null(card.Undo);
        Assert.Equal(AppRemoval.StoreManualChip, card.UndoChip);
        Assert.Contains(AppRemoval.StoreGetBackMany, card.Why);
        Assert.Equal(UndoSupport.None, FixCatalog.Build([], [card]).Single().Undo);

        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-xbox");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains(AppRemoval.StoreGetBackMany, r.Message);
        Assert.Equal(2, j.All.Count(c => c.Kind == ChangeKind.NotUndoable));
        Assert.DoesNotContain(j.All, c => c.Kind == ChangeKind.StoreReinstall);
        Assert.Contains("reinstall from the Microsoft Store to get it back", j.All.First(c => c.Kind == ChangeKind.NotUndoable).Label);
        Assert.Null(AppRemoval.Undo.Decode(svc.UndoFor(s.Id)?.Previous).Reinstall); // per-item undo only puts back the settings
    }

    // ---- apply, journal, undo ----

    [Fact]
    public async Task Remove_JournalsFamilyStoreIdAndLabel_UndoAll_Reinstalls_ThenVerifies()
    {
        var sys = With("Microsoft.BingWeather");
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-app-bing-weather");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains(AppRemoval.StoreUndo, r.Message);
        var c = Assert.Single(j.All);
        Assert.Equal(ChangeKind.StoreReinstall, c.Kind);
        Assert.Equal(Weather, c.Target);
        Assert.Equal(WeatherId, c.Previous);
        Assert.Equal("Weather removed (Microsoft.BingWeather, 100 MB) — undo reinstalls it from the Microsoft Store for the signed-in account; its settings and data aren't restored", c.Label);

        var all = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal((1, 0, 0), (all.Succeeded, all.Failed, all.Skipped));
        Assert.Contains("reinstalled from the Microsoft Store", all.Items[0].Message);
        Assert.Equal(StoreReinstall.Arguments(WeatherId), Assert.Single(sys.Winget).Arguments);
        Assert.Contains(Weather, sys.ForUser);
        Assert.Empty(j.All);
    }

    [Theory]
    [InlineData("exit")]      // winget failed (no internet, Store blocked)
    [InlineData("missing")]   // winget isn't installed
    [InlineData("timeout")]
    [InlineData("notback")]   // exit 0, but Get-AppxPackage doesn't find it
    [InlineData("unknown")]   // the check couldn't run
    public async Task UndoAll_ReinstallFails_ClearMessage_EntryKeptForRetry(string how)
    {
        var sys = With("Microsoft.BingWeather");
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-app-bing-weather");
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        sys.WingetResult = how switch
        {
            "exit" => WingetResult.Exited(unchecked((int)0x8A15005E)),
            "missing" => WingetResult.NotStarted("winget (App Installer) isn't installed for the signed-in account"),
            "timeout" => WingetResult.TimedOut(),
            _ => WingetResult.Exited(0),
        };
        sys.WingetInstallsNothing = how == "notback";
        if (how == "unknown") { sys.CheckFails = true; }

        var all = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal((0, 1, 0), (all.Succeeded, all.Failed, all.Skipped));
        Assert.StartsWith("Couldn't reinstall Weather automatically — reinstall it from the Microsoft Store.", all.Items[0].Message);
        Assert.Equal(ChangeKind.StoreReinstall, Assert.Single(j.All).Kind); // still undoable: try again later

        sys.WingetResult = WingetResult.Exited(0); sys.WingetInstallsNothing = false; sys.CheckFails = null;
        var retry = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal(1, retry.Succeeded);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Undo_AlreadyInstalled_Succeeds_WithoutWinget()
    {
        var j = new MemoryChangeJournal();
        j.Add(StoreReinstall.Record(AppRemoval.PackageById("bing-weather")!, null, "x"));
        var sys = new Sys { ForUser = { Weather } };
        var all = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal(1, all.Succeeded);
        Assert.Empty(sys.Winget);
        Assert.Contains("already installed", all.Items[0].Message);
    }

    [Theory]
    [InlineData("Microsoft.WindowsStore_8wekyb3d8bbwe", "9WZDNCRFJBMP")]       // never removed / reinstalled
    [InlineData("Contoso.Evil_8wekyb3d8bbwe", WeatherId)]                       // not on the list
    [InlineData(Weather, "9NBLGGH5R558")]                                        // id swapped in the journal file
    [InlineData("microsoft.windowscommunicationsapps_8wekyb3d8bbwe", "9WZDNCRFHVQM")] // on the list without a verified id
    public async Task Undo_RefusesJournalEntriesOffTheAllowlist(string family, string id)
    {
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.StoreReinstall, family, id, "tampered", "x"));
        var sys = new Sys();
        var all = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal(1, all.Failed);
        Assert.Empty(sys.Winget);
        Assert.Contains("isn't one this app reinstalls", all.Items[0].Message);
    }

    [Fact]
    public async Task PerItemUndo_Reinstalls_AndClearsTheJournal()
    {
        var sys = With("Microsoft.Todos");
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-app-todo");
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        var u = svc.UndoFor(s.Id)!;
        sys.WingetResult = WingetResult.Exited(1);
        var failed = await svc.UndoAsync(u);
        Assert.False(failed.Success);
        Assert.StartsWith("Couldn't reinstall Microsoft To Do automatically — reinstall it from the Microsoft Store.", failed.Message);
        Assert.Single(j.All);
        Assert.NotNull(svc.UndoFor(s.Id)); // can try again

        sys.WingetResult = WingetResult.Exited(0);
        var ok = await svc.UndoAsync(svc.UndoFor(s.Id)!);
        Assert.True(ok.Success, ok.Message);
        Assert.Contains("Microsoft To Do reinstalled", ok.Message);
        Assert.Empty(j.All);
        Assert.Equal(2, sys.Winget.Count);
    }

    [Fact]
    public async Task Xbox_AllWithStoreIds_ReinstallsAppsAndRestoresSettings()
    {
        var sys = With("Microsoft.GamingApp");
        sys.Services["XblGameSave"] = "Automatic";
        sys.Tasks[XblTask] = "Ready";
        sys.Reg[RegistryAllowlist.GameDvrEnabled.Target] = 1;
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-xbox");
        Assert.Equal(UndoSupport.Reinstall, s.Undo);
        Assert.Contains(AppRemoval.StoreUndoMany, s.Why);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Equal("Microsoft.GamingApp_8wekyb3d8bbwe", j.All.Single(c => c.Kind == ChangeKind.StoreReinstall).Target);

        var undone = await svc.UndoAsync(svc.UndoFor(s.Id)!);
        Assert.True(undone.Success, undone.Message);
        Assert.Contains("Xbox app reinstalled", undone.Message);
        Assert.Equal(1, sys.Reg[RegistryAllowlist.GameDvrEnabled.Target]);
        Assert.Equal("Automatic", sys.Services["XblGameSave"]);
        Assert.Equal("Ready", sys.Tasks[XblTask]);
        Assert.Empty(j.All);
    }

    [Fact]
    public void Journal_RoundTrip_KeepsWhatReinstallNeeds()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpd-store-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "changes.json");
        try
        {
            var rec = StoreReinstall.Record(AppRemoval.PackageById("clipchamp")!, 2980L << 20, "Remote technician");
            new FileChangeJournal(path).Add(rec);
            Assert.Contains("\"StoreReinstall\"", File.ReadAllText(path));
            var back = Assert.Single(new FileChangeJournal(path).All);
            Assert.Equal(rec, back);
            Assert.Equal("Clipchamp.Clipchamp_yxz26nhyzhsrt", back.Target);
            Assert.Equal("9P1J8S7CCWWT", back.Previous);
            Assert.Equal("9P1J8S7CCWWT", StoreReinstall.CommandFor(back.Target, back.Previous)!.StoreId);
            Assert.Equal(UndoSupport.Reinstall, Undoability.Of(back));

            var undo = new AppRemoval.Undo([], [], [], [rec.Target]);
            Assert.Equal(new[] { rec.Target }, AppRemoval.Undo.Decode(undo.Encode()).Reinstall!);
            Assert.Null(AppRemoval.Undo.Decode("""{"Registry":[],"Services":[],"Tasks":["\\x"]}""").Reinstall); // saved before this change
        }
        finally { try { Directory.Delete(dir, true); } catch (IOException) { } }
    }

    // ---- step-8 report ----

    private static string E(string s) => WebUtility.HtmlEncode(s);

    [Fact]
    public void Report_ListsReinstallUndoable_NotPermanent_AndSaysSettingsArentRestored()
    {
        var weather = StoreReinstall.Record(AppRemoval.PackageById("bing-weather")!, 40L << 20, "x");
        var mail = Undoability.Permanent("appx|mail", AppRemoval.RemovedLabel(AppRemoval.PackageById("mail-calendar")!, 206L << 20), "x");
        var fixes = new List<WorkflowFix>
        {
            new("w", "Remove Weather", "", AppRemoval.Category, SuggestionRisk.Medium, FixSource.Memory, 15, Undo: UndoSupport.Reinstall, UndoChip: AppRemoval.StoreChip),
            new("m", "Remove Mail and Calendar", "", AppRemoval.Category, SuggestionRisk.Low, FixSource.Memory, 15, Undo: UndoSupport.None, UndoChip: AppRemoval.StoreManualChip),
        };
        var s = new WorkflowState
        {
            Fixes = fixes, Approved = ["w", "m"], ChangesTracked = true,
            Outcomes =
            [
                new("w", "Remove Weather", true, "Weather removed.", Changes: [new(weather.Id, Undoability.Describe(weather), Undoability.Of(weather))]),
                new("m", "Remove Mail and Calendar", true, "Mail removed.", Changes: [new(mail.Id, Undoability.Describe(mail), Undoability.Of(mail))]),
            ],
        };
        var html = ClientReport.Build(s, null, null, BenchmarkComparison.Build(null, null), DateTimeOffset.Now);
        // Fixed report wording is written as is; journal labels are HTML-encoded.
        var reinstallHeading = "Removed apps that undo reinstalls from the Microsoft Store (for the account signed in at the time; needs internet). Their settings and data aren't restored:";
        var permanentHeading = "Permanent (can't be undone";
        Assert.Contains(reinstallHeading, html);
        Assert.Contains(permanentHeading, html);
        var reinstallAt = html.IndexOf(reinstallHeading, StringComparison.Ordinal);
        var permanentAt = html.IndexOf(permanentHeading, StringComparison.Ordinal);
        var weatherLine = "<li>" + E(weather.Label) + "</li>";
        var mailLine = "<li>" + E(mail.Label) + "</li>";
        Assert.InRange(html.IndexOf(weatherLine, reinstallAt, StringComparison.Ordinal), reinstallAt, permanentAt);    // under reinstall, not permanent
        Assert.True(html.IndexOf(mailLine, permanentAt, StringComparison.Ordinal) > permanentAt);
        Assert.Contains("(undo reinstalls it from the Microsoft Store; settings and data aren't restored)", html);
        Assert.Contains("reinstalled from the Microsoft Store by hand", html);

        // No journal to read: go by the fix.
        var untracked = new WorkflowState { Fixes = fixes, Approved = ["w"], Outcomes = [new("w", "Remove Weather", true, "Weather removed.")] };
        var html2 = ClientReport.Build(untracked, null, null, BenchmarkComparison.Build(null, null), DateTimeOffset.Now);
        Assert.Contains("Undo: undo reinstalls it from the Microsoft Store (needs internet); its settings and data aren't restored.", html2);
        Assert.Contains(reinstallHeading, html2);
        Assert.DoesNotContain(permanentHeading, html2);
    }

    [Fact]
    public async Task Workflow_RecordsTheReinstallChange_AndTheReportListsIt()
    {
        var sys = With("Microsoft.BingWeather");
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-app-bing-weather");
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        var c = Assert.Single(j.All);
        var change = new FixChange(c.Id, Undoability.Describe(c), Undoability.Of(c));
        Assert.Equal(UndoSupport.Reinstall, change.Undo);
        var state = new WorkflowState
        {
            Fixes = FixCatalog.Build([], Build(With("Microsoft.BingWeather"))), ChangesTracked = true,
            Outcomes = [new(FixCatalog.MemoryId(s.Id, MemoryActionType.RemoveApp, "bing-weather"), s.Title, true, "ok", Changes: [change])],
        };
        var html = ClientReport.Build(state, null, null, BenchmarkComparison.Build(null, null), DateTimeOffset.Now);
        Assert.Contains(E(Undoability.Describe(c)), html);
        Assert.Contains("Removed apps that undo reinstalls from the Microsoft Store", html);
        Assert.DoesNotContain("Permanent (can't be undone", html);
    }
}
