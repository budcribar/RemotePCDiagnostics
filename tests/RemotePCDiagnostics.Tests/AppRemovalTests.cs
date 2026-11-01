using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>#3 / #8 / #10 app removal: the allowlist, when each app is offered, permanent removal journaling, the reversible parts and undo.</summary>
public class AppRemovalTests
{
    private const string Ms = AppRemoval.MicrosoftPublisherId;
    private const string LenovoUninstaller = @"C:\Program Files (x86)\Lenovo\LenovoNow\unins000.exe";
    private const string PowerEngageCode = "{3CE8B8E8-B33B-453C-BB7A-821ED6E18A24}";
    private const string XblTask = @"\Microsoft\XblGameSave\XblGameSaveTask";

    private static UninstallEntry LenovoNow(string? quiet = "\"" + LenovoUninstaller + "\" /SILENT", string publisher = "Lenovo Group Ltd.") =>
        new("HKLM32", "{D2C4D3E1-6B5E-4F6C-9C0D-LenovoNow}_is1", "Lenovo Now", publisher, quiet, "\"" + LenovoUninstaller + "\"", false, 441L << 20, "4.8.0.54");

    private static UninstallEntry PowerEngage() =>
        new("HKLM32", PowerEngageCode, "Brother PowerENGAGE", "Brother Industries, Ltd.", null, "MsiExec.exe /I" + PowerEngageCode, true, 2L << 20, "1.0.27");

    private sealed class Sys : IMemorySystem
    {
        public Dictionary<string, int> Reg = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase);
        public List<InstalledAppx> Packages = [];
        public List<UninstallEntry> Programs = [];
        public Dictionary<string, string> Tasks = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Services = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Family names that stay installed after Remove-AppxPackage (protected / in use).</summary>
        public HashSet<string> Stubborn = new(StringComparer.OrdinalIgnoreCase);
        public bool RemoveScriptFails;
        public bool UninstallerDoesNothing;
        public bool? HasPen = false;
        public List<string> Calls = [];

        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), [], Devices: new DeviceFacts(HasPenDigitizer: HasPen), RemovableApps: ReadRemovableApps()));
        public bool? NarratorInUse = false;
        public AppRemovalInfo? ReadRemovableApps() => new(Packages.ToList(), Programs.ToList(),
            AppRemoval.ContentDeliverySettings.Concat(AppRemoval.XboxSettings).Append(RegistryAllowlist.NarratorWinEnterLaunch)
                .ToDictionary(r => r.Target, r => Reg.TryGetValue(r.Target, out var v) ? (int?)v : null),
            Tasks.Keys.ToList(), NarratorInUse);
        public Task<IReadOnlyList<string>?> RemoveAppxPackagesAsync(IReadOnlyList<RemovableAppx> apps, CancellationToken ct)
        {
            Calls.Add("appx:" + string.Join(",", apps.Select(a => a.FamilyName)));
            if (RemoveScriptFails) return Task.FromResult<IReadOnlyList<string>?>(null);
            AppRemoval.RemoveScript(apps); // throws for anything off the allowlist
            Packages.RemoveAll(p => apps.Any(a => a.FamilyName == p.FamilyName) && !Stubborn.Contains(p.FamilyName));
            return Task.FromResult<IReadOnlyList<string>?>(apps.Where(a => Packages.Any(p => p.FamilyName == a.FamilyName)).Select(a => a.FamilyName).ToList());
        }
        public Task<ActionOutcome> RunUninstallerAsync(UninstallCommand c, CancellationToken ct)
        {
            Calls.Add("uninstall:" + c.Display);
            if (!AppRemoval.IsAllowedCommand(c)) return Task.FromResult(new ActionOutcome(false, "refused"));
            if (!UninstallerDoesNothing)
                Programs.RemoveAll(p => c.Msi ? p.KeyName == c.Path : p.UninstallString?.Contains(c.Path) == true);
            return Task.FromResult(new ActionOutcome(true, "Uninstalled."));
        }
        public Task<string?> GetScheduledTaskStateAsync(string path, CancellationToken ct) =>
            Task.FromResult<string?>(Tasks.TryGetValue(path, out var s) ? s : ScheduledTaskAllowlist.Missing);
        public Task<string?> SetScheduledTaskEnabledAsync(string path, bool enabled, CancellationToken ct)
        {
            Calls.Add($"task:{path}={enabled}");
            if (!ScheduledTaskAllowlist.IsAllowed(path)) throw new InvalidOperationException("not allowed");
            if (!Tasks.ContainsKey(path)) return Task.FromResult<string?>(ScheduledTaskAllowlist.Missing);
            Tasks[path] = enabled ? "Ready" : "Disabled";
            return Task.FromResult<string?>(Tasks[path]);
        }
        public string GetServiceStartType(string n) => Services.TryGetValue(n, out var t) ? t : throw new InvalidOperationException("Service not found");
        public void SetServiceStartType(string n, string t) { Calls.Add($"svc:{n}={t}"); Services[n] = t; }
        public int? ReadDword(RegistrySetting s) => Reg.TryGetValue(s.Target, out var v) ? v : null;
        public void WriteDword(RegistrySetting s, int value) { Calls.Add($"write:{s.Target}={value}"); if (!Ignored.Contains(s.Target)) Reg[s.Target] = value; }
        public void DeleteDword(RegistrySetting s) { Calls.Add("delete:" + s.Target); Reg.Remove(s.Target); }
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

    private static InstalledAppx Pkg(string name, string pub = Ms, long? size = 100L << 20, bool user = true, bool prov = false) => new(name, pub, user, prov, size);

    private static MemorySnapshot Snap(Sys sys) => new(new(16L << 30, 8L << 30), [], Devices: new DeviceFacts(HasPenDigitizer: sys.HasPen), RemovableApps: sys.ReadRemovableApps());

    private static IReadOnlyList<MemorySuggestion> Build(Sys sys) => MemorySuggestionEngine.Build(Snap(sys));

    private static (MemoryChangeJournal, MemorySuggestionService) Make(Sys sys)
    {
        var j = new MemoryChangeJournal();
        return (j, new MemorySuggestionService(sys, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }

    private static void AllCdmOff(Sys sys) { foreach (var r in AppRemoval.ContentDeliverySettings) sys.Reg[r.Target] = 0; }

    // ---- allowlist ----

    [Fact]
    public void Allowlist_ExactFamilyNames_NothingProtected()
    {
        var expected = new[]
        {
            "microsoft.windowscommunicationsapps_8wekyb3d8bbwe", "Microsoft.WindowsMaps_8wekyb3d8bbwe", "Microsoft.People_8wekyb3d8bbwe",
            "Microsoft.Windows.DevHome_8wekyb3d8bbwe", "Microsoft.MixedReality.Portal_8wekyb3d8bbwe", "Microsoft.MicrosoftJournal_8wekyb3d8bbwe",
            "Clipchamp.Clipchamp_yxz26nhyzhsrt", "Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe", "Microsoft.BingNews_8wekyb3d8bbwe",
            "Microsoft.BingWeather_8wekyb3d8bbwe", "Microsoft.Todos_8wekyb3d8bbwe", "Microsoft.GetHelp_8wekyb3d8bbwe", "Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe",
            "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe", "C27EB4BA.DropboxOEM_xbfy0k16fey96",
            "MicrosoftWindows.NarratorExtension-Word_cw5n1h2txyewy", "MicrosoftWindows.NarratorExtension-ppt_cw5n1h2txyewy",
            "MicrosoftWindows.NarratorExtension-OutlookWebApp_cw5n1h2txyewy", "MicrosoftWindows.NarratorScript.Excel_cw5n1h2txyewy",
            "MicrosoftWindows.NarratorScript.Outlook_cw5n1h2txyewy", "Microsoft.GamingApp_8wekyb3d8bbwe", "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe",
            "Microsoft.XboxGameOverlay_8wekyb3d8bbwe", "Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe", "Microsoft.Xbox.TCUI_8wekyb3d8bbwe",
            "Microsoft.XboxIdentityProvider_8wekyb3d8bbwe", "Microsoft.Edge.GameAssist_8wekyb3d8bbwe",
        };
        Assert.Equal(expected, AppRemoval.Packages.Select(p => p.FamilyName));
        Assert.Equal(AppRemoval.Packages.Count, AppRemoval.Packages.Select(p => p.Id).Distinct().Count());
        Assert.DoesNotContain(AppRemoval.Packages, p => AppRemoval.NeverRemove.Contains(p.Name));
        foreach (var never in new[] { "Microsoft.WindowsStore", "Microsoft.Windows.Photos", "Microsoft.WindowsCalculator", "Microsoft.WindowsNotepad",
                     "Microsoft.WindowsTerminal", "Microsoft.MicrosoftEdge.Stable", "Microsoft.DesktopAppInstaller", "Microsoft.HEVCVideoExtension" })
        {
            Assert.Contains(never, AppRemoval.NeverRemove);
            Assert.Null(AppRemoval.FindPackage(never, Ms));
        }
        Assert.Equal("xbfy0k16fey96", AppRemoval.Packages.Single(p => p.Name.Contains("Dropbox")).PublisherId); // seen on a real PC (BUDSLAPTOP)
        // Same name, another publisher: not ours.
        Assert.Null(AppRemoval.FindPackage("Microsoft.BingNews", "aaaaaaaaaaaaa"));
        Assert.NotNull(AppRemoval.FindPackage("MICROSOFT.BINGNEWS", Ms));
        Assert.Equal(("Microsoft.BingNews", Ms), AppRemoval.ParseFullName("Microsoft.BingNews_4.1.24002.0_x64__8wekyb3d8bbwe")!.Value);
        Assert.Null(AppRemoval.ParseFullName("Microsoft.BingNews_8wekyb3d8bbwe"));
    }

    [Fact]
    public void RemoveScript_OnlyAllowlisted_RemovesForAllUsersAndProvisioned_ReadsBack()
    {
        var news = AppRemoval.PackageById("bing-news")!;
        var script = AppRemoval.RemoveScript([news]);
        Assert.Contains("'Microsoft.BingNews|8wekyb3d8bbwe'", script);
        Assert.Contains("Remove-AppxPackage -Package $_.PackageFullName -AllUsers", script);
        Assert.Contains("Remove-AppxProvisionedPackage -Online", script);
        Assert.EndsWith("'LEFT:'+($left -join ',')", script);
        Assert.Throws<InvalidOperationException>(() => AppRemoval.RemoveScript([new RemovableAppx("store", "Microsoft.WindowsStore", Ms, "Store", AppGroup.Consumer, "", "")]));
        Assert.Throws<InvalidOperationException>(() => AppRemoval.RemoveScript([news with { PublisherId = "x'; Remove-Item C:\\ -Recurse; '" }]));
        Assert.Equal(["Microsoft.BingNews_8wekyb3d8bbwe"], AppRemoval.ParseLeft("warning\r\nLEFT:Microsoft.BingNews_8wekyb3d8bbwe\r\n"));
        Assert.Empty(AppRemoval.ParseLeft("LEFT:")!);
        Assert.Null(AppRemoval.ParseLeft("error"));
    }

    // ---- offered / not offered, defaults ----

    [Fact]
    public void RetiredApps_Ticked_ConsumerApps_OptIn_OneCardEach_WithSizeAndCantBeUndone()
    {
        var sys = new Sys { Packages = [Pkg("microsoft.windowscommunicationsapps", size: 206L << 20), Pkg("Microsoft.WindowsMaps", user: false, prov: true), Pkg("Clipchamp.Clipchamp", "yxz26nhyzhsrt", 2980L << 20)] };
        AllCdmOff(sys);
        var list = Build(sys);
        var mail = list.Single(x => x.Id == "remove-app-mail-calendar");
        Assert.True(mail.DefaultOn);
        Assert.Equal(MemoryActionType.RemoveApp, Assert.Single(mail.Actions).Type);
        Assert.Equal("mail-calendar", mail.Actions[0].Target);
        Assert.Contains("206 MB", mail.Why);
        Assert.Contains("can't be undone — reinstall from the Microsoft Store if needed", mail.Why);
        Assert.Contains("can't be undone", mail.Actions[0].Confirm);
        Assert.Contains("Frees about 206 MB", string.Join(" ", mail.Steps));
        Assert.True(list.Single(x => x.Id == "remove-app-maps").DefaultOn); // provisioned only still counts
        var clip = list.Single(x => x.Id == "remove-app-clipchamp");
        Assert.False(clip.DefaultOn);
        Assert.Contains("2.9 GB", clip.Why);
        Assert.Equal(SuggestionRisk.Medium, clip.Risk);
        Assert.DoesNotContain(list, x => x.Id == "stop-silent-app-installs"); // all already 0
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(null, false)] // unknown: not offered
    public void Journal_OnlyWhenNoPen(bool? pen, bool offered)
    {
        var sys = new Sys { HasPen = pen, Packages = [Pkg("Microsoft.MicrosoftJournal")] };
        var s = Build(sys).SingleOrDefault(x => x.Id == "remove-app-journal");
        Assert.Equal(offered, s is not null);
        if (s is not null) Assert.True(s.DefaultOn);
    }

    [Fact]
    public void NothingOffered_WhenUnreadable_OrNotOnTheList_OrOtherPublisher()
    {
        Assert.DoesNotContain(MemorySuggestionEngine.Build(new(new(16L << 30, 8L << 30), [])), x => x.Category == AppRemoval.Category);
        var sys = new Sys { Packages = [Pkg("Microsoft.WindowsStore"), Pkg("Microsoft.Windows.Photos"), Pkg("Microsoft.BingNews", "aaaaaaaaaaaaa"), Pkg("Microsoft.WindowsMaps", user: false, prov: false)] };
        AllCdmOff(sys);
        Assert.DoesNotContain(Build(sys), x => x.Category == AppRemoval.Category);
    }

    [Fact]
    public void Xbox_OneOptInCard_ForTheWholeGroup()
    {
        var sys = new Sys { Packages = [Pkg("Microsoft.GamingApp", size: 300L << 20), Pkg("Microsoft.XboxGamingOverlay", size: 34L << 20), Pkg("Microsoft.Xbox.TCUI", size: null)] };
        var list = Build(sys);
        var x = list.Single(s => s.Id == "remove-xbox");
        Assert.False(x.DefaultOn);
        Assert.Equal(MemoryActionType.RemoveXboxApps, Assert.Single(x.Actions).Type);
        Assert.Contains("3 Xbox apps", x.Why);
        Assert.Contains("334 MB", x.Why);
        Assert.Contains("can't be undone — reinstall from the Microsoft Store if needed", x.Why);
        Assert.DoesNotContain(list, s => s.Id.StartsWith("remove-app-xbox"));
    }

    private const string Win = AppRemoval.WindowsPublisherId;
    private static readonly string[] NarratorPackages =
    [
        "MicrosoftWindows.NarratorExtension-Word", "MicrosoftWindows.NarratorExtension-ppt", "MicrosoftWindows.NarratorExtension-OutlookWebApp",
        "MicrosoftWindows.NarratorScript.Excel", "MicrosoftWindows.NarratorScript.Outlook",
    ];
    private static Sys NarratorPc() { var sys = new Sys { Packages = NarratorPackages.Select(n => Pkg(n, Win, 2L << 20, user: true, prov: true)).ToList() }; AllCdmOff(sys); return sys; }

    [Fact]
    public void Narrator_OneTickedCard_OnlyWhenNarratorIsntUsed()
    {
        var card = Build(NarratorPc()).Single(x => x.Id == "remove-narrator-addons");
        Assert.True(card.DefaultOn);
        Assert.Equal(MemoryActionType.RemoveNarratorAddons, Assert.Single(card.Actions).Type);
        Assert.Contains("5 add-ons", card.Why);
        Assert.Contains("10 MB", card.Why);
        Assert.Contains(card.Steps, x => x.Contains("Win+Ctrl+Enter"));
        Assert.DoesNotContain(Build(NarratorPc()), x => x.Id.StartsWith("remove-app-narrator"));

        var inUse = NarratorPc(); inUse.NarratorInUse = true;
        Assert.DoesNotContain(Build(inUse), x => x.Id == "remove-narrator-addons");
        var unknown = NarratorPc(); unknown.NarratorInUse = null;
        Assert.DoesNotContain(Build(unknown), x => x.Id == "remove-narrator-addons");
        var running = NarratorPc();
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(running) with { Apps = [new("Narrator", 1, 20L << 20, HasWindow: true)] }), x => x.Id == "remove-narrator-addons");
        // Same names from another publisher are never matched.
        Assert.DoesNotContain(Build(new Sys { Packages = NarratorPackages.Select(n => Pkg(n, Ms)).ToList() }), x => x.Id == "remove-narrator-addons");
    }

    [Fact]
    public async Task Narrator_RemovesAddons_Permanent_ShortcutOff_UndoRestoresShortcutOnly()
    {
        var sys = NarratorPc();
        sys.Stubborn.Add("MicrosoftWindows.NarratorScript.Outlook_" + Win);
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var card = svc.Suggestions.Single(x => x.Id == "remove-narrator-addons");
        var r = await svc.ApplyAsync(card, card.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("1 add-on couldn't be removed (Narrator for Outlook)", r.Message);
        Assert.Equal(4, j.All.Count(c => c.Kind == ChangeKind.NotUndoable));
        Assert.Equal(0, sys.Reg[RegistryAllowlist.NarratorWinEnterLaunch.Target]);
        Assert.Single(j.All, c => c.Kind == ChangeKind.RegistryValue && c.Target == RegistryAllowlist.NarratorWinEnterLaunch.Target && c.Previous == null);

        Assert.True((await svc.UndoAsync(svc.UndoFor("remove-narrator-addons")!)).Success);
        Assert.False(sys.Reg.ContainsKey(RegistryAllowlist.NarratorWinEnterLaunch.Target)); // was absent: deleted
        Assert.Equal(4, j.All.Count(c => c.Kind == ChangeKind.NotUndoable)); // the add-ons stay removed
        Assert.DoesNotContain(sys.Packages, p => p.Name == "MicrosoftWindows.NarratorExtension-Word");
    }

    [Fact]
    public void Narrator_InWorkflow_TickedAdminPermanent_AndDropboxOemOptIn()
    {
        var sys = NarratorPc();
        sys.Packages.Add(Pkg("C27EB4BA.DropboxOEM", "xbfy0k16fey96", 60L << 20));
        var fixes = FixCatalog.Build([], Build(sys));
        var n = fixes.Single(f => f.MemoryAction == MemoryActionType.RemoveNarratorAddons);
        Assert.True(n.DefaultOn);
        Assert.True(n.NeedsAdmin);
        Assert.Equal(UndoSupport.None, n.Undo);
        Assert.False(fixes.Single(f => f.SuggestionId == "remove-app-dropbox-oem").DefaultOn);
        Assert.Contains(MemoryActionType.RemoveNarratorAddons, FixCatalog.UnattendedMemoryActions);
    }

    [Fact]
    public void EdgeGameAssist_IsPartOfTheOptInXboxGroup_NotEdge()
    {
        var sys = new Sys { Packages = [Pkg("Microsoft.Edge.GameAssist", size: 3L << 20), Pkg("Microsoft.MicrosoftEdge.Stable", size: 400L << 20)] };
        AllCdmOff(sys);
        var list = Build(sys);
        var x = list.Single(s => s.Id == "remove-xbox");
        Assert.False(x.DefaultOn);
        Assert.Contains("Edge Game Assist", x.Why);
        Assert.DoesNotContain(list, s => s.Id == "remove-app-xbox-edge-gameassist");
        Assert.Null(AppRemoval.FindPackage("Microsoft.MicrosoftEdge.Stable", Ms)); // Edge itself is never removed
    }

    [Fact]
    public void VendorPrograms_Ticked_OnlyWithTheirOwnUninstaller()
    {
        var sys = new Sys { Programs = [LenovoNow(), PowerEngage()], Tasks = { [@"\Lenovo\LenovoNowTask"] = "Ready", [@"\PowerENGAGE"] = "Ready" } };
        AllCdmOff(sys);
        var list = Build(sys);
        var lenovo = list.Single(x => x.Id == "remove-app-lenovo-now");
        Assert.True(lenovo.DefaultOn);
        Assert.Contains("441 MB", lenovo.Why);
        Assert.Contains("reinstall from Lenovo if needed", lenovo.Why);
        Assert.Contains($"\"{LenovoUninstaller}\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART", lenovo.Steps[0]); // our arguments, not the registry's
        Assert.Contains(@"\Lenovo\LenovoNowTask", lenovo.Steps[0]);
        var pe = list.Single(x => x.Id == "remove-app-powerengage");
        Assert.Contains($"msiexec.exe /x {PowerEngageCode} /qn /norestart", pe.Steps[0]);
        Assert.Contains(@"\PowerENGAGE", pe.Steps[0]);

        // Not the vendor's uninstaller under Program Files, or another publisher: not offered.
        foreach (var bad in new[]
        {
            LenovoNow(quiet: @"""C:\Users\x\AppData\Local\Temp\unins000.exe"" /SILENT") with { UninstallString = null },
            LenovoNow(quiet: @"""C:\Program Files (x86)\Lenovo\LenovoNow\..\..\..\Windows\System32\cmd.exe"" /c del") with { UninstallString = null },
            LenovoNow(quiet: @"""C:\Program Files (x86)\Lenovo\LenovoNow\setup.exe"" /S") with { UninstallString = null },
            LenovoNow(quiet: @"""\\server\share\Lenovo\unins000.exe"" /SILENT") with { UninstallString = null },
            LenovoNow(publisher: "Someone Else"),
        })
            Assert.DoesNotContain(Build(new Sys { Programs = [bad] }), x => x.Id == "remove-app-lenovo-now");
        Assert.DoesNotContain(Build(new Sys { Programs = [PowerEngage() with { KeyName = "PowerENGAGE" }] }), x => x.Id == "remove-app-powerengage"); // MSI without a product code key
    }

    [Fact]
    public void Commands_OnlyAllowlistedOnes()
    {
        Assert.True(AppRemoval.IsAllowedCommand(new(false, LenovoUninstaller, ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"])));
        Assert.False(AppRemoval.IsAllowedCommand(new(false, LenovoUninstaller, ["/VERYSILENT", "& calc"])));
        Assert.False(AppRemoval.IsAllowedCommand(new(false, @"C:\Windows\System32\cmd.exe", ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"])));
        Assert.True(AppRemoval.IsAllowedCommand(new(true, PowerEngageCode, ["/x", PowerEngageCode, "/qn", "/norestart"])));
        Assert.False(AppRemoval.IsAllowedCommand(new(true, PowerEngageCode, ["/i", PowerEngageCode, "/qn"])));
        Assert.False(AppRemoval.IsAllowedCommand(new(true, "notaguid", ["/x", "notaguid", "/qn", "/norestart"])));
        Assert.True(ScheduledTaskAllowlist.IsAllowed(XblTask));
        Assert.True(ScheduledTaskAllowlist.IsAllowed(@"\Lenovo\LenovoNowDailyTask"));
        Assert.False(ScheduledTaskAllowlist.IsAllowed(@"\Lenovo\ImController\Plugin"));
        Assert.False(ScheduledTaskAllowlist.IsAllowed(@"\Microsoft\Windows\Defrag\ScheduledDefrag"));
        Assert.False(ScheduledTaskAllowlist.IsAllowed(@"\Lenovo\LenovoNow'; Remove-Item x; '"));
        Assert.Contains("-TaskPath '\\Microsoft\\XblGameSave\\' -TaskName 'XblGameSaveTask'", ScheduledTaskAllowlist.SetScript(XblTask, false));
        Assert.Throws<InvalidOperationException>(() => ScheduledTaskAllowlist.SetScript(@"\Microsoft\Windows\Defrag\ScheduledDefrag", false));
    }

    // ---- apply + journal ----

    [Fact]
    public async Task RemoveStoreApp_JournalsNotUndoable_WithNameAndSize()
    {
        var sys = new Sys { Packages = [Pkg("microsoft.windowscommunicationsapps", size: 206L << 20, prov: true)] };
        AllCdmOff(sys);
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-app-mail-calendar");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("Mail and Calendar removed for every account", r.Message);
        Assert.Contains("Freed about 206 MB", r.Message);
        Assert.Contains("can't be undone", r.Message);
        Assert.Equal(["appx:microsoft.windowscommunicationsapps_8wekyb3d8bbwe"], sys.Calls);
        var c = Assert.Single(j.All);
        Assert.Equal(ChangeKind.NotUndoable, c.Kind);
        Assert.StartsWith("appx|microsoft.windowscommunicationsapps_8wekyb3d8bbwe|", c.Target);
        Assert.Equal("Mail and Calendar removed (microsoft.windowscommunicationsapps, 206 MB) — can't be undone; reinstall from the Microsoft Store if needed", c.Label);
        Assert.Equal(UndoSupport.None, Undoability.Of(c));
        Assert.Null(svc.UndoFor(s.Id));
        Assert.DoesNotContain(svc.Suggestions, x => x.Id == s.Id);

        var all = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");
        Assert.Equal(1, all.Skipped);
        Assert.Equal(0, all.Failed);
        Assert.Empty(j.All);
    }

    [Theory]
    [InlineData(false)] // still there after removal (protected / in use)
    [InlineData(true)]  // PowerShell didn't run or didn't finish
    public async Task RemoveStoreApp_ReadBackFails_NothingJournaled(bool scriptFails)
    {
        var sys = new Sys { Packages = [Pkg("Microsoft.People")], RemoveScriptFails = scriptFails };
        sys.Stubborn.Add("Microsoft.People_8wekyb3d8bbwe");
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-app-people");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task UninstallVendorPrograms_RunsTheirUninstaller_JournalsEach_TurnsOffTasks_UndoTurnsTasksBackOn()
    {
        var sys = new Sys { Programs = [LenovoNow()], Tasks = { [@"\Lenovo\LenovoNowTask"] = "Ready", [@"\Lenovo\LenovoNowDaily"] = "Disabled" } };
        AllCdmOff(sys);
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-app-lenovo-now");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("Lenovo Now uninstalled", r.Message);
        Assert.Contains("reinstall from Lenovo if needed", r.Message);
        Assert.Contains($"uninstall:\"{LenovoUninstaller}\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART", sys.Calls);
        var gone = j.All.Single(c => c.Kind == ChangeKind.NotUndoable);
        Assert.Equal("Lenovo Now 4.8.0.54 uninstalled (441 MB) — can't be undone; reinstall from Lenovo if needed", gone.Label);
        var task = j.All.Single(c => c.Kind == ChangeKind.ScheduledTask);
        Assert.Equal(@"\Lenovo\LenovoNowTask", task.Target); // the one already off isn't touched
        Assert.Equal("Enabled", task.Previous);
        Assert.Equal("Disabled", sys.Tasks[@"\Lenovo\LenovoNowTask"]);

        var u = svc.UndoFor(s.Id)!;
        var undone = await svc.UndoAsync(u);
        Assert.True(undone.Success, undone.Message);
        Assert.Contains("can't be put back", undone.Message);
        Assert.Equal("Ready", sys.Tasks[@"\Lenovo\LenovoNowTask"]);
        Assert.Equal(ChangeKind.NotUndoable, Assert.Single(j.All).Kind);
    }

    [Fact]
    public async Task PowerEngage_MsiUninstall_ReadBackFails_NothingJournaledForTheProgram()
    {
        var sys = new Sys { Programs = [PowerEngage()], UninstallerDoesNothing = true };
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-app-powerengage");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains($"uninstall:msiexec.exe /x {PowerEngageCode} /qn /norestart", sys.Calls);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Xbox_RemovesPackages_SettingsServicesTask_PerItemUndo_RestoresAllButTheApps()
    {
        var sys = new Sys
        {
            Packages = [Pkg("Microsoft.GamingApp", size: 300L << 20), Pkg("Microsoft.XboxIdentityProvider", size: 17L << 20)],
            Services = { ["XblAuthManager"] = "Manual", ["XblGameSave"] = "Automatic", ["XboxGipSvc"] = "AutomaticDelayed" }, // XboxNetApiSvc not installed
            Tasks = { [XblTask] = "Ready" },
        };
        sys.Reg[RegistryAllowlist.GameDvrEnabled.Target] = 1;
        sys.Stubborn.Add("Microsoft.XboxIdentityProvider_8wekyb3d8bbwe");
        AllCdmOff(sys);
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-xbox");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("Removed Xbox app (about 300 MB freed)", r.Message);
        Assert.Contains("Xbox Identity Provider", r.Message); // couldn't be removed
        var permanent = Assert.Single(j.All, c => c.Kind == ChangeKind.NotUndoable);
        Assert.Contains("Xbox app removed (Microsoft.GamingApp, 300 MB)", permanent.Label);
        Assert.Equal(new[] { RegistryAllowlist.AppCaptureEnabled.Target, RegistryAllowlist.GameDvrEnabled.Target }.Order(),
            j.All.Where(c => c.Kind == ChangeKind.RegistryValue).Select(c => c.Target).Order());
        Assert.Equal("1", j.All.Single(c => c.Target == RegistryAllowlist.GameDvrEnabled.Target).Previous);
        Assert.Equal(["XblGameSave", "XboxGipSvc"], j.All.Where(c => c.Kind == ChangeKind.ServiceStartType).Select(c => c.Target).Order());
        Assert.Equal("Manual", sys.Services["XblGameSave"]);
        Assert.Equal(XblTask, j.All.Single(c => c.Kind == ChangeKind.ScheduledTask).Target);

        var undone = await svc.UndoAsync(svc.UndoFor(s.Id)!);
        Assert.True(undone.Success, undone.Message);
        Assert.Contains("removed Xbox apps can't be put back", undone.Message);
        Assert.Equal(1, sys.Reg[RegistryAllowlist.GameDvrEnabled.Target]);
        Assert.False(sys.Reg.ContainsKey(RegistryAllowlist.AppCaptureEnabled.Target));
        Assert.Equal(("Automatic", "AutomaticDelayed", "Manual"), (sys.Services["XblGameSave"], sys.Services["XboxGipSvc"], sys.Services["XblAuthManager"]));
        Assert.Equal("Ready", sys.Tasks[XblTask]);
        Assert.Equal(ChangeKind.NotUndoable, Assert.Single(j.All).Kind);
    }

    [Fact]
    public async Task UndoAll_RestoresXboxSettingsAndTasks_SkipsRemovedApps_RefusesOffListTargets()
    {
        var sys = new Sys { Packages = [Pkg("Microsoft.GamingApp")], Services = { ["XblGameSave"] = "Automatic" }, Tasks = { [XblTask] = "Ready", [@"\Microsoft\Windows\Defrag\ScheduledDefrag"] = "Disabled" } };
        AllCdmOff(sys);
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "remove-xbox");
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        j.Add(ChangeRecord.New(ChangeKind.ScheduledTask, @"\Microsoft\Windows\Defrag\ScheduledDefrag", "Enabled", "tampered", "x"));
        j.Add(ChangeRecord.New(ChangeKind.ScheduledTask, @"\Lenovo\LenovoNowGone", "Enabled", "removed with its app", "x"));

        var all = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");
        Assert.Equal(1, all.Skipped); // the removed Xbox app
        Assert.Equal(1, all.Failed);  // the task that isn't on the allowlist
        Assert.Equal("Ready", sys.Tasks[XblTask]);
        Assert.Equal("Disabled", sys.Tasks[@"\Microsoft\Windows\Defrag\ScheduledDefrag"]);
        Assert.DoesNotContain(sys.Calls, c => c.Contains("Defrag"));
        Assert.Equal("Automatic", sys.Services["XblGameSave"]);
        Assert.False(sys.Reg.ContainsKey(RegistryAllowlist.GameDvrEnabled.Target));
        Assert.Equal(@"\Microsoft\Windows\Defrag\ScheduledDefrag", Assert.Single(j.All).Target);
    }

    [Fact]
    public async Task ContentDelivery_Ticked_SetsAllFive_JournalsOldValues_UndoRestores()
    {
        var sys = new Sys();
        sys.Reg[RegistryAllowlist.SilentInstalledApps.Target] = 1;
        sys.Reg[RegistryAllowlist.SoftLanding.Target] = 0;
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "stop-silent-app-installs");
        Assert.True(s.DefaultOn);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.All(AppRemoval.ContentDeliverySettings, x => Assert.Equal(0, sys.Reg[x.Target]));
        Assert.Equal(4, j.All.Count); // SoftLanding was already 0
        Assert.Equal("Silent installs of promoted apps turned off for this account (was set to 1)", j.All.Single(c => c.Target == RegistryAllowlist.SilentInstalledApps.Target).Label);
        Assert.Equal(@"HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager|SilentInstalledAppsEnabled", RegistryAllowlist.SilentInstalledApps.Target);
        Assert.DoesNotContain(svc.Suggestions, x => x.Id == s.Id);

        var undone = await svc.UndoAsync(svc.UndoFor(s.Id)!);
        Assert.True(undone.Success, undone.Message);
        Assert.Equal(1, sys.Reg[RegistryAllowlist.SilentInstalledApps.Target]);
        Assert.Equal(0, sys.Reg[RegistryAllowlist.SoftLanding.Target]);
        Assert.False(sys.Reg.ContainsKey(RegistryAllowlist.SystemPaneSuggestions.Target));
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task ContentDelivery_NothingSticks_Failure_NothingJournaled()
    {
        var sys = new Sys();
        foreach (var x in AppRemoval.ContentDeliverySettings) sys.Ignored.Add(x.Target);
        var (j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "stop-silent-app-installs");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Nothing was changed", r.Message);
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(s.Id));
    }

    // ---- workflow ----

    [Fact]
    public void Workflow_ListsThem_Defaults_Undo_Admin()
    {
        var sys = new Sys
        {
            Packages = [Pkg("Microsoft.People"), Pkg("Microsoft.BingWeather"), Pkg("Microsoft.GamingApp")],
            Programs = [LenovoNow()],
        };
        var fixes = FixCatalog.Build([], Build(sys));
        var people = fixes.Single(f => f.SuggestionId == "remove-app-people");
        Assert.True(people.DefaultOn);
        Assert.True(people.NeedsAdmin);
        Assert.Equal(UndoSupport.None, people.Undo);
        Assert.Equal("can't be undone", Undoability.Chip(people.Undo));
        Assert.Contains("can't be undone — reinstall from the Microsoft Store if needed", people.Why);
        Assert.False(fixes.Single(f => f.SuggestionId == "remove-app-bing-weather").DefaultOn);
        var xbox = fixes.Single(f => f.SuggestionId == "remove-xbox");
        Assert.False(xbox.DefaultOn);
        Assert.Equal(UndoSupport.None, xbox.Undo);
        var lenovo = fixes.Single(f => f.SuggestionId == "remove-app-lenovo-now");
        Assert.True(lenovo.DefaultOn);
        Assert.True(lenovo.NeedsAdmin);
        var cdm = fixes.Single(f => f.SuggestionId == "stop-silent-app-installs");
        Assert.True(cdm.DefaultOn);
        Assert.False(cdm.NeedsAdmin);
        Assert.Equal(UndoSupport.Full, cdm.Undo);
        foreach (var t in new[] { MemoryActionType.RemoveApp, MemoryActionType.RemoveXboxApps, MemoryActionType.StopSilentAppInstalls })
        {
            Assert.Contains(t, FixCatalog.UnattendedMemoryActions);
            Assert.True(MemoryFeedback.IsDeferred(t));
        }
    }
}
