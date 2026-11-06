using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>#23 Skip the Office start screen: when it's offered, the per-account writes, journal and undo.</summary>
public class OfficeStartScreenTests
{
    private sealed class Sys : IMemorySystem
    {
        public Dictionary<string, int> Reg = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Targets whose writes "succeed" but don't stick (organization policy).</summary>
        public HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Denied = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Calls = [];
        /// <summary>Installed Office 16 apps; their values come from <see cref="Reg"/> at capture time (as the Host reads them).</summary>
        public List<string>? Installed = ["Word", "Excel", "PowerPoint"];
        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), [],
                OfficeStart: Installed is null ? null : new OfficeStartInfo(Installed.Select(a => new OfficeStartApp(a, ReadDword(OfficeStartScreen.Setting(a)!))).ToList())));
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) { Calls.Add("kill:" + p); return Task.FromResult(new ActionOutcome(true, "")); }
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public byte[]? GetStartupApproved(string n) => null;
        public void SetStartupApproved(string n, byte[]? v) { }
        public bool IsBrowserRunning(BrowserKind k) => false;
        public string? ReadBrowserLocalState(BrowserKind k) => null;
        public void WriteBrowserLocalState(BrowserKind k, string json) { }
        public void OpenUri(string uri) { }
        public string GetServiceStartType(string n) => "Automatic";
        public void SetServiceStartType(string n, string t) { }
        public int? ReadDword(RegistrySetting s) => Reg.TryGetValue(s.Target, out var v) ? v : null;
        public void WriteDword(RegistrySetting s, int value)
        {
            Calls.Add($"write:{s.Target}={value}");
            if (Denied.Contains(s.Target)) throw new UnauthorizedAccessException();
            if (!Ignored.Contains(s.Target)) Reg[s.Target] = value;
        }
        public void DeleteDword(RegistrySetting s) { Calls.Add("delete:" + s.Target); Reg.Remove(s.Target); }
    }

    private static readonly string Word = RegistryAllowlist.WordStartScreen.Target;
    private static readonly string Excel = RegistryAllowlist.ExcelStartScreen.Target;
    private static readonly string PowerPoint = RegistryAllowlist.PowerPointStartScreen.Target;
    private const string Id = "office-start-screen";

    private static MemorySnapshot Snap(OfficeStartInfo? office) => new(new(16L << 30, 8L << 30), [], OfficeStart: office);
    private static OfficeStartInfo Office(int? word = null, int? excel = null, int? powerPoint = null) =>
        new([new("Word", word), new("Excel", excel), new("PowerPoint", powerPoint)]);

    private static (Sys, MemoryChangeJournal, MemorySuggestionService) Make(Sys? sys = null)
    {
        var s = sys ?? new Sys();
        var j = new MemoryChangeJournal();
        return (s, j, new MemorySuggestionService(s, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }

    [Fact]
    public void Targets_AreThePerAccountOptionsValues_NotThePolicyKey()
    {
        Assert.Equal(@"HKCU\Software\Microsoft\Office\16.0\Word\Options|DisableBootToOfficeStart", Word);
        Assert.Equal(@"HKCU\Software\Microsoft\Office\16.0\Excel\Options|DisableBootToOfficeStart", Excel);
        Assert.Equal(@"HKCU\Software\Microsoft\Office\16.0\PowerPoint\Options|DisableBootToOfficeStart", PowerPoint);
        Assert.Same(RegistryAllowlist.ExcelStartScreen, RegistryAllowlist.Find(Excel.ToUpperInvariant()));
        Assert.Same(RegistryAllowlist.PowerPointStartScreen, OfficeStartScreen.Setting("PowerPoint"));
        // Group Policy would lock the setting; other Office keys / versions are never touched.
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Policies\Microsoft\Office\16.0\Word\Options|DisableBootToOfficeStart"));
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Microsoft\Office\16.0\Common\General|DisableBootToOfficeStart"));
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Microsoft\Office\16.0\Outlook\Options|DisableBootToOfficeStart"));
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Microsoft\Office\15.0\Word\Options|DisableBootToOfficeStart"));
        Assert.Null(OfficeStartScreen.Setting("Outlook"));
    }

    // ---- engine ----

    [Fact]
    public void Offered_WhenOffice16Installed_AndStartScreenOn_OneCardForAllThree()
    {
        var s = MemorySuggestionEngine.Build(Snap(Office(excel: 0))).Single(x => x.Id == Id);
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.Equal(MemoryActionType.SkipOfficeStartScreen, Assert.Single(s.Actions).Type);
        Assert.True(s.DefaultOn);
        Assert.Null(s.SavingBytes);
        Assert.StartsWith("Word, Excel and PowerPoint open to a Start screen", s.Why);
        var steps = string.Join(" ", s.Steps);
        Assert.Contains("Applies to the Windows account this app runs as", steps);
        Assert.Contains("recent files are still under File > Open", steps);
        Assert.EndsWith("Undo brings the start screen back.", s.Steps[^1]);
    }

    [Fact]
    public void OnlySomeStillOn_OnlyThoseListed()
    {
        var s = MemorySuggestionEngine.Build(Snap(Office(word: 1, powerPoint: 0))).Single(x => x.Id == Id);
        Assert.StartsWith("Excel and PowerPoint open to a Start screen", s.Why);
        Assert.DoesNotContain("Word", s.Steps[0]);
        Assert.Equal(["Excel", "PowerPoint"], OfficeStartScreen.StillOn(Snap(Office(word: 1, powerPoint: 0))).Select(a => a.App));
        // Only Excel installed.
        var excelOnly = MemorySuggestionEngine.Build(Snap(new([new("Excel", null)]))).Single(x => x.Id == Id);
        Assert.StartsWith("Excel opens to a Start screen", excelOnly.Why);
    }

    [Fact]
    public void NotOffered_WhenOfficeMissing_Unreadable_OrAllAlreadyOff()
    {
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(null)), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new([]))), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(Office(1, 1, 1))), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(Office(1, 2, 1))), x => x.Id == Id); // any non-zero = start screen off
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new([new("Outlook", null)]))), x => x.Id == Id); // no start screen fix for other apps
    }

    [Theory]
    [InlineData(@"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", true)]
    [InlineData(@"C:\Program Files (x86)\Microsoft Office\Office16\EXCEL.EXE", true)]
    [InlineData(@"C:\Program Files\Microsoft Office\root\Office16\", true)]
    [InlineData(@"C:\Program Files\Microsoft Office\Office15\WINWORD.EXE", false)]
    [InlineData(null, false)]
    public void Detection_Office16Path(string? path, bool expected) => Assert.Equal(expected, OfficeStartScreen.IsOffice16Path(path));

    [Fact]
    public void Detection_ClickToRunProducts()
    {
        Assert.True(OfficeStartScreen.IsOffice16Version("16.0.18129.20158"));
        Assert.False(OfficeStartScreen.IsOffice16Version("15.0.5589.1001"));
        Assert.False(OfficeStartScreen.IsOffice16Version(null));
        string? None(string _) => null;
        Assert.True(OfficeStartScreen.InClickToRun("Word", "O365ProPlusRetail", None));
        Assert.True(OfficeStartScreen.InClickToRun("PowerPoint", "HomeStudent2021Retail,VisioProRetail", None));
        Assert.True(OfficeStartScreen.InClickToRun("Excel", "ExcelRetail", None));
        Assert.False(OfficeStartScreen.InClickToRun("Word", "ExcelRetail", None));
        Assert.False(OfficeStartScreen.InClickToRun("Word", "VisioProRetail,ProjectProRetail", None));
        Assert.False(OfficeStartScreen.InClickToRun("PowerPoint", "O365ProPlusRetail", id => id == "O365ProPlusRetail" ? "groove,lync,powerpoint" : null));
        Assert.False(OfficeStartScreen.InClickToRun("Word", null, None));
    }

    // ---- service: apply, journal, per-item undo ----

    [Fact]
    public async Task Apply_WritesOnlyTheStillOnApps_JournalsEach_UndoRestoresOrDeletes()
    {
        var sys = new Sys();
        sys.Reg[Excel] = 1; // already off: not touched
        sys.Reg[PowerPoint] = 0; // explicitly on
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("Word and PowerPoint will open straight to a blank document", r.Message);
        Assert.Contains("Takes effect the next time each app opens.", r.Message);
        Assert.DoesNotContain("Takes effect next launch", r.Message); // already says when: no repeated generic line, no memory delta claimed
        Assert.Equal((1, 1, 1), (sys.Reg[Word], sys.Reg[Excel], sys.Reg[PowerPoint]));
        Assert.DoesNotContain(sys.Calls, c => c.Contains(Excel));
        Assert.Equal(2, j.All.Count);
        Assert.All(j.All, c => Assert.Equal(ChangeKind.RegistryValue, c.Kind));
        Assert.All(j.All, c => Assert.False(c.NeedsRestart));
        var word = j.All.Single(c => c.Target == Word);
        Assert.Null(word.Previous);
        Assert.Equal("Word start screen turned off for this account (was not set)", word.Label);
        var ppt = j.All.Single(c => c.Target == PowerPoint);
        Assert.Equal("0", ppt.Previous);
        Assert.Equal("PowerPoint start screen turned off for this account (was set to 0)", ppt.Label);
        Assert.DoesNotContain(svc.Suggestions, x => x.Id == Id); // rescanned: nothing left to offer

        var u = svc.UndoFor(Id)!;
        var undone = await svc.UndoAsync(u);
        Assert.True(undone.Success, undone.Message);
        Assert.Contains("start screen is back in Word and PowerPoint", undone.Message);
        Assert.False(sys.Reg.ContainsKey(Word));
        Assert.Equal(0, sys.Reg[PowerPoint]);
        Assert.Equal(1, sys.Reg[Excel]);
        Assert.Contains("delete:" + Word, sys.Calls);
        Assert.Empty(j.All);
        Assert.Contains(svc.Suggestions, x => x.Id == Id); // offered again
    }

    [Theory]
    [InlineData(false)] // write "works" but reads back unchanged (organization policy)
    [InlineData(true)]  // access denied
    public async Task WriteThatDoesNotStick_IsAFailure_NothingJournaled(bool denied)
    {
        var sys = new Sys { Installed = ["Word"] };
        (denied ? sys.Denied : sys.Ignored).Add(Word);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Nothing was changed", r.Message);
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(Id));
    }

    [Fact]
    public async Task OneAppDoesNotStick_OthersStillApplied_OnlyThoseJournaled()
    {
        var sys = new Sys();
        sys.Ignored.Add(Excel);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("Excel couldn't be changed", r.Message);
        Assert.Equal(new HashSet<string> { Word, PowerPoint }, j.All.Select(c => c.Target).ToHashSet());
        Assert.Equal(1, sys.Reg[Word]);
        Assert.False(sys.Reg.ContainsKey(Excel));
        Assert.Equal(2, RegistryUndo.Decode(svc.UndoFor(Id)!.Previous).Count);
    }

    // ---- UndoService (Undo all) ----

    [Fact]
    public async Task UndoAll_RestoresOrDeletes_AndRefusesTargetsNotOnTheAllowlist()
    {
        var sys = new Sys();
        sys.Reg[Word] = 1;
        sys.Reg[Excel] = 1;
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, Word, null, "Word start screen turned off for this account (was not set)", "x"));
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, Excel, "0", "Excel start screen turned off for this account (was set to 0)", "x"));
        const string policy = @"HKCU\Software\Policies\Microsoft\Office\16.0\Word\Options|DisableBootToOfficeStart";
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, policy, "1", "tampered", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");

        Assert.Equal(2, r.Succeeded);
        Assert.Equal(1, r.Failed);
        Assert.False(r.NeedsRestart);
        Assert.False(sys.Reg.ContainsKey(Word));
        Assert.Equal(0, sys.Reg[Excel]);
        Assert.DoesNotContain(sys.Calls, c => c.Contains("Policies"));
        Assert.Equal(policy, Assert.Single(j.All).Target); // refused, left in the journal
    }

    // ---- workflow ----

    [Fact]
    public void Workflow_ListsIt_Ticked_FullUndo_NoAdmin_Deferred()
    {
        var fix = FixCatalog.Build([], MemorySuggestionEngine.Build(Snap(Office()))).Single(f => f.MemoryAction == MemoryActionType.SkipOfficeStartScreen);
        Assert.True(fix.DefaultOn);
        Assert.False(fix.NeedsAdmin);
        Assert.Equal(UndoSupport.Full, fix.Undo);
        Assert.Equal(Id, fix.SuggestionId);
        Assert.Contains(MemoryActionType.SkipOfficeStartScreen, FixCatalog.UnattendedMemoryActions);
        Assert.Equal(UndoSupport.Full, Undoability.Of(MemoryActionType.SkipOfficeStartScreen));
        Assert.True(MemoryFeedback.IsDeferred(MemoryActionType.SkipOfficeStartScreen));
    }
}
