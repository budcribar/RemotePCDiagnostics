using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>#24 Make Microsoft Print to PDF the default printer (opt-in): when it's offered, apply, journal and undo.</summary>
public class DefaultPrinterTests
{
    private const string Pdf = DefaultPrinter.PdfPrinter;
    private const string Hp = "HP LaserJet M404 (WSD)";
    private const string Id = "default-printer-pdf";
    private static readonly string Mode = RegistryAllowlist.LegacyDefaultPrinterMode.Target;

    private sealed class Sys : IMemorySystem
    {
        public Dictionary<string, int> Reg = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Installed printers and their ports.</summary>
        public Dictionary<string, string> Printers = new(StringComparer.OrdinalIgnoreCase) { [Hp] = "WSD-5b2c7a10-0000-0000-0000-000000000000", [Pdf] = "PORTPROMPT:" };
        public string? Default = Hp;
        /// <summary>SetDefaultPrinter "succeeds" but the default doesn't change (organization policy).</summary>
        public bool IgnoreSetDefault;
        public bool ModeDenied;
        public List<string> Calls = [];
        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), [], DefaultPrinter: ReadDefaultPrinter()));
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
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
            if (ModeDenied) throw new UnauthorizedAccessException();
            Reg[s.Target] = value;
        }
        public void DeleteDword(RegistrySetting s) { Calls.Add("delete:" + s.Target); Reg.Remove(s.Target); }
        public DefaultPrinterInfo? ReadDefaultPrinter() =>
            new(Default, Default is not null && Printers.TryGetValue(Default, out var port) ? port : null, ReadDword(RegistryAllowlist.LegacyDefaultPrinterMode), Printers.ContainsKey(Pdf));
        public bool PrinterExists(string name) => Printers.ContainsKey(name) || DefaultPrinter.IsConnectionName(name) && Connections.Contains(name);
        public HashSet<string> Connections = new(StringComparer.OrdinalIgnoreCase);
        public ActionOutcome SetDefaultPrinter(string name)
        {
            Calls.Add("default:" + name);
            if (!PrinterExists(name)) return new(false, "not installed");
            if (!IgnoreSetDefault) Default = name;
            return new(true, "");
        }
    }

    private static MemorySnapshot Snap(DefaultPrinterInfo? p) => new(new(16L << 30, 8L << 30), [], DefaultPrinter: p);

    private static (Sys, MemoryChangeJournal, MemorySuggestionService) Make(Sys? sys = null)
    {
        var s = sys ?? new Sys();
        var j = new MemoryChangeJournal();
        return (s, j, new MemorySuggestionService(s, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }

    private static UndoService Undo(MemoryChangeJournal j, Sys sys) =>
        new(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys);

    [Fact]
    public void Allowlist_HasOnlyThePerAccountLegacyMode()
    {
        Assert.Equal(@"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows|LegacyDefaultPrinterMode", Mode);
        Assert.Same(RegistryAllowlist.LegacyDefaultPrinterMode, RegistryAllowlist.Find(Mode.ToUpperInvariant()));
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows|Device")); // never written directly
        Assert.Null(RegistryAllowlist.Find(@"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows|LegacyDefaultPrinterMode"));
    }

    // ---- detection rules ----

    [Theory]
    [InlineData("HP LaserJet,winspool,Ne01:", "HP LaserJet")]
    [InlineData(@"\\print01\Floor2,winspool,Ne03:", @"\\print01\Floor2")]
    [InlineData("Microsoft Print to PDF", "Microsoft Print to PDF")]
    [InlineData("", null)]
    [InlineData(",winspool,Ne01:", null)]
    [InlineData(null, null)]
    public void ParseDevice(string? device, string? expected) => Assert.Equal(expected, DefaultPrinter.ParseDevice(device));

    [Theory]
    [InlineData("WSD-5b2c7a10-1111-2222-3333-444455556666", true)]
    [InlineData("IP_192.168.1.40", true)]
    [InlineData(@"\\print01\Floor2", true)]
    [InlineData("USB001", false)]
    [InlineData("PORTPROMPT:", false)]
    [InlineData("LPT1:", false)]
    [InlineData(null, false)]
    public void NetworkPorts(string? port, bool expected) => Assert.Equal(expected, DefaultPrinter.IsNetworkPort(port));

    [Theory]
    [InlineData("HP LaserJet M404 (WSD)", true)]
    [InlineData(@"\\print01\Floor2", true)]
    [InlineData("Brother HL-L2350DW series", true)]
    [InlineData(@"C:\Windows\evil", false)]
    [InlineData(@"\\a\b\c", false)]
    [InlineData("a,winspool,Ne01:", false)]
    [InlineData("with \"quote\"", false)]
    [InlineData(" padded", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void SafeNames(string? name, bool expected) => Assert.Equal(expected, DefaultPrinter.IsSafeName(name));

    [Fact]
    public void Offered_ForWsdOrIpOrSharedDefault_OptIn_WithPlainCard()
    {
        var s = MemorySuggestionEngine.Build(Snap(new(Hp, "WSD-1234", 0, true))).Single(x => x.Id == Id);
        Assert.False(s.DefaultOn);
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.Equal(MemoryActionType.SetPdfDefaultPrinter, Assert.Single(s.Actions).Type);
        Assert.Contains("2–10 seconds", s.Why);
        Assert.Contains("keeps switching back", s.Why); // Windows manages the default (mode 0)
        var steps = string.Join(" ", s.Steps);
        Assert.Contains($"Print dialogs will start on {Pdf}", steps);
        Assert.Contains($"choose \"{Hp}\"", steps);
        Assert.StartsWith("Undo makes", s.Steps[^1]);

        Assert.Contains(MemorySuggestionEngine.Build(Snap(new("Canon", "IP_10.0.0.9", 1, true))), x => x.Id == Id);
        Assert.Contains(MemorySuggestionEngine.Build(Snap(new(@"\\print01\Floor2", null, null, true))), x => x.Id == Id);
        Assert.DoesNotContain("keeps switching back", MemorySuggestionEngine.Build(Snap(new("Canon", "IP_10.0.0.9", 1, true))).Single(x => x.Id == Id).Why);
    }

    [Fact]
    public void NotOffered_LocalOrPdfDefault_NoPdfPrinter_NoDefault_OrUnreadable()
    {
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(null)), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new(null, null, 0, true))), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new("Brother", "USB001", 0, true))), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new(Pdf, "PORTPROMPT:", 1, true))), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new(Hp, "WSD-1234", 0, false))), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new("Some printer", null, 0, true))), x => x.Id == Id); // port unknown
    }

    // ---- service: apply, journal, per-item undo ----

    [Fact]
    public async Task Apply_SetsModeThenPdf_ReadsBack_JournalsBoth_UndoRestoresPrinterAndMode()
    {
        var (sys, j, svc) = Make();
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains($"{Pdf} is now the default printer", r.Message);
        Assert.Contains("Takes effect next launch", r.Message); // deferred: no memory delta claimed
        Assert.Equal(Pdf, sys.Default);
        Assert.Equal(1, sys.Reg[Mode]);
        Assert.Equal([$"write:{Mode}=1", "default:" + Pdf], sys.Calls); // mode first, so Windows doesn't switch it back

        Assert.Equal(2, j.All.Count);
        var mode = j.All.Single(c => c.Kind == ChangeKind.RegistryValue);
        Assert.Equal(Mode, mode.Target);
        Assert.Null(mode.Previous);
        Assert.Contains("LegacyDefaultPrinterMode was not set", mode.Label);
        var printer = j.All.Single(c => c.Kind == ChangeKind.DefaultPrinter);
        Assert.Equal(DefaultPrinter.JournalTarget, printer.Target);
        Assert.Equal(Hp, printer.Previous);
        Assert.Equal($"Default printer for this account set to {Pdf} (was \"{Hp}\")", printer.Label);
        Assert.False(printer.NeedsRestart);
        Assert.Equal(UndoSupport.Full, Undoability.Of(printer));
        Assert.DoesNotContain(svc.Suggestions, x => x.Id == Id); // rescanned: default is local now

        var undone = await svc.UndoAsync(svc.UndoFor(Id)!);
        Assert.True(undone.Success, undone.Message);
        Assert.Contains($"\"{Hp}\" is the default printer again", undone.Message);
        Assert.Equal(Hp, sys.Default);
        Assert.False(sys.Reg.ContainsKey(Mode));
        Assert.Empty(j.All);
        Assert.Contains(svc.Suggestions, x => x.Id == Id); // offered again
    }

    [Fact]
    public async Task Apply_ModeAlreadyOne_OnlyPrinterJournaled_UndoLeavesModeAlone()
    {
        var sys = new Sys();
        sys.Reg[Mode] = 1;
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        Assert.Equal(ChangeKind.DefaultPrinter, Assert.Single(j.All).Kind);
        Assert.Empty(RegistryUndo.Decode(svc.UndoFor(Id)!.Previous));
        Assert.True((await svc.UndoAsync(svc.UndoFor(Id)!)).Success);
        Assert.Equal(1, sys.Reg[Mode]);
        Assert.Equal(Hp, sys.Default);
    }

    [Fact]
    public async Task PrinterDoesNotStick_ModeRolledBack_NothingJournaled()
    {
        var sys = new Sys { IgnoreSetDefault = true };
        sys.Reg[Mode] = 0;
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Nothing was changed", r.Message);
        Assert.Equal(0, sys.Reg[Mode]); // put back
        Assert.Equal(Hp, sys.Default);
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(Id));
    }

    [Fact]
    public async Task ModeDenied_NothingChanged_NothingJournaled()
    {
        var sys = new Sys { ModeDenied = true };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("default:"));
        Assert.Equal(Hp, sys.Default);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Undo_PreviousPrinterRemoved_SaysSo_ModeStillRestored()
    {
        var (sys, j, svc) = Make();
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        sys.Printers.Remove(Hp);
        var r = await svc.UndoAsync(svc.UndoFor(Id)!);
        Assert.False(r.Success);
        Assert.Contains($"\"{Hp}\", is no longer installed", r.Message);
        Assert.Equal(Pdf, sys.Default);
        Assert.False(sys.Reg.ContainsKey(Mode)); // mode put back anyway
        Assert.Equal(ChangeKind.DefaultPrinter, Assert.Single(j.All).Kind); // kept, so Undo all can retry if it's re-added
    }

    // ---- UndoService (Undo all) ----

    [Fact]
    public async Task UndoAll_RestoresPrinterAndMode()
    {
        var sys = new Sys { Default = Pdf };
        sys.Reg[Mode] = 1;
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, Mode, "0", "mode", "x"));
        j.Add(ChangeRecord.New(ChangeKind.DefaultPrinter, DefaultPrinter.JournalTarget, Hp, "printer", "x"));
        var r = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal(2, r.Succeeded);
        Assert.False(r.NeedsRestart);
        Assert.Equal(Hp, sys.Default);
        Assert.Equal(0, sys.Reg[Mode]);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task UndoAll_SharedConnection_Restored()
    {
        const string shared = @"\\print01\Floor2";
        var sys = new Sys { Default = Pdf };
        sys.Connections.Add(shared);
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.DefaultPrinter, DefaultPrinter.JournalTarget, shared, "printer", "x"));
        Assert.Equal(1, (await Undo(j, sys).UndoAllAsync("x")).Succeeded);
        Assert.Equal(shared, sys.Default);
    }

    [Theory]
    [InlineData("HKCU|SomethingElse", Hp)]       // not the allowlisted target
    [InlineData(DefaultPrinter.JournalTarget, @"C:\Windows\System32\evil.dll")]
    [InlineData(DefaultPrinter.JournalTarget, "a,winspool,Ne01:")]
    [InlineData(DefaultPrinter.JournalTarget, null)]
    public async Task UndoAll_RefusesTamperedRecords(string target, string? previous)
    {
        var sys = new Sys { Default = Pdf };
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.DefaultPrinter, target, previous, "tampered", "x"));
        var r = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal(1, r.Failed);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("default:"));
        Assert.Equal(Pdf, sys.Default);
        Assert.Single(j.All);
    }

    [Fact]
    public async Task UndoAll_PreviousPrinterGone_FailsWithMessage_KeepsRecord()
    {
        var sys = new Sys { Default = Pdf };
        sys.Printers.Remove(Hp);
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.DefaultPrinter, DefaultPrinter.JournalTarget, Hp, "printer", "x"));
        var r = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal(1, r.Failed);
        Assert.Contains("no longer installed", r.Items[0].Message);
        Assert.Single(j.All);
    }

    // ---- workflow ----

    [Fact]
    public void Workflow_ListsIt_OptIn_FullUndo_NoAdmin_Deferred()
    {
        var fix = FixCatalog.Build([], MemorySuggestionEngine.Build(Snap(new(Hp, "WSD-1234", 0, true)))).Single(f => f.MemoryAction == MemoryActionType.SetPdfDefaultPrinter);
        Assert.False(fix.DefaultOn);
        Assert.False(fix.NeedsAdmin);
        Assert.Equal(UndoSupport.Full, fix.Undo);
        Assert.Equal(Id, fix.SuggestionId);
        Assert.Contains(MemoryActionType.SetPdfDefaultPrinter, FixCatalog.UnattendedMemoryActions);
        Assert.Equal(UndoSupport.Full, Undoability.Of(MemoryActionType.SetPdfDefaultPrinter));
        Assert.True(MemoryFeedback.IsDeferred(MemoryActionType.SetPdfDefaultPrinter));
    }
}
