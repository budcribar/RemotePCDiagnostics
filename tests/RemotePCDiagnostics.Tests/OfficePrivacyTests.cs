using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>#18 Office optional connected experiences: when it's offered, the one policy write, journal and undo.</summary>
public class OfficePrivacyTests
{
    private sealed class Sys : IMemorySystem
    {
        public Dictionary<string, int> Reg = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Denied = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Calls = [];
        public bool Installed = true;
        public int? DisconnectedState;
        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), [],
                OfficePrivacy: new OfficePrivacyInfo(Installed, Installed ? ReadDword(OfficePrivacy.Setting) : null, DisconnectedState)));
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
            if (Denied.Contains(s.Target)) throw new UnauthorizedAccessException();
            if (!Ignored.Contains(s.Target)) Reg[s.Target] = value;
        }
        public void DeleteDword(RegistrySetting s) { Calls.Add("delete:" + s.Target); Reg.Remove(s.Target); }
    }

    private static readonly string Policy = RegistryAllowlist.OfficeOptionalConnectedExperiences.Target;
    private const string Id = "office-optional-experiences";

    private static MemorySnapshot Snap(OfficePrivacyInfo? p) => new(new(16L << 30, 8L << 30), [], OfficePrivacy: p);

    private static (Sys, MemoryChangeJournal, MemorySuggestionService) Make(Sys? sys = null)
    {
        var s = sys ?? new Sys();
        var j = new MemoryChangeJournal();
        return (s, j, new MemorySuggestionService(s, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }

    [Fact]
    public void Target_IsTheOptionalExperiencesPolicy_NotDisconnectedState()
    {
        Assert.Equal(@"HKCU\Software\Policies\Microsoft\Office\16.0\Common\Privacy|ControllerConnectedServicesEnabled", Policy);
        Assert.Same(RegistryAllowlist.OfficeOptionalConnectedExperiences, RegistryAllowlist.Find(Policy.ToLowerInvariant()));
        Assert.Same(RegistryAllowlist.OfficeOptionalConnectedExperiences, OfficePrivacy.Setting);
        Assert.Equal(2, OfficePrivacy.Disabled);
        // All connected experiences (co-authoring, OneDrive files), content analysis, downloads: never written.
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Policies\Microsoft\Office\16.0\Common\Privacy|DisconnectedState"));
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Policies\Microsoft\Office\16.0\Common\Privacy|UserContentDisabled"));
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Policies\Microsoft\Office\16.0\Common\Privacy|DownloadContentDisabled"));
        Assert.Null(RegistryAllowlist.Find(@"HKLM\Software\Policies\Microsoft\Office\16.0\Common\Privacy|ControllerConnectedServicesEnabled"));
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Microsoft\Office\16.0\Common\Privacy|ControllerConnectedServicesEnabled"));
    }

    // ---- engine ----

    [Fact]
    public void Offered_WhenOffice16Installed_AndPolicyNotSet_OptIn()
    {
        var s = MemorySuggestionEngine.Build(Snap(new(true, null, null))).Single(x => x.Id == Id);
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.Equal(MemoryActionType.DisableOfficeOptionalExperiences, Assert.Single(s.Actions).Type);
        Assert.False(s.DefaultOn);
        Assert.Null(s.SavingBytes); // not measured: no number shown
        Assert.Contains("while Office apps are open", s.Why);
        var steps = string.Join(" ", s.Steps);
        Assert.Contains("online pictures", steps);
        Assert.Contains("co-authoring", steps);
        Assert.Contains("OneDrive and SharePoint", steps);
        Assert.Contains("managed by your organization", steps);
        Assert.Contains("Copilot isn't changed", steps);
        Assert.EndsWith("Undo brings them back.", s.Steps[^1]);
        Assert.Equal("Office", s.Category);
    }

    [Fact]
    public void NotOffered_WhenOfficeMissing_Unknown_AlreadyOff_OrManaged()
    {
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(null)), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new(false, null, null))), x => x.Id == Id);
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new(true, 2, null))), x => x.Id == Id); // already off
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new(true, 1, null))), x => x.Id == Id); // explicitly allowed (organization): not overridden
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new(true, null, 2))), x => x.Id == Id); // all connected experiences already off
        Assert.Contains(MemorySuggestionEngine.Build(Snap(new(true, null, 1))), x => x.Id == Id);
    }

    // ---- service: apply, journal, per-item undo ----

    [Fact]
    public async Task Apply_WritesTwo_Journals_UndoDeletesIt()
    {
        var (sys, j, svc) = Make();
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("OneDrive, SharePoint and co-authoring keep working", r.Message);
        Assert.Contains("Takes effect next launch", r.Message); // deferred: no memory delta claimed
        Assert.Equal(2, sys.Reg[Policy]);
        Assert.Equal([$"write:{Policy}=2"], sys.Calls);
        var c = Assert.Single(j.All);
        Assert.Equal(ChangeKind.RegistryValue, c.Kind);
        Assert.Equal(Policy, c.Target);
        Assert.Null(c.Previous);
        Assert.False(c.NeedsRestart);
        Assert.Equal("Office optional connected experiences turned off for this account (policy was not set)", c.Label);
        Assert.DoesNotContain(svc.Suggestions, x => x.Id == Id); // rescanned: nothing left to offer

        var undone = await svc.UndoAsync(svc.UndoFor(Id)!);
        Assert.True(undone.Success, undone.Message);
        Assert.Contains("optional online extras are back", undone.Message);
        Assert.False(sys.Reg.ContainsKey(Policy));
        Assert.Contains("delete:" + Policy, sys.Calls);
        Assert.Empty(j.All);
        Assert.Contains(svc.Suggestions, x => x.Id == Id); // offered again
    }

    [Theory]
    [InlineData(false)] // write "works" but reads back unchanged
    [InlineData(true)]  // access denied (not elevated)
    public async Task WriteThatDoesNotStick_IsAFailure_NothingJournaled(bool denied)
    {
        var sys = new Sys();
        (denied ? sys.Denied : sys.Ignored).Add(Policy);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Id);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Nothing was changed", r.Message);
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(Id));
    }

    // ---- UndoService (Undo all) ----

    [Fact]
    public async Task UndoAll_RestoresOrDeletes_AndRefusesDisconnectedState()
    {
        var sys = new Sys();
        sys.Reg[Policy] = 2;
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, Policy, null, "Office optional connected experiences turned off for this account (policy was not set)", "x"));
        const string all = @"HKCU\Software\Policies\Microsoft\Office\16.0\Common\Privacy|DisconnectedState";
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, all, "1", "tampered", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");

        Assert.Equal(1, r.Succeeded);
        Assert.Equal(1, r.Failed);
        Assert.False(r.NeedsRestart);
        Assert.False(sys.Reg.ContainsKey(Policy));
        Assert.DoesNotContain(sys.Calls, x => x.Contains("DisconnectedState"));
        Assert.Equal(all, Assert.Single(j.All).Target); // refused, left in the journal
    }

    [Fact]
    public async Task UndoAll_WritesBackAnOldValue()
    {
        var sys = new Sys();
        sys.Reg[Policy] = 2;
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, Policy, "1", "Office optional connected experiences turned off for this account (policy was set to 1)", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");
        Assert.Equal(1, r.Succeeded);
        Assert.Equal(1, sys.Reg[Policy]);
        Assert.Empty(j.All);
    }

    // ---- workflow ----

    [Fact]
    public void Workflow_ListsIt_Unticked_FullUndo_Admin_Deferred()
    {
        var fix = FixCatalog.Build([], MemorySuggestionEngine.Build(Snap(new(true, null, null)))).Single(f => f.MemoryAction == MemoryActionType.DisableOfficeOptionalExperiences);
        Assert.False(fix.DefaultOn);
        Assert.True(fix.NeedsAdmin);
        Assert.Equal(UndoSupport.Full, fix.Undo);
        Assert.Equal(Id, fix.SuggestionId);
        Assert.Contains(MemoryActionType.DisableOfficeOptionalExperiences, FixCatalog.UnattendedMemoryActions);
        Assert.Equal(UndoSupport.Full, Undoability.Of(MemoryActionType.DisableOfficeOptionalExperiences));
        Assert.True(MemoryFeedback.IsDeferred(MemoryActionType.DisableOfficeOptionalExperiences));
    }
}
