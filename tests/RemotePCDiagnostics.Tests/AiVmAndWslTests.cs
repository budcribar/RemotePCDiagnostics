using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>#14: Claude / Codex VM services to Manual (workflow, undo) and wsl --shutdown (live page only).</summary>
public class AiVmAndWslTests
{
    private const long Mb = 1L << 20, Gb = 1L << 30;
    private const string Codex = "CodexSandboxService.OpenAI.Codex_2p2nqf0c97628";

    private sealed class Sys : IMemorySystem
    {
        public MemorySnapshot Snap = new(new(16 * Gb, 8 * Gb), []);
        public Dictionary<string, string> StartTypes = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Services whose start type "is set" but reads back unchanged (organization policy / access).</summary>
        public HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Calls = [];
        public IReadOnlyList<string>? Running;
        public ActionOutcome CommandResult = new(true, "WSL shut down.");
        public MemoryReading ReadMemory() => Snap.Memory;
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => Task.FromResult(Snap);
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) { Calls.Add($"run:{f} {string.Join(' ', a)}"); return Task.FromResult(CommandResult); }
        public byte[]? GetStartupApproved(string n) => null;
        public void SetStartupApproved(string n, byte[]? v) { }
        public bool IsBrowserRunning(BrowserKind k) => false;
        public string? ReadBrowserLocalState(BrowserKind k) => null;
        public void WriteBrowserLocalState(BrowserKind k, string json) { }
        public void OpenUri(string uri) { }
        public string GetServiceStartType(string n) => StartTypes.GetValueOrDefault(n, "Automatic");
        public void SetServiceStartType(string n, string t) { Calls.Add($"start-type:{n}={t}"); if (!Ignored.Contains(n)) StartTypes[n] = t; }
        public IReadOnlyList<string>? RunningProcessNames() => Running;
    }

    private static ServiceInfo Svc(string name, string start = "AUTO_START", string status = "RUNNING") => new(name, name + " display", status, start, "LocalSystem", "");
    private static ServiceUsage Use(string name, bool? canStart = true, string start = "AUTO_START") => new(Svc(name, start), 26 * Mb, 1, canStart);
    private static MemorySnapshot Snap(params ServiceUsage[] services) => new(new(16 * Gb, 8 * Gb), [], Services: services);
    private static MemorySnapshot Apps(params AppUsage[] apps) => new(new(16 * Gb, 8 * Gb), apps);
    private static AppUsage Vm(long bytes = 2 * Gb) => new("vmmemWSL", 1, bytes);

    private static (Sys, MemoryChangeJournal, MemorySuggestionService) Make(MemorySnapshot snap)
    {
        var sys = new Sys { Snap = snap };
        var j = new MemoryChangeJournal();
        return (sys, j, new MemorySuggestionService(sys, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }

    // ---------------- service security descriptor ----------------

    private static byte[] SidBytes(string sid)
    {
        var parts = sid.Split('-');
        var subs = parts.Skip(3).Select(uint.Parse).ToArray();
        var b = new List<byte> { 1, (byte)subs.Length, 0, 0, 0, 0, 0, byte.Parse(parts[2]) };
        foreach (var s in subs) b.AddRange(BitConverter.GetBytes(s));
        return b.ToArray();
    }

    /// <summary>A self-relative SD with only a DACL: (type, flags, mask, sid) ACEs in order.</summary>
    private static byte[] Sd(params (byte Type, byte Flags, uint Mask, string Sid)[] aces)
    {
        var aceBytes = new List<byte>();
        foreach (var (type, flags, mask, sid) in aces)
        {
            var s = SidBytes(sid);
            var size = (ushort)(8 + s.Length);
            aceBytes.AddRange([type, flags, (byte)size, (byte)(size >> 8)]);
            aceBytes.AddRange(BitConverter.GetBytes(mask));
            aceBytes.AddRange(s);
        }
        var aclSize = (ushort)(8 + aceBytes.Count);
        var sd = new List<byte> { 1, 0 };
        sd.AddRange(BitConverter.GetBytes((ushort)(0x8000 | 0x0004))); // self-relative, DACL present
        sd.AddRange(BitConverter.GetBytes(0)); sd.AddRange(BitConverter.GetBytes(0)); sd.AddRange(BitConverter.GetBytes(0)); // owner, group, SACL
        sd.AddRange(BitConverter.GetBytes(20)); // DACL right after the header
        sd.AddRange([2, 0, (byte)aclSize, (byte)(aclSize >> 8), (byte)aces.Length, 0, 0, 0]);
        sd.AddRange(aceBytes);
        return sd.ToArray();
    }

    private const uint Start = 0x10, Stop = 0x20, Query = 0x4 | 0x1 | 0x80 | 0x8 | 0x20000;
    private const string SystemSid = "S-1-5-18", Admins = "S-1-5-32-544", Interactive = "S-1-5-4", AuthUsers = "S-1-5-11", Users = "S-1-5-32-545";

    [Fact]
    public void Security_DefaultServiceDacl_UsersCantStart()
    {
        // What CreateService gives by default: SYSTEM / Administrators full control; INTERACTIVE only query/interrogate/read.
        Assert.False(ServiceSecurity.UsersCanStart(Sd((0, 0, 0xF01FF, SystemSid), (0, 0, 0xF01FF, Admins), (0, 0, Query, Interactive))));
    }

    [Fact]
    public void Security_StartGrantedToSignedInUsers_CanStart()
    {
        Assert.True(ServiceSecurity.UsersCanStart(Sd((0, 0, 0xF01FF, SystemSid), (0, 0, Query | Start | Stop, AuthUsers))));
        Assert.True(ServiceSecurity.UsersCanStart(Sd((0, 0, Query | Start, Interactive))));
        Assert.True(ServiceSecurity.UsersCanStart(Sd((0, 0, ServiceSecurity.GenericExecute, Users))));
        Assert.True(ServiceSecurity.UsersCanStart(Sd((0, 0, ServiceSecurity.GenericAll, "S-1-1-0"))));
    }

    [Fact]
    public void Security_StopOnly_DenyFirst_InheritOnly_AndAdminsOnly_AreNotEnough()
    {
        Assert.False(ServiceSecurity.UsersCanStart(Sd((0, 0, Query | Stop, AuthUsers))));
        Assert.False(ServiceSecurity.UsersCanStart(Sd((1, 0, Start, Interactive), (0, 0, Start, AuthUsers))));   // deny comes first
        Assert.True(ServiceSecurity.UsersCanStart(Sd((0, 0, Start, AuthUsers), (1, 0, Start, Interactive))));    // allow comes first
        Assert.False(ServiceSecurity.UsersCanStart(Sd((0, 0x08, Start, AuthUsers))));                            // inherit-only: doesn't apply
        Assert.False(ServiceSecurity.UsersCanStart(Sd((0, 0, Start, Admins))));                                  // admins only
    }

    [Fact]
    public void Security_MalformedOrMissing_IsUnknown()
    {
        Assert.Null(ServiceSecurity.UsersCanStart(null));
        Assert.Null(ServiceSecurity.UsersCanStart([]));
        Assert.Null(ServiceSecurity.UsersCanStart(new byte[20]));
        var good = Sd((0, 0, Start, AuthUsers));
        Assert.Null(ServiceSecurity.UsersCanStart(good[..^3]));                                                  // truncated ACE
        Assert.Equal("S-1-5-32-545", ServiceSecurity.Sid(SidBytes("S-1-5-32-545"), 0, 16));
        // No DACL at all = everyone may.
        var noDacl = new byte[20]; noDacl[0] = 1; noDacl[3] = 0x80;
        Assert.True(ServiceSecurity.UsersCanStart(noDacl));
    }

    // ---------------- services to Manual: engine ----------------

    [Fact]
    public void Offered_ClaudeAndCodex_WhenAutomaticAndUsersCanStart_ManualOnly_Ticked()
    {
        var list = MemorySuggestionEngine.Build(Snap(Use("CoworkVMService"), Use(Codex)));
        var claude = list.Single(x => x.Id == "svc-coworkvmservice");
        var codex = list.Single(x => x.Id == "svc-" + Codex.ToLowerInvariant());
        foreach (var s in new[] { claude, codex })
        {
            Assert.Equal(SuggestionKind.Automated, s.Kind);
            var a = Assert.Single(s.Actions);                                     // no "Stop now": it would cut off a running task
            Assert.Equal(MemoryActionType.SetServiceManual, a.Type);
            Assert.Equal("Don't start automatically", a.Label);
            Assert.True(s.DefaultOn);
            Assert.Equal("Undo sets it back to Automatic.", s.Steps[^1]);
            Assert.Contains("doesn't stop the service or the VM now", s.Steps[0]);
        }
        Assert.Equal("Start Claude's Linux VM only when it's needed", claude.Title);
        Assert.Contains("vmmem", claude.Why);
        Assert.Contains("every Windows sign-in", claude.Why);
        Assert.Contains("Claude starts the service itself when a feature needs it", claude.Steps[1]);
        Assert.Equal("Start the Codex sandbox only when it's needed", codex.Title);
        Assert.Contains("OpenAI Codex starts the service itself", codex.Steps[1]);
        Assert.DoesNotContain("updates", codex.Why, StringComparison.OrdinalIgnoreCase); // not the generic vendor-updater text
    }

    [Fact]
    public void Offered_EvenWhileClaudeIsOpen()
    {
        var snap = Snap(Use("CoworkVMService")) with { Apps = [new AppUsage("claude", 4, 600 * Mb, HasWindow: true)] };
        Assert.Contains(MemorySuggestionEngine.Build(snap), x => x.Id == "svc-coworkvmservice");
    }

    [Theory]
    [InlineData(false, "AUTO_START")]
    [InlineData(null, "AUTO_START")]
    [InlineData(true, "DEMAND_START")]
    [InlineData(true, "DISABLED")]
    public void NotOffered_WhenUsersCantStartIt_Unknown_OrNotAutomatic(bool? canStart, string start)
    {
        var list = MemorySuggestionEngine.Build(Snap(Use("CoworkVMService", canStart, start), Use(Codex, canStart, start)));
        Assert.DoesNotContain(list, x => x.Id.StartsWith("svc-cowork") || x.Id.StartsWith("svc-codex"));
    }

    [Fact]
    public void StartsWithWindowsToo_CardSaysToTurnThatOffAsWell()
    {
        var snap = Snap(Use("CoworkVMService")) with { Startup = [new("Claude", @"""C:\Users\b\AppData\Local\AnthropicClaude\claude.exe""", true)] };
        var steps = string.Join(" ", MemorySuggestionEngine.Build(snap).Single(x => x.Id == "svc-coworkvmservice").Steps);
        Assert.Contains("Claude also starts with Windows on this PC", steps);
        var off = snap with { Startup = [new("Claude", @"""C:\x\claude.exe""", false)] };
        Assert.DoesNotContain("also starts with Windows", string.Join(" ", MemorySuggestionEngine.Build(off).Single(x => x.Id == "svc-coworkvmservice").Steps));
    }

    [Fact]
    public void Workflow_ListsIt_Ticked_Admin_FullUndo_NoDoubledSuffix()
    {
        var fixes = FixCatalog.Build([], MemorySuggestionEngine.Build(Snap(Use("CoworkVMService"), Use(Codex))));
        foreach (var name in new[] { "CoworkVMService", Codex })
        {
            var fix = fixes.Single(f => f.MemoryTarget == name);
            Assert.Equal(MemoryActionType.SetServiceManual, fix.MemoryAction);
            Assert.True(fix.DefaultOn);
            Assert.True(fix.NeedsAdmin);
            Assert.Equal(UndoSupport.Full, fix.Undo);
            Assert.DoesNotContain(": start only when needed", fix.Title);
        }
        Assert.True(MemoryFeedback.IsDeferred(MemoryActionType.SetServiceManual));
    }

    // ---------------- services to Manual: apply, read back, journal, undo ----------------

    [Fact]
    public async Task Apply_SetsManual_ReadsBack_Journals_UndoRestoresAutomatic()
    {
        var (sys, j, svc) = Make(Snap(Use("CoworkVMService")));
        sys.StartTypes["CoworkVMService"] = "AutomaticDelayed";
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "svc-coworkvmservice");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("was AutomaticDelayed", r.Message);
        Assert.Equal("Manual", sys.StartTypes["CoworkVMService"]);
        var rec = Assert.Single(j.All);
        Assert.Equal(ChangeKind.ServiceStartType, rec.Kind);
        Assert.Equal("CoworkVMService", rec.Target);
        Assert.Equal("AutomaticDelayed", rec.Previous);
        Assert.Contains("was AutomaticDelayed", rec.Label);

        var u = svc.UndoFor("svc-coworkvmservice")!;
        Assert.True((await svc.UndoAsync(u)).Success);
        Assert.Equal("AutomaticDelayed", sys.StartTypes["CoworkVMService"]);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Apply_DidntStick_NothingJournaled()
    {
        var (sys, j, svc) = Make(Snap(Use(Codex)));
        sys.Ignored.Add(Codex);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id.StartsWith("svc-codex"));
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Nothing was changed", r.Message);
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(s.Id));
    }

    [Fact]
    public async Task UndoAll_RestoresTheOldStartType()
    {
        var (sys, j, svc) = Make(Snap(Use("CoworkVMService")));
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "svc-coworkvmservice");
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");
        Assert.Equal(1, r.Succeeded);
        Assert.Equal("Automatic", sys.StartTypes["CoworkVMService"]);
        Assert.Empty(j.All);
    }

    // ---------------- wsl --shutdown ----------------

    [Fact]
    public void Wsl_Offered_WhenVmmemWslIsLarge_AndNothingUsesLinux()
    {
        var s = MemorySuggestionEngine.Build(Apps(Vm(), new AppUsage("chrome", 10, 900 * Mb, HasWindow: true), new AppUsage("wslservice", 1, 20 * Mb))).Single(x => x.Id == "wsl-shutdown");
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.Equal(2 * Gb, s.SavingBytes);
        var a = Assert.Single(s.Actions);
        Assert.Equal(MemoryActionType.ShutdownWsl, a.Type);
        Assert.Contains("closes all running Linux distributions and anything running in them", a.Confirm);
        Assert.Contains("Claude", a.Confirm);
        var steps = string.Join(" ", s.Steps);
        Assert.Contains("Claude Desktop runs its own Linux virtual machine", steps);
        Assert.Contains("interrupts that task until it starts again", steps);
        Assert.Contains("Nothing to undo", steps);
        Assert.Equal(UndoSupport.NothingToUndo, Undoability.Of(MemoryActionType.ShutdownWsl));
        Assert.False(MemoryFeedback.IsDeferred(MemoryActionType.ShutdownWsl));
    }

    [Theory]
    [InlineData("wsl")]
    [InlineData("wslhost")]
    [InlineData("bash")]
    [InlineData("ubuntu2204")]
    [InlineData("Docker Desktop")]
    [InlineData("com.docker.backend")]
    [InlineData("com.docker.build")]
    [InlineData("podman")]
    [InlineData("openSUSE-Tumbleweed")]
    public void Wsl_NotOffered_WhenLinuxLooksInUse(string busy) =>
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Apps(Vm(), new AppUsage(busy, 1, 10 * Mb))), x => x.Id == "wsl-shutdown");

    [Fact]
    public void Wsl_NotOffered_ForSmallVm_PlainVmmem_OrNoVm()
    {
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Apps(Vm(100 * Mb))), x => x.Id == "wsl-shutdown");
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Apps(new AppUsage("vmmem", 1, 4 * Gb))), x => x.Id == "wsl-shutdown"); // Claude's / Hyper-V VM: wsl --shutdown wouldn't free it
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Apps()), x => x.Id == "wsl-shutdown");
    }

    [Fact]
    public void Wsl_NotInTheWorkflow_ReportSaysTheRestartCoversIt()
    {
        var list = MemorySuggestionEngine.Build(Apps(Vm()));
        Assert.DoesNotContain(MemoryActionType.ShutdownWsl, FixCatalog.UnattendedMemoryActions);
        Assert.DoesNotContain(FixCatalog.Build([], list), f => f.SuggestionId == "wsl-shutdown");
        Assert.Contains(FixCatalog.NotOffered([], list), l => l.StartsWith("Shut down the idle Linux (WSL) virtual machine: not needed"));
        Assert.DoesNotContain(FixCatalog.Recommendations(list), l => l.Contains("WSL"));
    }

    [Fact]
    public void Wsl_Allowlist_OnlySystem32WslWithShutdown()
    {
        var cmd = MemoryCommandAllowlist.WslShutdown;
        Assert.EndsWith(@"\System32\wsl.exe", cmd.FileName);
        Assert.Equal(new[] { "--shutdown" }, cmd.Arguments);
        Assert.True(MemoryCommandAllowlist.IsAllowed(cmd.FileName, ["--shutdown"]));
        Assert.True(MemoryCommandAllowlist.IsAllowed(cmd.FileName.ToUpperInvariant(), ["--shutdown"]));
        Assert.False(MemoryCommandAllowlist.IsAllowed("wsl", ["--shutdown"]));                              // never from PATH
        Assert.False(MemoryCommandAllowlist.IsAllowed("wsl.exe", ["--shutdown"]));
        Assert.False(MemoryCommandAllowlist.IsAllowed(@"C:\Temp\wsl.exe", ["--shutdown"]));
        Assert.False(MemoryCommandAllowlist.IsAllowed(cmd.FileName, ["--unregister", "Ubuntu"]));
        Assert.False(MemoryCommandAllowlist.IsAllowed(cmd.FileName, ["--shutdown", "--force"]));
        Assert.False(MemoryCommandAllowlist.IsAllowed(cmd.FileName, ["-e", "rm"]));
        Assert.False(MemoryCommandAllowlist.IsAllowed(cmd.FileName, []));
        Assert.True(MemoryCommandAllowlist.IsAllowed("dotnet", ["build-server", "shutdown"]));             // unchanged
    }

    [Fact]
    public async Task Wsl_Apply_RunsOnlyTheAllowlistedCommand_NothingJournaled()
    {
        var (sys, j, svc) = Make(Apps(Vm()));
        sys.Running = ["vmmemWSL", "chrome", "explorer"];
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "wsl-shutdown");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Equal($"run:{MemoryCommandAllowlist.WslShutdown.FileName} --shutdown", Assert.Single(sys.Calls));
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor("wsl-shutdown"));
    }

    [Fact]
    public async Task Wsl_Apply_RefusedWhenLinuxStartedBeingUsedSinceTheScan()
    {
        var (sys, j, svc) = Make(Apps(Vm()));
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "wsl-shutdown");
        sys.Running = ["vmmemWSL", "wsl", "Docker Desktop"];
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Linux is in use now", r.Message);
        Assert.Empty(sys.Calls);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Wsl_Apply_CommandFailure_IsReported()
    {
        var (sys, _, svc) = Make(Apps(Vm()));
        sys.CommandResult = new(false, "WSL didn't shut down.");
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "wsl-shutdown");
        Assert.False((await svc.ApplyAsync(s, s.Actions[0])).Success);
    }
}
