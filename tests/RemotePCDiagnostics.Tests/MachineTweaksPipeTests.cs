using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// HKLM policy values, the browsers' extension blocklists, the page file and Defender exclusions are changed by the Agent over the admin
/// pipe (<see cref="AdminPipeFraming.OpMachineTweak"/>); the app never makes these changes itself (it never runs as administrator).
/// </summary>
public sealed class MachineTweaksPipeTests
{
    private const string Honey = "bmnlcjabgnpnenekpadlanbbkooimhnj";
    private const string Vs = @"C:\Program Files\Microsoft Visual Studio\18\Community\";

    /// <summary>Path rules as on a Windows PC, without touching the disk.</summary>
    private static readonly DefenderPaths Paths = new(
        [@"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData"],
        [@"C:\Program Files", @"C:\Program Files (x86)"],
        dir => !dir.Contains("missing", StringComparison.OrdinalIgnoreCase),
        file => !file.Contains("missing", StringComparison.OrdinalIgnoreCase));

    private static readonly string PageFile = PageFileSettings.Encode([new(@"C:\pagefile.sys", 4096, 8192)]);

    [Fact]
    public async Task The_agent_makes_each_change_and_sends_back_what_it_read()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var backend = new FakeTweaks();
        var (server, task, client) = await StartAsync(backend, cts.Token);
        using (server)
        {
            await using (client)
            {
                var app = new AgentMachineTweaks(new ClientBridge(client));
                app.WriteDword(RegistryAllowlist.WidgetsPolicy, 0);
                app.DeleteDword(RegistryAllowlist.EdgeStartupBoostPolicy);
                Assert.True(app.DeleteKeyIfEmpty(@"SOFTWARE\Policies\Microsoft\Dsh"));
                Assert.False(app.DeleteKeyIfEmpty(@"SOFTWARE\Policies\Microsoft\Edge"));
                app.AddExtensionBlock(BrowserKind.Chrome, "3", Honey);
                app.RemoveExtensionBlock(BrowserKind.Edge, "1", Honey);
                Assert.True((await app.EnableAutoPageFileAsync(cts.Token)).Success);
                var restored = await app.RestorePageFileAsync(PageFile, cts.Token);
                Assert.True(restored.Success, restored.Message);
                Assert.Equal("restored 1", restored.Message);
                Assert.Equal(FakeTweaks.Probe, await app.ReadDefenderAsync(cts.Token));
                var (ok, readBack) = await app.AddDefenderExclusionsAsync([@"D:\work", @"C:\Users\ann\.nuget\packages"], [Vs + @"MSBuild\Current\Bin\MSBuild.exe"], cts.Token);
                Assert.True(ok);
                Assert.Equal(FakeTweaks.ReadBack, readBack);
                Assert.True(await app.RemoveDefenderExclusionsAsync([@"D:\work"], [], cts.Token));
            }
            await task;
        }

        Assert.Equal(
        [
            @"write HKLM\SOFTWARE\Policies\Microsoft\Dsh|AllowNewsAndInterests=0", @"delete HKLM\SOFTWARE\Policies\Microsoft\Edge|StartupBoostEnabled",
            @"key SOFTWARE\Policies\Microsoft\Dsh", @"key SOFTWARE\Policies\Microsoft\Edge", "block Chrome 3 " + Honey, "unblock Edge 1 " + Honey,
            "pagefile auto", "pagefile restore", "defender read", @"defender add D:\work;C:\Users\ann\.nuget\packages | " + Vs + @"MSBuild\Current\Bin\MSBuild.exe",
            @"defender remove D:\work | ",
        ], backend.Calls);
    }

    public static TheoryData<AdminPipeTweak> Refused() =>
    [
        new AdminPipeTweak(AdminPipeTweak.RegistryWrite, Target: RegistryAllowlist.SearchHighlightsToggle.Target, Number: 0),   // per-account: the app's own
        new AdminPipeTweak(AdminPipeTweak.RegistryWrite, Target: @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa|RunAsPPL", Number: 0),
        new AdminPipeTweak(AdminPipeTweak.RegistryWrite, Target: RegistryAllowlist.WidgetsPolicy.Target),                        // no value
        new AdminPipeTweak(AdminPipeTweak.RegistryDelete, Target: @"HKLM\SOFTWARE\Microsoft\Windows Defender|DisableAntiSpyware"),
        new AdminPipeTweak(AdminPipeTweak.RegistryKeyDelete, Target: @"SYSTEM\CurrentControlSet\Services"),
        new AdminPipeTweak(AdminPipeTweak.RegistryKeyDelete, Target: "SOFTWARE"),
        new AdminPipeTweak(AdminPipeTweak.ExtensionBlockAdd, Target: "Chrome", Name: "1", Text: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), // not on the allowlist
        new AdminPipeTweak(AdminPipeTweak.ExtensionBlockAdd, Target: "Chrome", Name: "*", Text: Honey),
        new AdminPipeTweak(AdminPipeTweak.ExtensionBlockAdd, Target: "Firefox", Name: "1", Text: Honey),
        new AdminPipeTweak(AdminPipeTweak.ExtensionBlockRemove, Target: "Chrome", Name: "01", Text: Honey),
        new AdminPipeTweak(AdminPipeTweak.PageFileRestore, Text: "not base64!"),
        new AdminPipeTweak(AdminPipeTweak.PageFileRestore, Text: PageFileSettings.Encode([new(@"C:\Windows\System32\config\SAM", 1, 1)])),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"C:\"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"C:\Windows\Temp"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"C:\Program Files\Evil"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"C:\ProgramData"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"C:\Users\ann"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"C:\Users\ann\Downloads\tools"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"C:\Users\ann\AppData\Local\Temp"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"C:\Users\ann\Documents"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"D:\work\*"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"D:\work\..\..\Windows"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"\\server\share\code"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: [@"D:\missing"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Processes: [@"C:\Users\ann\Downloads\MSBuild.exe"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Processes: [Vs + @"Common7\IDE\cmd.exe"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Processes: ["powershell.exe"]),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd),
        new AdminPipeTweak(AdminPipeTweak.DefenderAdd, Folders: Enumerable.Range(0, MachineTweakRules.MaxDefenderFolders + 1).Select(i => $@"D:\work\p{i}").ToList()),
        new AdminPipeTweak("run_script", Text: "Set-MpPreference -DisableRealtimeMonitoring $true"),
    ];

    [Theory]
    [MemberData(nameof(Refused))]
    public async Task The_agent_refuses_anything_else(AdminPipeTweak tweak)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var backend = new FakeTweaks();
        var (server, task, client) = await StartAsync(backend, cts.Token);
        using (server)
        {
            await using (client)
            {
                var r = await client.MachineTweakAsync(tweak, cts.Token);
                Assert.False(r.Ok);
                Assert.True(r.Allowed); // an answer from this Agent (not "update"), with the reason
                Assert.False(string.IsNullOrEmpty(r.Error));
            }
            await task;
        }
        Assert.Empty(backend.Calls);
    }

    [Fact]
    public void The_rules_allow_what_the_fixes_and_undo_send()
    {
        Assert.Null(MachineTweakRules.Refusal(new(AdminPipeTweak.RegistryWrite, Target: RegistryAllowlist.SearchHighlightsPolicy.Target, Number: 0)));
        Assert.Null(MachineTweakRules.Refusal(new(AdminPipeTweak.RegistryKeyDelete, Target: BrowserExtensions.BlocklistKey(BrowserKind.Edge))));
        Assert.Null(MachineTweakRules.Refusal(new(AdminPipeTweak.DefenderAdd, Folders: [@"D:\work", @"C:\src", @"C:\Users\ann\source\repos", @"C:\Users\ann\.nuget\packages"],
            Processes: [Vs + @"Common7\IDE\devenv.exe", @"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\VBCSCompiler.exe"]), Paths));
        // Undo removes an exclusion even after its folder or Visual Studio is gone.
        Assert.Null(MachineTweakRules.Refusal(new(AdminPipeTweak.DefenderRemove, Folders: [@"D:\missing"], Processes: [@"C:\Program Files\Microsoft Visual Studio\missing\Community\MSBuild\Current\Bin\MSBuild.exe"]), Paths));
        Assert.NotNull(MachineTweakRules.Refusal(new(AdminPipeTweak.DefenderAdd, Processes: [@"C:\Program Files\Microsoft Visual Studio\missing\Community\MSBuild\Current\Bin\MSBuild.exe"]), Paths));
        Assert.Null(MachineTweakRules.Refusal(new(AdminPipeTweak.PageFileRestore, Text: PageFile)));
    }

    [Fact]
    public async Task Without_the_agent_nothing_is_changed_and_the_message_says_what_to_do()
    {
        var notConnected = new FakeBridge { IsConnected = false };
        var app = new AgentMachineTweaks(notConnected);
        Assert.Contains("Admin Repair Mode", Assert.Throws<AdminRequiredException>(() => app.WriteDword(RegistryAllowlist.WidgetsPolicy, 0)).Message);
        Assert.Throws<AdminRequiredException>(() => app.AddExtensionBlock(BrowserKind.Chrome, "1", Honey));
        var pf = await app.EnableAutoPageFileAsync(CancellationToken.None);
        Assert.False(pf.Success);
        Assert.Contains("Admin Repair Mode", pf.Message);
        await Assert.ThrowsAsync<AdminRequiredException>(() => app.AddDefenderExclusionsAsync([@"D:\work"], [], CancellationToken.None));
        Assert.Null(await app.ReadDefenderAsync(CancellationToken.None)); // the app reads what it can itself
        Assert.Empty(notConnected.Sent);
    }

    [Fact]
    public async Task An_older_agent_without_these_changes_says_to_update()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (server, task, client) = await StartAsync(null, cts.Token);
        using (server)
        {
            await using (client)
            {
                var app = new AgentMachineTweaks(new ClientBridge(client));
                Assert.Contains("Update", Assert.Throws<AdminRequiredException>(() => app.WriteDword(RegistryAllowlist.WidgetsPolicy, 0)).Message);
                Assert.Contains("Update", (await app.RestorePageFileAsync(PageFile, cts.Token)).Message);
                Assert.Null(await app.ReadDefenderAsync(cts.Token));
            }
            await task;
        }
    }

    [Fact]
    public async Task A_widgets_fix_without_the_agent_shows_what_to_do_and_journals_nothing()
    {
        var sys = new AgentRegistry(new AgentMachineTweaks(null));
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, settle: TimeSpan.Zero, journal: j);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "widgets");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Equal("The Agent isn't connected. " + ElevationService.AdminRepairHint, r.Message);
        Assert.Empty(j.All);
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(IMachineTweaks? backend, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")), machineTweaks: backend, defenderPaths: Paths);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }

    private sealed class FakeTweaks : IMachineTweaks
    {
        public const string Probe = """{"On":"True","Mode":"Normal","Paths":["D:\\old"],"Procs":[]}""";
        public const string ReadBack = """{"Paths":["D:\\work"],"Procs":[]}""";
        public List<string> Calls { get; } = [];
        public void WriteDword(RegistrySetting setting, int value) => Calls.Add($"write {setting.Target}={value}");
        public void DeleteDword(RegistrySetting setting) => Calls.Add("delete " + setting.Target);
        public bool DeleteKeyIfEmpty(string key) { Calls.Add("key " + key); return key.EndsWith("Dsh", StringComparison.Ordinal); }
        public void AddExtensionBlock(BrowserKind browser, string valueName, string extensionId) => Calls.Add($"block {browser} {valueName} {extensionId}");
        public void RemoveExtensionBlock(BrowserKind browser, string valueName, string extensionId) => Calls.Add($"unblock {browser} {valueName} {extensionId}");
        public Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct) { Calls.Add("pagefile auto"); return Task.FromResult(new ActionOutcome(true, "auto")); }
        public Task<ActionOutcome> RestorePageFileAsync(string settings, CancellationToken ct)
        {
            Calls.Add("pagefile restore");
            return Task.FromResult(new ActionOutcome(true, "restored " + PageFileSettings.TryDecode(settings)!.Count));
        }
        public Task<string?> ReadDefenderAsync(CancellationToken ct) { Calls.Add("defender read"); return Task.FromResult<string?>(Probe); }
        public Task<(bool Ok, string? Output)> AddDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct)
        {
            Calls.Add($"defender add {string.Join(";", folders)} | {string.Join(";", processes)}");
            return Task.FromResult<(bool, string?)>((true, ReadBack));
        }
        public Task<bool> RemoveDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct)
        {
            Calls.Add($"defender remove {string.Join(";", folders)} | {string.Join(";", processes)}");
            return Task.FromResult(true);
        }
    }

    /// <summary>The app's bridge, as the window has it: the connected client.</summary>
    private sealed class ClientBridge(AdminPipeClient client) : FakeBridge
    {
        public override Task<AdminPipeResponse> MachineTweakAsync(AdminPipeTweak tweak, CancellationToken ct = default) => client.MachineTweakAsync(tweak, ct);
    }

    private class FakeBridge : IElevatedCommandBridge
    {
        public bool IsConnected { get; set; } = true;
        public List<AdminPipeTweak> Sent { get; } = [];
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);
        public Task<RemotePCDiagnostics.Core.Sensors.SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) =>
            Task.FromResult<RemotePCDiagnostics.Core.Sensors.SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
        public virtual Task<AdminPipeResponse> MachineTweakAsync(AdminPipeTweak tweak, CancellationToken ct = default)
        {
            Sent.Add(tweak);
            return Task.FromResult(new AdminPipeResponse(true));
        }
    }

    /// <summary>The Host's shape: HKLM values through the Agent, nothing else.</summary>
    private sealed class AgentRegistry(IMachineTweaks machine) : IMemorySystem
    {
        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => Task.FromResult(new MemorySnapshot(ReadMemory(), [new("WidgetBoard", 1, 200L << 20)], Feeds: new(22631, WidgetsInstalled: true)));
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
        public int? ReadDword(RegistrySetting setting) => null;
        public void WriteDword(RegistrySetting setting, int value) => machine.WriteDword(setting, value);
        public void DeleteDword(RegistrySetting setting) => machine.DeleteDword(setting);
        public bool RegistryKeyExists(RegistryRoot root, string key) => true;
    }
}
