using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Modules.BatteryPower;
using RemotePCDiagnostics.Modules.DeveloperSetup;
using Xunit;
using DataRegistryRoot = RemotePCDiagnostics.Core.DataSources.RegistryRoot;

namespace RemotePCDiagnostics.Tests;

public sealed class Batch2ReversibleFixesTests
{
    private static readonly Guid BalancedScheme = Guid.Parse("381b4222-f694-41f0-9685-ff5bb260df2e");
    private static readonly Guid OtherScheme = Guid.Parse("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");

    private static WmiRow Row(params (string K, long V)[] pairs) =>
        new(pairs.ToDictionary(p => p.K, p => System.Text.Json.JsonSerializer.SerializeToElement(p.V)));

    // -------------------------------------------------------------------------
    // 2a. Storage Sense
    // -------------------------------------------------------------------------

    [Fact]
    public async Task StorageSense_PolicyPresent_ShowsStateAndOffersNoFix()
    {
        var reg = new FakeRegistrySource(new Dictionary<string, WmiRow>
        {
            [StorageSenseReader.PolicyKey] = Row((StorageSenseReader.PolicyGlobalValueName, 0)),
            [StorageSenseReader.UserKey] = Row(("01", 0), ("2048", 7)),
        });

        var status = await StorageSenseReader.ReadAsync(reg, CancellationToken.None);

        Assert.NotNull(status);
        Assert.True(status!.PolicyControlled);
        Assert.False(status.Enabled);
        Assert.False(status.CanOfferEnable);

        var card = DriveHealthModule.BuildStorageSenseCard(status);
        Assert.Contains("policy", card.Note ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Null(card.Actions);
    }

    [Fact]
    public async Task StorageSense_PolicyAbsentAndOff_OffersEnableFixAndPreservesOtherValuesAndUndoes()
    {
        var reg = new FakeRegistrySource(new Dictionary<string, WmiRow>
        {
            [StorageSenseReader.UserKey] = Row(("01", 0), ("2048", 7), ("04", 1), ("08", 1), ("256", 30), ("32", 0), ("512", 0)),
        });

        var status = await StorageSenseReader.ReadAsync(reg, CancellationToken.None);
        Assert.NotNull(status);
        Assert.False(status!.PolicyControlled);
        Assert.False(status.Enabled);
        Assert.True(status.CanOfferEnable);
        Assert.Contains("Every week", status.DescribeEffectiveBehavior(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Downloads: Never", status.DescribeEffectiveBehavior(), StringComparison.OrdinalIgnoreCase);

        var card = DriveHealthModule.BuildStorageSenseCard(status);
        var action = Assert.Single(card.Actions!);
        Assert.Equal(RemediationKind.EnableStorageSense, action.Kind);

        // Apply via RemediationService: must write ONLY "01" = 1 and preserve all other values.
        var tweaks = new FakeRegistryTweaks();
        tweaks.Values[RegistryAllowlist.StorageSenseEnabled.Target] = 0;
        tweaks.ExtraValues["2048"] = 7;
        tweaks.ExtraValues["32"] = 0;
        tweaks.ExistingKeys.Add(RegistryAllowlist.StorageSenseEnabled.Key);

        var journal = new InMemoryChangeJournal();
        var svc = new RemediationService(new SystemCommandRunner(), journal: journal, registryTweaks: tweaks);
        var res = await svc.ExecuteAsync(action, CancellationToken.None);

        Assert.True(res.Success);
        Assert.Equal(1, tweaks.Values[RegistryAllowlist.StorageSenseEnabled.Target]);
        Assert.Equal(7, tweaks.ExtraValues["2048"]);
        Assert.Equal(0, tweaks.ExtraValues["32"]);
        var rec = Assert.Single(journal.All);
        Assert.Equal(ChangeKind.RegistryValue, rec.Kind);
        Assert.Equal(RegistryAllowlist.StorageSenseEnabled.Target, rec.Target);
        Assert.Equal("0", rec.Previous);

        // Undo round-trip restores 0.
        var undo = new UndoService(journal, new SystemCommandRunner(), memory: tweaks);
        var undoRes = await undo.UndoAllAsync("test", CancellationToken.None);
        Assert.Equal(1, undoRes.Succeeded);
        Assert.Equal(0, tweaks.Values[RegistryAllowlist.StorageSenseEnabled.Target]);
    }

    [Fact]
    public async Task StorageSense_FailedWrite_ReturnsFailureAndDoesNotJournal()
    {
        var tweaks = new FakeRegistryTweaks { FailWrite = true };
        var journal = new InMemoryChangeJournal();
        var svc = new RemediationService(new SystemCommandRunner(), journal: journal, registryTweaks: tweaks);

        var res = await svc.ExecuteAsync(new AreaAction(RemediationKind.EnableStorageSense, "Turn on Storage Sense", "", "Storage Sense"), CancellationToken.None);

        Assert.False(res.Success);
        Assert.Empty(journal.All);
    }

    // -------------------------------------------------------------------------
    // 2b. Max processor state back to 100%
    // -------------------------------------------------------------------------

    [Fact]
    public void PowerSettingTarget_Allowlist_AcceptsOnlyProcessorAcMax()
    {
        var valid = PowerSettingTarget.ForProcessorAcMax(BalancedScheme).Encode();
        Assert.True(PowerSettingTarget.TryParse(valid, out var parsed));
        Assert.Equal(BalancedScheme, parsed.SchemeGuid);
        Assert.True(parsed.IsAllowedProcessorAcMax);

        // Reject DC, wrong subgroup, wrong setting, malformed
        Assert.False(PowerSettingTarget.TryParse($"{BalancedScheme:D}|{WindowsPowerPolicyReader.SubProcessorGuid:D}|{WindowsPowerPolicyReader.ProcThrottleMaxGuid:D}|DC", out _));
        Assert.False(PowerSettingTarget.TryParse($"{BalancedScheme:D}|{Guid.NewGuid():D}|{WindowsPowerPolicyReader.ProcThrottleMaxGuid:D}|AC", out _));
        Assert.False(PowerSettingTarget.TryParse($"{BalancedScheme:D}|{WindowsPowerPolicyReader.SubProcessorGuid:D}|{Guid.NewGuid():D}|AC", out _));
        Assert.False(PowerSettingTarget.TryParse("not-a-target", out _));
    }

    [Fact]
    public void BatteryPowerModule_MaxProcessorState_OffersFixOnlyWhenBelow100AndEditable()
    {
        var bat = new BatteryStatus("BAT0", "OEM", "Li-Ion", "Plugged in", 100, 50000, 48000, 12, PowerOnline: true);

        var editableCapped = new PowerPolicySnapshot("Balanced", AcMaxProcessorStatePercent: 80, AcMaxProcessorStateEditable: true);
        var r1 = BatteryPowerModule.Build([bat], null, policy: editableCapped);
        var card1 = Assert.Single(r1.Cards, c => c.Id == "plan");
        Assert.Contains(card1.Actions ?? [], a => a.Kind == RemediationKind.ResetMaxProcessorState);

        var policyLocked = new PowerPolicySnapshot("Balanced", AcMaxProcessorStatePercent: 80, AcMaxProcessorStateEditable: false);
        var r2 = BatteryPowerModule.Build([bat], null, policy: policyLocked);
        var card2 = Assert.Single(r2.Cards, c => c.Id == "plan");
        Assert.DoesNotContain(card2.Actions ?? [], a => a.Kind == RemediationKind.ResetMaxProcessorState);
        Assert.Contains("Group Policy", card2.Note ?? "", StringComparison.OrdinalIgnoreCase);

        var absentSetting = new PowerPolicySnapshot("Balanced", AcMaxProcessorStatePercent: null, AcMaxProcessorStateEditable: true);
        var r3 = BatteryPowerModule.Build([bat], null, policy: absentSetting);
        var card3 = Assert.Single(r3.Cards, c => c.Id == "plan");
        Assert.DoesNotContain(card3.Actions ?? [], a => a.Kind == RemediationKind.ResetMaxProcessorState);
    }

    [Fact]
    public async Task PowerSettingController_PermissionDenied_FallsBackToAgentAndJournals()
    {
        var agent = new FakeElevatedBridge { Connected = true, PowerSettingSucceeds = true };
        var ctrl = new WindowsPowerSettingController(
            agent: agent,
            readActiveScheme: () => BalancedScheme,
            isEditable: () => true,
            readValue: _ => 80,
            writeValue: (_, _) => WindowsPowerPolicyReader.ErrorAccessDenied);

        var journal = new InMemoryChangeJournal();
        var svc = new RemediationService(new SystemCommandRunner(), journal: journal, powerSettings: ctrl);
        var res = await svc.ExecuteAsync(new AreaAction(RemediationKind.ResetMaxProcessorState, "Set back to 100%", "", "Max processor state"), CancellationToken.None);

        Assert.True(res.Success);
        Assert.Equal(1, agent.PowerSettingCalls);
        Assert.Equal(100, agent.LastPowerSettingValue);
        var rec = Assert.Single(journal.All);
        Assert.Equal(ChangeKind.PowerSetting, rec.Kind);
        Assert.Equal("80", rec.Previous);
    }

    [Fact]
    public async Task PowerSettingController_PolicyOverrideAndAbsentSetting_RefuseWithoutWriting()
    {
        var writes = 0;
        var locked = new WindowsPowerSettingController(
            readActiveScheme: () => BalancedScheme,
            isEditable: () => false,
            readValue: _ => 75,
            writeValue: (_, _) => { writes++; return 0; });

        var rLocked = await locked.WriteAcMaxProcessorStateAsync(BalancedScheme, 100, true, CancellationToken.None);
        Assert.False(rLocked.Success);
        Assert.True(rLocked.PolicyLocked);
        Assert.Equal(0, writes);

        var absent = new WindowsPowerSettingController(
            readActiveScheme: () => BalancedScheme,
            isEditable: () => true,
            readValue: _ => null,
            writeValue: (_, _) => { writes++; return 0; });

        var rAbsent = await absent.WriteAcMaxProcessorStateAsync(BalancedScheme, 100, true, CancellationToken.None);
        Assert.False(rAbsent.Success);
        Assert.Equal(0, writes);
    }

    [Fact]
    public async Task PowerSettingController_ActivationFailure_CleanRollbackDoesNotJournal_FailedRollbackJournalsPartial()
    {
        // Case 1: activation fails, rollback succeeds -> no journal entry
        var current = 70;
        var cleanRollbackCtrl = new WindowsPowerSettingController(
            readActiveScheme: () => BalancedScheme,
            isEditable: () => true,
            readValue: _ => current,
            writeValue: (_, v) => { current = v; return 0; },
            setActiveScheme: _ => 87);

        var j1 = new InMemoryChangeJournal();
        var svc1 = new RemediationService(new SystemCommandRunner(), journal: j1, powerSettings: cleanRollbackCtrl);
        var res1 = await svc1.ExecuteAsync(new AreaAction(RemediationKind.ResetMaxProcessorState, "Reset", "", ""), CancellationToken.None);
        Assert.False(res1.Success);
        Assert.Equal(70, current);
        Assert.Empty(j1.All);

        // Case 2: activation fails AND rollback fails -> journals partial change with original value 70
        var stuck = 70;
        var writeCount = 0;
        var failedRollbackCtrl = new WindowsPowerSettingController(
            readActiveScheme: () => BalancedScheme,
            isEditable: () => true,
            readValue: _ => stuck,
            writeValue: (_, v) =>
            {
                writeCount++;
                if (writeCount == 1) { stuck = v; return 0; }
                return 5; // rollback fails
            },
            setActiveScheme: _ => 87);

        var j2 = new InMemoryChangeJournal();
        var svc2 = new RemediationService(new SystemCommandRunner(), journal: j2, powerSettings: failedRollbackCtrl);
        var res2 = await svc2.ExecuteAsync(new AreaAction(RemediationKind.ResetMaxProcessorState, "Reset", "", ""), CancellationToken.None);
        Assert.False(res2.Success);
        Assert.Equal(100, stuck);
        var partial = Assert.Single(j2.All);
        Assert.Equal(ChangeKind.PowerSetting, partial.Kind);
        Assert.Equal("70", partial.Previous);
    }

    [Fact]
    public async Task PowerSetting_UndoAfterSwitchingSchemes_RestoresRecordedSchemeWithoutActivatingOldPlan()
    {
        var values = new Dictionary<Guid, int> { [BalancedScheme] = 80, [OtherScheme] = 100 };
        var active = BalancedScheme;
        var activated = new List<Guid>();

        var ctrl = new WindowsPowerSettingController(
            readActiveScheme: () => active,
            isEditable: () => true,
            readValue: s => values.TryGetValue(s, out var v) ? v : null,
            writeValue: (s, v) => { values[s] = v; return 0; },
            setActiveScheme: s => { activated.Add(s); return 0; });

        var journal = new InMemoryChangeJournal();
        var svc = new RemediationService(new SystemCommandRunner(), journal: journal, powerSettings: ctrl);
        var apply = await svc.ExecuteAsync(new AreaAction(RemediationKind.ResetMaxProcessorState, "Reset", "", ""), CancellationToken.None);
        Assert.True(apply.Success);
        Assert.Equal(100, values[BalancedScheme]);
        Assert.Single(activated, BalancedScheme);

        // User switches to OtherScheme before clicking Undo.
        active = OtherScheme;
        activated.Clear();

        var undo = new UndoService(journal, new SystemCommandRunner(), powerSettings: ctrl);
        var undoRes = await undo.UndoAllAsync("test", CancellationToken.None);

        Assert.Equal(1, undoRes.Succeeded);
        Assert.Equal(80, values[BalancedScheme]);
        Assert.Empty(activated); // Must NOT reactivate BalancedScheme while OtherScheme is active.
    }

    // -------------------------------------------------------------------------
    // 2c. Dev Drive package caches, LongPathsEnabled, .wslconfig
    // -------------------------------------------------------------------------

    [Fact]
    public void DevDrivePackageCaches_Allowlist_RejectsCargoGradleAndUnknownVars()
    {
        Assert.True(DevDrivePackageCaches.IsAllowlisted("NUGET_PACKAGES"));
        Assert.True(DevDrivePackageCaches.IsAllowlisted("npm_config_cache"));
        Assert.True(DevDrivePackageCaches.IsAllowlisted("PIP_CACHE_DIR"));
        Assert.True(DevDrivePackageCaches.IsAllowlisted("VCPKG_DEFAULT_BINARY_CACHE"));

        Assert.False(DevDrivePackageCaches.IsAllowlisted("CARGO_HOME"));
        Assert.False(DevDrivePackageCaches.IsAllowlisted("GRADLE_USER_HOME"));
        Assert.False(DevDrivePackageCaches.IsAllowlisted("PATH"));

        Assert.True(DevDrivePackageCaches.TryParseActionTarget("NUGET_PACKAGES|D:\\", out var spec, out var folder));
        Assert.Equal("NUGET_PACKAGES", spec.EnvVar);
        Assert.Equal(@"D:\packages\nuget", folder);

        Assert.False(DevDrivePackageCaches.TryParseActionTarget("CARGO_HOME|D:\\", out _, out _));
        Assert.False(DevDrivePackageCaches.TryParseActionTarget("GRADLE_USER_HOME|D:\\", out _, out _));
    }

    [Fact]
    public void DevDrivePackageCaches_ParseWslConfigMemory_HandParsesIniCleanly()
    {
        var ini = """
            # Global WSL config
            [experimental]
            memory=1GB

            [wsl2]
            ; cap memory
            processors=8
            memory = 16GB # comment
            swap=4GB
            """;
        Assert.Equal("16GB", DevDrivePackageCaches.ParseWslConfigMemory(ini));
        Assert.Null(DevDrivePackageCaches.ParseWslConfigMemory("[experimental]\nmemory=8GB"));
    }

    [Fact]
    public void DeveloperSetupModule_ShowsCachesWithDevDriveActions_CargoGradleInfoOnly_AndReadOnlySystemRows()
    {
        var nugetSpec = DevDrivePackageCaches.WritableSpecs[0];
        var cargoSpec = DevDrivePackageCaches.InfoOnlySpecs[0];
        var caches = new List<PackageCacheInfo>
        {
            new(nugetSpec, @"C:\Users\dev\.nuget\packages", false, false, 1_500_000_000),
            new(cargoSpec, @"C:\Users\dev\.cargo", false, false, 900_000_000),
        };

        var report = DeveloperSetupModule.Build(
            [new(DeveloperLanguage.CSharp, ".NET SDK", "dotnet.exe", "10.0.100", 10), new(DeveloperLanguage.Rust, "Rust", "cargo.exe", "1.82.0", 1)],
            freeSpaceGb: 120,
            defender: null,
            devDrive: new(true, true, true, true),
            conditions: new(false, null, "Balanced", "Balanced"),
            packageCaches: caches,
            devDriveRoot: @"D:\",
            longPathsEnabled: false,
            wslInstalled: true,
            wslConfigMemory: "12GB");

        var cacheCard = Assert.Single(report.Cards, c => c.Id == "caches");
        var action = Assert.Single(cacheCard.Actions!);
        Assert.Equal(RemediationKind.MovePackageCacheToDevDrive, action.Kind);
        Assert.Equal(@"NUGET_PACKAGES|D:\", action.Target);
        Assert.Contains(cacheCard.Rows, r => r.Values[0].Contains("Cargo") && r.Values[3].Contains("Move by hand"));

        var sysCard = Assert.Single(report.Cards, c => c.Id == "dev-system");
        Assert.Contains(sysCard.Rows, r => r.Values[0].Contains("LongPathsEnabled") && r.Values[1] == "Disabled");
        Assert.Contains(sysCard.Rows, r => r.Values[0].Contains(".wslconfig") && r.Values[1] == "12GB");
    }

    [Fact]
    public async Task UserEnvironmentVariable_ApplyAndUndo_HandlesBothAbsentAndPreexistingValues()
    {
        var store = new FakeUserEnvironmentStore();
        var journal = new InMemoryChangeJournal();
        var svc = new RemediationService(new SystemCommandRunner(), journal: journal, userEnv: store);
        var undo = new UndoService(journal, new SystemCommandRunner(), userEnv: store);

        // Case 1: var was absent -> Undo deletes it
        var r1 = await svc.ExecuteAsync(new AreaAction(RemediationKind.MovePackageCacheToDevDrive, "Move NuGet", @"NUGET_PACKAGES|D:\", "NuGet"), CancellationToken.None);
        Assert.True(r1.Success);
        Assert.Equal(@"D:\packages\nuget", store.Read("NUGET_PACKAGES"));
        Assert.Contains(@"D:\packages\nuget", store.CreatedDirs);

        var u1 = await undo.UndoAllAsync("test", CancellationToken.None);
        Assert.Equal(1, u1.Succeeded);
        Assert.Null(store.Read("NUGET_PACKAGES"));

        // Case 2: var had an existing value -> Undo restores it
        store.Values["PIP_CACHE_DIR"] = @"E:\old-pip-cache";
        var r2 = await svc.ExecuteAsync(new AreaAction(RemediationKind.MovePackageCacheToDevDrive, "Move pip", @"PIP_CACHE_DIR|D:\", "pip"), CancellationToken.None);
        Assert.True(r2.Success);
        Assert.Equal(@"D:\packages\pip", store.Read("PIP_CACHE_DIR"));

        var u2 = await undo.UndoAllAsync("test", CancellationToken.None);
        Assert.Equal(1, u2.Succeeded);
        Assert.Equal(@"E:\old-pip-cache", store.Read("PIP_CACHE_DIR"));
    }

    // -------------------------------------------------------------------------
    // Fakes
    // -------------------------------------------------------------------------

    private sealed class FakeRegistrySource(Dictionary<string, WmiRow> rows) : IRegistrySource
    {
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct)
        {
            if (rows.TryGetValue(read.Path, out var row))
                return Task.FromResult(new WmiQueryResult("reg", read.Path, [row]));
            return Task.FromResult(new WmiQueryResult("reg", read.Path, null, "not found"));
        }
    }

    private sealed class FakeRegistryTweaks : IMemorySystem
    {
        public Dictionary<string, int?> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> ExtraValues { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> ExistingKeys { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool FailWrite { get; set; }

        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), []));
        public int? ReadDword(RegistrySetting s) => Values.TryGetValue(s.Target, out var v) ? v : null;
        public void WriteDword(RegistrySetting s, int value)
        {
            if (FailWrite) throw new UnauthorizedAccessException("Access denied");
            Values[s.Target] = value;
            ExistingKeys.Add(s.Key);
        }
        public void DeleteDword(RegistrySetting s) => Values.Remove(s.Target);
        public bool RegistryKeyExists(Core.Changes.RegistryRoot root, string subKey) => ExistingKeys.Contains(subKey);
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
    }

    private sealed class FakeUserEnvironmentStore : IUserEnvironmentStore
    {
        public Dictionary<string, string> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> CreatedDirs { get; } = [];

        public string? Read(string name) => Values.TryGetValue(name, out var v) ? v : null;
        public void Write(string name, string value) => Values[name] = value;
        public void Delete(string name) => Values.Remove(name);
        public void EnsureDirectory(string path) => CreatedDirs.Add(path);
    }

    private sealed class InMemoryChangeJournal : IChangeJournal
    {
        private readonly List<ChangeRecord> _records = [];
        public event Action? Changed;
        public IReadOnlyList<ChangeRecord> All => _records.AsReadOnly();
        public void Add(ChangeRecord record) { _records.Add(record); Changed?.Invoke(); }
        public void Remove(Guid id) { _records.RemoveAll(r => r.Id == id); Changed?.Invoke(); }
        public void RemoveLatest(ChangeKind kind, string target)
        {
            var idx = _records.FindLastIndex(r => r.Kind == kind && string.Equals(r.Target, target, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return;
            _records.RemoveAt(idx);
            Changed?.Invoke();
        }
        public void Clear() { _records.Clear(); Changed?.Invoke(); }
    }

    private sealed class FakeElevatedBridge : IElevatedCommandBridge
    {
        public bool Connected { get; set; }
        public bool PowerSettingSucceeds { get; set; }
        public int PowerSettingCalls { get; private set; }
        public int? LastPowerSettingValue { get; private set; }

        public bool IsConnected => Connected;
        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);
        public Task<Core.Sensors.SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) =>
            Task.FromResult<Core.Sensors.SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
        public Task<(bool Success, string Message)> SetPowerSettingAsync(string target, int value, bool activateIfActive, CancellationToken ct)
        {
            PowerSettingCalls++;
            LastPowerSettingValue = value;
            return Task.FromResult(PowerSettingSucceeds
                ? (true, $"Configured maximum processor state on AC set to {value}%.")
                : (false, "Agent rejected power setting."));
        }
    }
}
