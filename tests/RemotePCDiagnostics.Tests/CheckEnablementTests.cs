using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Checks;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Tests;

public class CheckEnablementTests
{
    [Fact]
    public async Task Report_lists_every_diagnostic_check_and_withholds_a_checkbox_when_the_hardware_is_missing()
    {
        var hidden = new HiddenCheck();
        var os = new PlainCheck(ModuleSlugs.Osquery, ModuleIds.Osquery, "Hardware inventory");
        var stress = new PlainCheck(ModuleSlugs.CpuStress, ModuleIds.CpuStress, "CPU stress test") { InRunAll = false };
        var diag = new DiagnosticsService(new ResultStore(), [os, hidden, stress]);
        await diag.RedetectAsync();

        var settings = new CheckSettings { Disabled = [ModuleSlugs.Osquery] };
        var choices = CheckEnableRules.Choices(diag, settings);

        Assert.Equal([ModuleSlugs.Osquery, ModuleSlugs.DriveHealth], choices.Select(c => c.Id));
        var inventory = choices.Single(c => c.Id == ModuleSlugs.Osquery);
        Assert.Equal("Hardware", inventory.Category);
        Assert.True(inventory.Available);
        Assert.False(inventory.Enabled);
        Assert.Null(inventory.Reason);

        var drive = choices.Single(c => c.Id == ModuleSlugs.DriveHealth);
        Assert.Equal("Storage", drive.Category);
        Assert.False(drive.Available);
        Assert.True(drive.Enabled);
        Assert.Equal("No drive found", drive.Reason);
        Assert.DoesNotContain(choices, c => c.Id == ModuleSlugs.CpuStress);

        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(AgentExports.BuildCheckEnablement(choices), AgentJson()));
        Assert.Equal(1, doc.RootElement.GetProperty("schema").GetInt32());
        var rows = doc.RootElement.GetProperty("checks").EnumerateArray().ToList();
        Assert.Equal([ModuleSlugs.Osquery, ModuleSlugs.DriveHealth], rows.Select(r => r.GetProperty("id").GetString()));
        var speed = rows[0];
        Assert.True(speed.GetProperty("available").GetBoolean());
        Assert.False(speed.GetProperty("enabled").GetBoolean());
        Assert.False(speed.TryGetProperty("reason", out _));
        var missing = rows[1];
        Assert.False(missing.GetProperty("available").GetBoolean());
        Assert.True(missing.GetProperty("enabled").GetBoolean());
        Assert.Equal("No drive found", missing.GetProperty("reason").GetString());
        Assert.False(missing.TryGetProperty("control", out _));
    }

    [Fact]
    public async Task A_hidden_check_is_left_out_until_detection_finishes()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var hidden = new HiddenCheck { Hold = gate.Task };
        var diag = new DiagnosticsService(new ResultStore(), [hidden]);

        Assert.Empty(diag.CheckChoices());
        gate.TrySetResult();
        await diag.RedetectAsync();

        var choice = Assert.Single(diag.CheckChoices());
        Assert.False(choice.Available);
        Assert.Equal("No drive found", choice.Reason);
    }

    [Fact]
    public void Enabling_and_disabling_saves_the_set_the_checkbox_and_the_bulk_buttons_use()
    {
        Assert.Equal("check-enable-Osquery", CheckEnableRules.Control(ModuleSlugs.Osquery));
        Assert.Equal("check-enable-DriveHealth", CheckEnableRules.Control(ModuleSlugs.DriveHealth));

        var store = new MemoryCheckSettingsStore();
        var settings = new CheckSettingsService(store);
        Assert.True(settings.IsEnabled(ModuleSlugs.Osquery));

        settings.SetEnabled(ModuleSlugs.Osquery, on: false, available: true);
        Assert.Equal([ModuleSlugs.Osquery], store.State!.Disabled);
        Assert.False(settings.IsEnabled(ModuleSlugs.Osquery));
        Assert.True(settings.IsEnabled(ModuleSlugs.DriveHealth));

        settings.SetEnabled(ModuleSlugs.DriveHealth, on: true, available: false);
        Assert.Equal([ModuleSlugs.Osquery], settings.Settings.Disabled);

        settings.SetAll([ModuleSlugs.Osquery, ModuleSlugs.DriveHealth], on: false);
        Assert.Equal([ModuleSlugs.DriveHealth, ModuleSlugs.Osquery], settings.Settings.Disabled);
        settings.SetEnabled(ModuleSlugs.DriveHealth, on: false, available: false);
        Assert.Contains(ModuleSlugs.DriveHealth, settings.Settings.Disabled);
        settings.SetAll([ModuleSlugs.Osquery], on: true);
        Assert.Equal([ModuleSlugs.DriveHealth], settings.Settings.Disabled);

        var path = Path.Combine(Path.GetTempPath(), "rpd-checks-" + Guid.NewGuid().ToString("N"), ProtectedState.CheckSettingsFile);
        var file = new FileCheckSettingsStore(path);
        file.Save(settings.Settings);
        var loaded = file.Load();
        Assert.NotNull(loaded);
        Assert.Equal(settings.Settings.Disabled, loaded.Disabled);
        Assert.Null(ProtectedStateFiles.InvalidState(ProtectedState.CheckSettingsFile, loaded.ToJson()));
        Assert.NotNull(ProtectedStateFiles.InvalidState(ProtectedState.CheckSettingsFile, "{"));
        try { Directory.Delete(Path.GetDirectoryName(path)!, recursive: true); } catch { }
    }

    [Fact]
    public async Task Run_all_and_a_single_run_skip_a_turned_off_check_and_still_run_the_others()
    {
        var os = new PlainCheck(ModuleSlugs.Osquery, ModuleIds.Osquery, "Hardware inventory");
        var battery = new PlainCheck(ModuleSlugs.BatteryPower, ModuleIds.BatteryPower, "Battery & power plan");
        var audit = new PlainCheck(ModuleSlugs.SecurityAudit, ModuleIds.SecurityAudit, "Security audit") { InRunAll = false };
        var store = new MemoryCheckSettingsStore();
        var settings = new CheckSettingsService(store);
        settings.SetEnabled(os.Name, on: false, available: true);
        var diag = new DiagnosticsService(new ResultStore(), [os, battery, audit], checks: settings);

        var all = await diag.RunAllAsync();
        Assert.Equal(0, os.Runs);
        Assert.Equal(1, battery.Runs);
        Assert.Equal(0, audit.Runs);
        var skipped = all.Single(r => r.ModuleName == os.Name);
        Assert.Equal(DiagnosticStatus.Warning, skipped.Status);
        Assert.Equal(RowKind.Skipped, CheckRows.KindOf(skipped));
        Assert.NotEqual("Critical", ResultEventLogger.Outcome(skipped));
        Assert.Equal("Skipped", ResultEventLogger.Outcome(skipped));
        Assert.True(CheckEnableRules.IsTurnedOff(skipped));
        Assert.Equal(DiagnosticStatus.Ok, all.Single(r => r.ModuleName == battery.Name).Status);

        var again = await diag.RunAsync(os.Name);
        Assert.Equal(0, os.Runs);
        Assert.Equal(RowKind.Skipped, CheckRows.KindOf(again));

        var onDemand = await diag.RunAsync(audit.Name);
        Assert.Equal(1, audit.Runs);
        Assert.Equal(DiagnosticStatus.Ok, onDemand.Status);

        settings.SetAll([os.Name], on: true);
        await diag.RunAsync(os.Name);
        Assert.Equal(1, os.Runs);

        var banner = DashboardSummary.Build(
            [new BannerModule(os.Name, os.DisplayName, false, false, skipped.Status, skipped.Message, Skipped: true)], null);
        Assert.Empty(banner.Problems);
    }

    [Fact]
    public void Checks_page_exposes_the_contract_the_same_way_the_benchmark_toggles_do()
    {
        Assert.True(BrowserContract.Checks >= 4);
        var page = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Pages", "ChecksPage.razor"));
        Assert.Contains("TestId=\"checks-report-data\"", page, StringComparison.Ordinal);
        Assert.Contains("data-testid=\"checks-settings-toggle\"", page, StringComparison.Ordinal);
        Assert.Contains("aria-expanded=\"@(_checksOpen ? \"true\" : \"false\")\"", page, StringComparison.Ordinal);
        Assert.Contains("open=\"@_checksOpen\"", page, StringComparison.Ordinal);
        Assert.Contains("data-testid=\"checks-toggle-all\"", page, StringComparison.Ordinal);
        Assert.Contains("data-testid=\"checks-refresh\"", page, StringComparison.Ordinal);
        Assert.Contains("data-testid=\"@CheckEnableRules.Control(check.Id)\"", page, StringComparison.Ordinal);
        Assert.Contains("data-check-id=\"@check.Id\"", page, StringComparison.Ordinal);
        Assert.Contains("data-enabled=\"@(check.Enabled ? \"true\" : \"false\")\"", page, StringComparison.Ordinal);
        Assert.Contains("data-available=\"true\"", page, StringComparison.Ordinal);
        Assert.Contains("@onclick=\"() => ToggleCheck(check)\" @onclick:preventDefault=\"true\"", page, StringComparison.Ordinal);
        Assert.Contains("App.CheckSettings.SetEnabled(check.Id, !check.Enabled, check.Available, persistToHost: PersistToHost)", page, StringComparison.Ordinal);
        Assert.Contains("App.CheckSettings.SetAll(Diagnostics.CheckChoices().Where(c => c.Available).Select(c => c.Id), on, persistToHost: PersistToHost)", page, StringComparison.Ordinal);
        Assert.Contains("BrowserContract.Checks", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Order_persists_backwards_compatibly_and_ApplyRemotePrefs_does_not_overwrite_host_store()
    {
        // Legacy JSON without Order deserializes cleanly to empty Order.
        var legacy = CheckSettings.FromJson("""{"SchemaVersion":1,"Disabled":["Osquery"]}""");
        Assert.NotNull(legacy);
        Assert.Empty(legacy.Order);

        var store = new MemoryCheckSettingsStore();
        var svc = new CheckSettingsService(store);
        var all = new[] { ModuleSlugs.Osquery, ModuleSlugs.DriveHealth, ModuleSlugs.BatteryPower };

        svc.Reorder(ModuleSlugs.BatteryPower, ModuleSlugs.Osquery, all);
        Assert.Equal([ModuleSlugs.BatteryPower, ModuleSlugs.Osquery, ModuleSlugs.DriveHealth], svc.Settings.Order);
        Assert.Equal(svc.Settings.Order, store.State!.Order);

        var applied = CheckEnableRules.ApplyOrder(all, id => id, svc.Settings.Order);
        Assert.Equal([ModuleSlugs.BatteryPower, ModuleSlugs.Osquery, ModuleSlugs.DriveHealth], applied);

        var roundTripped = CheckSettings.FromJson(svc.Settings.ToJson());
        Assert.NotNull(roundTripped);
        Assert.Equal(svc.Settings.Order, roundTripped.Order);

        // Remote prefs update in-memory session without overwriting host store.
        var hostSnapshot = store.State;
        svc.ApplyRemotePrefs(new CheckSettings { Disabled = [ModuleSlugs.DriveHealth], Order = [ModuleSlugs.Osquery, ModuleSlugs.BatteryPower] });
        Assert.False(svc.IsEnabled(ModuleSlugs.DriveHealth));
        Assert.Equal([ModuleSlugs.Osquery, ModuleSlugs.BatteryPower], svc.Settings.Order);
        Assert.Same(hostSnapshot, store.State);
    }

    [Fact]
    public async Task AutoRun_StartEnabledChecksAsync_runs_enabled_checks_and_skips_disabled_checks()
    {
        var os = new PlainCheck(ModuleSlugs.Osquery, ModuleIds.Osquery, "Hardware inventory");
        var battery = new PlainCheck(ModuleSlugs.BatteryPower, ModuleIds.BatteryPower, "Battery & power plan");
        var drivers = new PlainCheck(ModuleSlugs.DeviceDrivers, ModuleIds.DeviceDrivers, "Device Manager & drivers");
        var store = new MemoryCheckSettingsStore();
        var settings = new CheckSettingsService(store);
        settings.SetEnabled(drivers.Name, on: false, available: true);
        var diag = new DiagnosticsService(new ResultStore(), [os, battery, drivers], checks: settings);

        await AutoRun.StartEnabledChecksAsync(diag, settings, _ => null, log: null, maxConcurrency: 2);

        Assert.Equal(1, os.Runs);
        Assert.Equal(1, battery.Runs);
        Assert.Equal(0, drivers.Runs);

        // Respects REMOTEPC_AUTORUN=0
        await AutoRun.StartEnabledChecksAsync(diag, settings, k => k == AutoRun.EnvironmentVariable ? "0" : null, log: null);
        Assert.Equal(1, os.Runs);
    }

    private static JsonSerializerOptions AgentJson() => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    internal static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "RemotePCDiagnostics.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate repository root containing RemotePCDiagnostics.sln.");
    }

    private sealed class MemoryCheckSettingsStore : ICheckSettingsStore
    {
        public CheckSettings? State;
        public CheckSettings? Load() => State;
        public void Save(CheckSettings settings) => State = settings;
    }

    private sealed class PlainCheck(string name, Guid id, string title) : IDiagnosticModule
    {
        public int Runs;
        public bool InRunAll { get; init; } = true;
        public Guid Id => id;
        public string Name => name;
        public string DisplayName => title;
        public bool IncludeInRunAll => InRunAll;
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken ct = default)
        {
            Runs++;
            return Task.FromResult(new DiagnosticResult(name, DiagnosticStatus.Ok, "ok", DateTimeOffset.Now));
        }
    }

    private sealed class HiddenCheck : IDetectableModule
    {
        public Task? Hold { get; init; }
        public Guid Id => ModuleIds.DriveHealth;
        public string Name => ModuleSlugs.DriveHealth;
        public string DisplayName => "Drive health & free space";
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public async Task<ModuleDetection> DetectAsync(CancellationToken ct = default)
        {
            if (Hold is not null) await Hold.WaitAsync(ct).ConfigureAwait(false);
            return ModuleDetection.NotApplicable("No drive found");
        }
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken ct = default) =>
            Task.FromResult(new DiagnosticResult(Name, DiagnosticStatus.Ok, "ok", DateTimeOffset.Now));
    }
}
