using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Preferences;

namespace RemotePCDiagnostics.Tests;

public sealed class PreferencesTests : IDisposable
{
    private readonly string dir = Path.Combine(Path.GetTempPath(), "rpd-prefs-" + Guid.NewGuid().ToString("N"));
    private string PathOf => System.IO.Path.Combine(dir, "preferences.json");

    [Fact]
    public void FileStore_RoundTrips_AndMissingOrBrokenFileMeansDefaults()
    {
        var store = new FilePreferencesStore(PathOf);
        Assert.Null(store.Load().Theme);
        var svc = new PreferencesService(store);
        svc.Update(p => p with { Theme = "dark", StressMode = "Extended", ChecksCollapsed = false, SelectedModuleIds = [ModuleIds.Osquery], WorkflowOpenAreas = ["Startup apps"] });
        svc.RememberFixChoices([("mem:startup-spotify:disablestartup:spotify", false), ("rem:cleantempfiles:", true)]);

        var again = new FilePreferencesStore(PathOf).Load();
        Assert.Equal("dark", again.Theme);
        Assert.Equal("Extended", again.StressMode);
        Assert.False(again.ChecksCollapsed);
        Assert.Equal([ModuleIds.Osquery], again.SelectedModuleIds);
        Assert.Null(again.SelectedModules);
        Assert.Equal(["Startup apps"], again.WorkflowOpenAreas);
        Assert.False(again.WorkflowFixChoices["mem:startup-spotify:disablestartup:spotify"]);

        File.WriteAllText(PathOf, "{ not json");
        Assert.Null(new FilePreferencesStore(PathOf).Load().Theme);
    }

    [Fact]
    public void Selections_saved_by_name_are_read_as_module_ids()
    {
        Directory.CreateDirectory(dir);
        File.WriteAllText(PathOf, """{ "SelectedModules": ["Osquery", "drivehealth", "NoLongerExists"] }""");
        var p = new FilePreferencesStore(PathOf).Load();
        Assert.Equal([ModuleIds.Osquery, ModuleIds.DriveHealth], p.SelectedModuleIds);
        Assert.Null(p.SelectedModules);
    }

    [Fact]
    public void FixChoices_OverrideDefaults_ForgetGoesBackToDefault_AndAreCapped()
    {
        var svc = new PreferencesService(new MemoryPreferencesStore());
        Assert.True(svc.IsTicked("a", defaultOn: true));
        svc.RememberFixChoices([("a", false), ("b", true)]);
        Assert.False(svc.IsTicked("a", defaultOn: true));
        Assert.True(svc.IsTicked("b", defaultOn: false));   // an opt-in fix the remote user ticked stays ticked
        svc.ForgetFixChoices(["a"]);
        Assert.True(svc.IsTicked("a", defaultOn: true));

        svc.RememberFixChoices(Enumerable.Range(0, UserPreferences.MaxFixChoices + 50).Select(i => ($"x{i}", true)));
        Assert.Equal(UserPreferences.MaxFixChoices, svc.Current.WorkflowFixChoices.Count);
    }

    [Fact]
    public void ChecksScreen_RemembersSelectionCollapseAndMode()
    {
        var prefs = new PreferencesService(new MemoryPreferencesStore());
        var store = new ResultStore();
        static Task<DiagnosticResult> Ok(string n) => Task.FromResult(new DiagnosticResult(n, DiagnosticStatus.Ok, "ok", DateTimeOffset.Now));
        var diag = new DiagnosticsService(store, [new FakeModule("A", _ => Ok("A")), new FakeModule("B", _ => Ok("B"))]);
        var screen = new ChecksScreenState(diag, store, prefs);
        Assert.True(screen.IsSelected("A"));
        screen.SetSelected("A", false);
        screen.CollapsedChecks = false;
        screen.Mode = StressSuiteMode.Extended;

        var next = new ChecksScreenState(diag, store, prefs);   // e.g. after the app restarts
        Assert.False(next.IsSelected("A"));
        Assert.True(next.IsSelected("B"));
        Assert.False(next.CollapsedChecks);
        Assert.Equal(StressSuiteMode.Extended, next.Mode);
    }

    public void Dispose() { try { Directory.Delete(dir, true); } catch { } }
}
