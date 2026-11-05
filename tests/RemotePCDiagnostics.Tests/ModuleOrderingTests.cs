using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Tests;

public class ModuleOrderingTests
{
    private static ModuleDescriptor D(string slug, string group = ModuleGroups.Other, int order = 100, string[]? dependsOn = null, string[]? runAfter = null) =>
        new(TestIds.For(slug), slug, slug, ModuleKind.Check, group, order)
        {
            DependsOn = (dependsOn ?? []).Select(TestIds.For).ToList(), RunAfter = (runAfter ?? []).Select(TestIds.For).ToList(),
        };

    [Fact]
    public void Sort_puts_dependencies_first_and_breaks_ties_by_group_then_order()
    {
        var sorted = ModuleOrdering.Sort([
            D("c", ModuleGroups.Windows, 100, dependsOn: ["b"]),
            D("b", ModuleGroups.Windows, 300),
            D("a", ModuleGroups.Hardware, 900),
            D("d", ModuleGroups.Hardware, 100, runAfter: ["c"]),
            D("e", ModuleGroups.Windows, 200, dependsOn: ["missing"]),
        ]).Select(d => d.Slug);
        // a, then e and b (Windows by order: e 200 before b 300), then c (needs b), then d (after c, though Hardware ranks first).
        Assert.Equal(["a", "e", "b", "c", "d"], sorted);
    }

    [Fact]
    public void The_built_in_stress_suite_order_comes_from_RunAfter()
    {
        var stress = BuiltInModules.Descriptors.Where(d => d.Kind == ModuleKind.StressTest).Reverse();
        Assert.Equal([ModuleSlugs.CpuStress, ModuleSlugs.MemoryTest, ModuleSlugs.DiskSpeed, ModuleSlugs.GpuStress, ModuleSlugs.NetworkTest],
            ModuleOrdering.Sort(stress).Select(d => d.Slug));
        Assert.Empty(ModuleOrdering.FindCycles(BuiltInModules.Descriptors));
    }

    [Fact]
    public void FindCycles_reports_each_loop_and_ignores_the_rest()
    {
        var cycles = ModuleOrdering.FindCycles([
            D("a", dependsOn: ["b"]), D("b", runAfter: ["c"]), D("c", dependsOn: ["a"]),
            D("self", dependsOn: ["self"]), D("ok", dependsOn: ["a"]),
        ]);
        Assert.Equal(2, cycles.Count);
        Assert.Contains(cycles, c => c.ToHashSet().SetEquals(new[] { "a", "b", "c" }.Select(TestIds.For)));
        Assert.Contains(cycles, c => c.SequenceEqual([TestIds.For("self")]));
    }

    private static (DiagnosticsService Diag, ResultStore Store, List<string> Ran) Service(IEnumerable<ModuleDescriptor> known, params (string Name, DiagnosticStatus Status)[] modules)
    {
        var ran = new List<string>();
        var store = new ResultStore();
        var catalog = new ModuleCatalog(BuiltInModules.Descriptors.Concat(known));
        var fakes = modules.Select(m => new FakeModule(m.Name, async ct =>
        {
            await Task.Yield();
            lock (ran) ran.Add(m.Name);
            return new DiagnosticResult(m.Name, m.Status, m.Status.ToString(), DateTimeOffset.Now);
        }));
        return (new DiagnosticsService(store, fakes, catalog), store, ran);
    }

    [Fact]
    public async Task Run_all_skips_a_module_whose_dependency_failed_and_records_why()
    {
        var (diag, store, ran) = Service([D("scan", order: 1), D("repair", order: 2, dependsOn: ["scan"]), D("other", order: 3, dependsOn: ["fine"]), D("fine")],
            ("scan", DiagnosticStatus.Error), ("repair", DiagnosticStatus.Ok), ("fine", DiagnosticStatus.Warning), ("other", DiagnosticStatus.Ok));
        await diag.RunAllAsync();

        Assert.DoesNotContain("repair", ran);
        var r = store.Get("repair");
        Assert.Equal("Skipped", ResultEventLogger.Outcome(r));
        Assert.Equal("Skipped: scan did not pass", r.Message);
        Assert.Equal(RowKind.Skipped, CheckRows.KindOf(r));
        Assert.Equal(LogLevel.Warning, ResultEventLogger.LevelFor(r));
        // A Warning counts as passed.
        Assert.Contains("other", ran);
        Assert.True(ran.IndexOf("fine") < ran.IndexOf("other"));
    }

    [Fact]
    public async Task Run_all_blocks_a_module_whose_dependency_cannot_run_here()
    {
        var (diag, store, ran) = Service([D("needs-retired", dependsOn: [ModuleSlugs.BsodHistory]), D("needs-unknown", dependsOn: ["nowhere"])],
            ("needs-retired", DiagnosticStatus.Ok), ("needs-unknown", DiagnosticStatus.Ok));
        await diag.RunAllAsync();
        Assert.Empty(ran);
        Assert.Equal("Blocked", ResultEventLogger.Outcome(store.Get("needs-retired")));
        Assert.Contains("no longer available", store.Get("needs-retired").Message);
        Assert.Contains("isn't installed", store.Get("needs-unknown").Message);
        Assert.Equal(RowKind.Blocked, CheckRows.KindOf(store.Get("needs-unknown")));
    }

    [Fact]
    public async Task RunAfter_orders_without_requiring_a_pass()
    {
        var (diag, _, ran) = Service([D("first", order: 900), D("second", order: 1, runAfter: ["first"])],
            ("first", DiagnosticStatus.Error), ("second", DiagnosticStatus.Ok));
        await diag.RunAllAsync();
        Assert.Equal(["first", "second"], ran);
    }

    [Fact]
    public void Modules_in_a_dependency_loop_are_not_runnable_but_stay_known()
    {
        var (diag, _, _) = Service([D("a", dependsOn: ["b"]), D("b", dependsOn: ["a"]), D("c")],
            ("a", DiagnosticStatus.Ok), ("b", DiagnosticStatus.Ok), ("c", DiagnosticStatus.Ok));
        Assert.Equal(["c"], diag.Modules.Select(m => m.Name));
        Assert.Equal(ModuleState.Disabled, diag.Catalog.StateOf(TestIds.For("a")));
        Assert.Equal("a", diag.Catalog.DisplayName(TestIds.For("a")));
    }

    [Fact]
    public async Task Running_one_module_runs_its_dependencies_that_have_not_passed_first()
    {
        var (diag, store, ran) = Service([D("base"), D("mid", dependsOn: ["base"]), D("top", dependsOn: ["mid"])],
            ("base", DiagnosticStatus.Ok), ("mid", DiagnosticStatus.Ok), ("top", DiagnosticStatus.Ok));
        var r = await diag.RunWithDependenciesAsync("top");
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(["base", "mid", "top"], ran);

        ran.Clear();
        await diag.RunWithDependenciesAsync("top"); // base and mid passed in this session: not run again
        Assert.Equal(["top"], ran);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("top").Status);
    }
}
