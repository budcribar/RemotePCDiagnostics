using RemotePCDiagnostics.Core;
using System.Text.Json;
using Bunit;
using RemotePCDiagnostics.Core.GpuMemory;
using RemotePCDiagnostics.UI.Shared;
using static RemotePCDiagnostics.Tests.GpuMemoryTests;

namespace RemotePCDiagnostics.Tests;

/// <summary>The graphics memory test's choices on the Stress tests page, and the gpumemory-data copy Admin's run_gpu_memory_test reads.</summary>
public sealed class GpuMemoryChoicesTests : BunitContext
{
    private static JsonElement Data(IRenderedComponent<GpuMemoryChoices> cut) =>
        JsonDocument.Parse(cut.Find("[data-testid=gpumemory-data]").GetAttribute("data-report")!).RootElement;

    [Fact]
    public void Lists_each_graphics_chip_with_what_it_will_test()
    {
        var module = new GpuMemoryModule(new SimulatedGpuMemory(Integrated(), Discrete()));
        var cut = Render<GpuMemoryChoices>(p => p.Add(x => x.Module, module));

        Assert.Equal("quick", cut.Find("[data-testid=gpumemory-options]").GetAttribute("data-mode"));
        var rows = cut.FindAll("[data-testid=gpumemory-adapter]");
        Assert.Equal(2, rows.Count);
        Assert.Contains("Built-in", rows[0].TextContent);
        Assert.Contains("4.8 GB", rows[1].TextContent);

        var data = Data(cut);
        Assert.Equal("quick", data.GetProperty("mode").GetString());
        Assert.Equal(1.5, data.GetProperty("minutesPerChip").GetDouble());
        var adapters = data.GetProperty("adapters").EnumerateArray().ToList();
        Assert.Equal([true, false], adapters.Select(a => a.GetProperty("integrated").GetBoolean()));
        Assert.Equal(4864, adapters[1].GetProperty("plannedMb").GetInt64());
        Assert.Equal(JsonValueKind.Null, data.GetProperty("results").ValueKind);
    }

    [Fact]
    public void Choosing_extended_sets_the_module_and_the_data_copy()
    {
        var module = new GpuMemoryModule(new SimulatedGpuMemory(Discrete()));
        var cut = Render<GpuMemoryChoices>(p => p.Add(x => x.Module, module));

        cut.Find("[data-testid=gpumemory-mode-extended]").Change(true);

        Assert.Equal(GpuMemoryMode.Extended, module.Mode);
        Assert.Equal("extended", Data(cut).GetProperty("mode").GetString());
        Assert.Equal(10, Data(cut).GetProperty("minutesPerChip").GetDouble());
    }

    [Fact]
    public void Disabled_while_running_keeps_the_mode()
    {
        var module = new GpuMemoryModule(new SimulatedGpuMemory(Discrete()));
        var cut = Render<GpuMemoryChoices>(p => p.Add(x => x.Module, module).Add(x => x.Disabled, true));
        cut.Find("[data-testid=gpumemory-mode-extended]").Change(true);
        Assert.Equal(GpuMemoryMode.Quick, module.Mode);
    }

    [Fact]
    public async Task After_a_run_the_data_copy_has_each_chips_numbers_and_first_wrong_offsets()
    {
        var sim = new SimulatedGpuMemory(Discrete());
        sim.StuckBits.Add((4096, 1, true));
        var module = new GpuMemoryModule(sim, clockFactory: () => sim.Clock);
        await module.RefreshAsync(null, CancellationToken.None);
        var cut = Render<GpuMemoryChoices>(p => p.Add(x => x.Module, module));

        var r = Data(cut).GetProperty("results").EnumerateArray().Single();
        Assert.Equal("ErrorsFound", r.GetProperty("outcome").GetString());
        Assert.Equal("Error", r.GetProperty("level").GetString());
        Assert.Equal(4864, r.GetProperty("testedMb").GetInt64());
        Assert.Equal("bit 1", r.GetProperty("flippedBits").GetString());
        Assert.Equal(4096, r.GetProperty("firstErrors")[0].GetProperty("offset").GetInt64());
        Assert.True(r.GetProperty("errors").GetInt64() > 0);
    }

    [Fact]
    public void No_graphics_chip_says_why()
    {
        var cut = Render<GpuMemoryChoices>(p => p.Add(x => x.Module, new GpuMemoryModule(new NoGpuMemorySource())));
        Assert.Contains("Remote Desktop", cut.Find("[data-testid=gpumemory-none]").TextContent);
    }
}
