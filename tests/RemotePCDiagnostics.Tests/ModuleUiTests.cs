using RemotePCDiagnostics.Core.Plugins;

namespace RemotePCDiagnostics.Tests;

/// <summary>Unsigned modules with their own UI: the manifest flag, loading the details component in a user-mode process, the frame rules.</summary>
public sealed class ModuleUiTests
{
    private static string Dll(string folder, string name) => Path.Combine(AppContext.BaseDirectory, folder, name);

    [Fact]
    public void HasUi_defaults_to_false_and_reads_from_module_json()
    {
        Assert.False(ModuleManifest.Parse("""{"id":"a22691b9-cab4-4006-b4c0-5428268812d6","slug":"x.y","entryType":"X"}"""u8).HasUi);
        Assert.True(ModuleManifest.Parse("""{"id":"a22691b9-cab4-4006-b4c0-5428268812d6","slug":"x.y","entryType":"X","hasUi":true}"""u8).HasUi);
    }

    [Fact]
    public void UserModePlugin_loads_the_module_and_its_details_component()
    {
        var lines = new List<string>();
        var loaded = UserModePlugin.Load(Dll("sample-module-ui", "SampleModuleUi.dll"), new LineLogger(lines.Add));
        Assert.Equal("sample.clock", loaded.Manifest.Slug);
        Assert.True(loaded.Manifest.HasUi);
        Assert.Equal(loaded.Manifest.Id, loaded.Module.Id);
        Assert.Equal("SampleModuleUi.ClockDetails", loaded.DetailsComponent?.FullName);
        // Components is shared with the host, so the host can render the module's component.
        Assert.True(typeof(Microsoft.AspNetCore.Components.IComponent).IsAssignableFrom(loaded.DetailsComponent));
    }

    [Fact]
    public void UserModePlugin_reports_no_details_component_for_a_module_without_one()
    {
        var loaded = UserModePlugin.Load(Dll("sample-module", "SampleModule.dll"));
        Assert.Equal("sample.uptime", loaded.Manifest.Slug);
        Assert.False(loaded.Manifest.HasUi);
        Assert.Null(loaded.DetailsComponent);
    }

    [Fact]
    public void The_frame_is_sandboxed_without_same_origin()
    {
        Assert.Contains("allow-scripts", ModuleUiFrame.Sandbox);
        Assert.DoesNotContain("allow-same-origin", ModuleUiFrame.Sandbox);
        Assert.DoesNotContain("allow-top-navigation", ModuleUiFrame.Sandbox);
        Assert.DoesNotContain("allow-popups", ModuleUiFrame.Sandbox);
        Assert.DoesNotContain("allow-modals", ModuleUiFrame.Sandbox);
    }

    [Theory]
    [InlineData(500, 500)]
    [InlineData(500.2, 501)]
    [InlineData(10, ModuleUiFrame.MinHeight)]
    [InlineData(1e9, ModuleUiFrame.MaxHeight)]
    [InlineData(double.NaN, ModuleUiFrame.MinHeight)]
    [InlineData(double.PositiveInfinity, ModuleUiFrame.MinHeight)]
    [InlineData(-5, ModuleUiFrame.MinHeight)]
    public void A_requested_height_is_clamped(double requested, int expected) => Assert.Equal(expected, ModuleUiFrame.ClampHeight(requested));
}
