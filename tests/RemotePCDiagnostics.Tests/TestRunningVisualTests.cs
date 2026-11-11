using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

/// <summary>Verifies that every >=30s diagnostic/stress test has a valid animated isometric GIF, a reduced-motion static PNG fallback,
/// and renders cleanly through <see cref="TestRunningVisual"/>.</summary>
public class TestRunningVisualTests
{
    private static string RepoRoot
    {
        get
        {
            for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
                if (File.Exists(Path.Combine(d.FullName, "RemotePCDiagnostics.sln"))) return d.FullName;
            throw new DirectoryNotFoundException("Could not locate repository root containing RemotePCDiagnostics.sln.");
        }
    }
    private static string AssetsDir => Path.Combine(RepoRoot, "src", "RemotePCDiagnostics.UI", "wwwroot", "img", "tests");

    public static TheoryData<string, string> ModuleToAssetCases => new()
    {
        { ModuleSlugs.CpuStress, "cpu-stress" },
        { ModuleSlugs.GpuStress, "gpu-stress" },
        { ModuleSlugs.MemoryTest, "memory-test" },
        { ModuleSlugs.DiskSpeed, "disk-speed" },
        { ModuleSlugs.NetworkTest, "network-test" },
        { ModuleSlugs.NpuTest, "npu-test" },
        { ModuleSlugs.MicToSpeaker, "audio-test" },
        { ModuleSlugs.SpeakerToMic, "audio-test" },
        { ModuleSlugs.SfcVerifyOnly, "sfc-scan" },
        { ModuleSlugs.DismScanHealth, "dism-scan" },
        { ModuleSlugs.SecurityAudit, "security-audit" },
        { "benchmark", "benchmark" },
    };

    [Theory]
    [MemberData(nameof(ModuleToAssetCases))]
    public void Every_long_running_test_maps_to_existing_gif_and_reduced_motion_png(string inputSlug, string expectedAsset)
    {
        Assert.Equal(expectedAsset, TestRunningVisual.AssetSlugFor(inputSlug));

        var gifPath = Path.Combine(AssetsDir, $"{expectedAsset}.gif");
        var pngPath = Path.Combine(AssetsDir, $"{expectedAsset}.png");

        Assert.True(File.Exists(gifPath), $"Missing GIF: {gifPath}");
        Assert.True(File.Exists(pngPath), $"Missing PNG: {pngPath}");

        var gifBytes = File.ReadAllBytes(gifPath);
        var pngBytes = File.ReadAllBytes(pngPath);

        Assert.True(gifBytes.Length > 10_000, $"Expected animated GIF > 10 KB for {expectedAsset}");
        Assert.Equal("GIF89a", System.Text.Encoding.ASCII.GetString(gifBytes, 0, 6));

        Assert.True(pngBytes.Length > 5_000, $"Expected static PNG > 5 KB for {expectedAsset}");
        Assert.Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47 }, pngBytes[..4]);
    }

    [Fact]
    public async Task TestRunningVisual_renders_gif_and_prefers_reduced_motion_source()
    {
        using var services = new ServiceCollection().BuildServiceProvider();
        using var renderer = new HtmlRenderer(services, NullLoggerFactory.Instance);

        var html = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var parameters = ParameterView.FromDictionary(new Dictionary<string, object?>
            {
                [nameof(TestRunningVisual.Slug)] = ModuleSlugs.DiskSpeed,
                [nameof(TestRunningVisual.TestId)] = "diskspeed-visual",
            });
            var output = await renderer.RenderComponentAsync<TestRunningVisual>(parameters);
            return output.ToHtmlString();
        });

        Assert.Contains("data-testid=\"diskspeed-visual\"", html);
        Assert.Contains("data-visual=\"disk-speed\"", html);
        Assert.Contains("media=\"(prefers-reduced-motion: reduce)\"", html);
        Assert.Contains("_content/RemotePCDiagnostics.UI/img/tests/disk-speed.png", html);
        Assert.Contains("_content/RemotePCDiagnostics.UI/img/tests/disk-speed.gif", html);
        Assert.Contains("width=\"220\" height=\"124\"", html);
        Assert.DoesNotContain("running-visual-caption", html);

        var withCaption = await renderer.Dispatcher.InvokeAsync(async () =>
        {
            var parameters = ParameterView.FromDictionary(new Dictionary<string, object?>
            {
                [nameof(TestRunningVisual.Slug)] = ModuleSlugs.SpeakerToMic,
                [nameof(TestRunningVisual.Caption)] = "Playing test tone",
            });
            var output = await renderer.RenderComponentAsync<TestRunningVisual>(parameters);
            return output.ToHtmlString();
        });

        Assert.Contains("data-visual=\"audio-test\"", withCaption);
        Assert.Contains("running-visual-caption", withCaption);
        Assert.Contains("Playing test tone", withCaption);
    }

    [Fact]
    public void ModuleUiHost_links_test_visual_assets()
    {
        var csproj = File.ReadAllText(Path.Combine(RepoRoot, "src", "RemotePCDiagnostics.ModuleUiHost", "RemotePCDiagnostics.ModuleUiHost.csproj"));
        Assert.Contains(@"RemotePCDiagnostics.UI\wwwroot\img\tests\**", csproj);
    }
}
