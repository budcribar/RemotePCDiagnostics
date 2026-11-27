using System.Text.Json;
using Bunit;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Storage;
using RemotePCDiagnostics.UI.Shared;
using static RemotePCDiagnostics.Tests.DriveSelfTestTests;

namespace RemotePCDiagnostics.Tests;

/// <summary>The drive self-test's choices on the Stress tests page, and the selftest-data copy Admin's run_drive_self_test reads.</summary>
public sealed class DriveSelfTestOptionsTests : BunitContext
{
    private static DriveSelfTestModule Module(params SelfTestDriveAnswer[] drives) =>
        new(new RecordingReplay([RecordedCall.FromSelfTest(["list"], new SelfTestReply(new SelfTestAnswer { Drives = [.. drives] }, null))]).SelfTest);

    private static JsonElement Data(IRenderedComponent<DriveSelfTestOptions> cut) =>
        JsonDocument.Parse(cut.Find("[data-testid=selftest-data]").GetAttribute("data-report")!).RootElement;

    [Fact]
    public void Lists_each_drive_with_its_estimate_and_why_a_usb_drive_cannot_be_tested()
    {
        var module = Module(Nvme(0, NvmeLog(), extendedMinutes: 12), Usb(1), Ata(2, AtaSmart(extendedMinutes: 85), AtaLog((1, 0x00, 500, 0))));
        var cut = Render<DriveSelfTestOptions>(p => p.Add(x => x.Module, module));
        cut.WaitForAssertion(() => Assert.Equal(3, cut.FindAll("[data-testid=selftest-drive]").Count));

        Assert.Equal("short", cut.Find("[data-testid=selftest-options]").GetAttribute("data-mode"));
        Assert.Equal("false", cut.Find("[data-testid=selftest-drive][data-disk='1']").GetAttribute("data-supported"));
        Assert.True(cut.Find("[data-testid=selftest-disk-1]").HasAttribute("disabled"));
        Assert.Contains("USB", cut.Find("[data-testid=selftest-drive][data-disk='1']").TextContent);

        var data = Data(cut);
        Assert.Equal(1, data.GetProperty("schema").GetInt32());
        Assert.Equal(JsonValueKind.Null, data.GetProperty("disks").ValueKind);
        var drives = data.GetProperty("drives").EnumerateArray().ToList();
        Assert.Equal([0, 1, 2], drives.Select(d => d.GetProperty("disk").GetInt32()));
        Assert.Equal([true, false, true], drives.Select(d => d.GetProperty("chosen").GetBoolean()));
        Assert.Equal(85, drives[2].GetProperty("extendedMinutes").GetInt32());
        Assert.Equal(SelfTestDecoder.Describe(SelfTestOutcome.Passed), drives[2].GetProperty("lastResult").GetString());
    }

    [Fact]
    public void Choosing_extended_and_one_drive_sets_the_module_and_the_data_copy()
    {
        var module = Module(Nvme(0, NvmeLog(), extendedMinutes: 12), Ata(2, AtaSmart(extendedMinutes: 85), AtaLog()));
        var cut = Render<DriveSelfTestOptions>(p => p.Add(x => x.Module, module));
        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("[data-testid=selftest-drive]").Count));

        cut.Find("[data-testid=selftest-mode-extended]").Change(true);
        cut.Find("[data-testid=selftest-disk-0]").Change(false);

        Assert.Equal(SelfTestKind.Extended, module.Mode);
        Assert.Equal([2], module.Disks!);
        Assert.Equal("extended", cut.Find("[data-testid=selftest-options]").GetAttribute("data-mode"));
        Assert.Equal([2], Data(cut).GetProperty("disks").EnumerateArray().Select(d => d.GetInt32()));
        Assert.Contains("about 1 h 25 min", cut.Find(".selftest-mode").TextContent);

        // Ticking it again is every drive again, which is the default (null).
        cut.Find("[data-testid=selftest-disk-0]").Change(true);
        Assert.Null(module.Disks);
    }

    [Fact]
    public void While_running_the_choices_are_fixed()
    {
        var module = Module(Nvme(0, NvmeLog()));
        var cut = Render<DriveSelfTestOptions>(p => p.Add(x => x.Module, module).Add(x => x.Disabled, true));
        cut.WaitForAssertion(() => Assert.Single(cut.FindAll("[data-testid=selftest-drive]")));
        Assert.True(cut.Find("[data-testid=selftest-disk-0]").HasAttribute("disabled"));
        Assert.True(cut.Find(".selftest-mode").HasAttribute("disabled"));
    }

    [Fact]
    public void Without_the_agent_it_says_so()
    {
        var module = new DriveSelfTestModule(new RecordingReplay([]).SelfTest, noAgent: () => true);
        var cut = Render<DriveSelfTestOptions>(p => p.Add(x => x.Module, module));
        cut.WaitForAssertion(() => Assert.Contains("Agent", cut.Find("[data-testid=selftest-preview-error]").TextContent));
        Assert.Contains("Agent", Data(cut).GetProperty("error").GetString());
    }
}
