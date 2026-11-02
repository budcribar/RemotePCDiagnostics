using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Keys saved on PCs (remembered ticks, the undo journal) must not change when code is renamed or text is translated.
/// If one of these fails after a rename, keep the old key (FixKeys / the enum name), don't update the test.
/// </summary>
public class StableKeysTests
{
    [Fact]
    public void EveryFixType_HasAUniqueFixedKey()
    {
        foreach (var k in Enum.GetValues<RemediationKind>()) Assert.True(FixKeys.Remediation.ContainsKey(k), $"FixKeys.Remediation is missing {k}");
        foreach (var t in Enum.GetValues<MemoryActionType>()) Assert.True(FixKeys.Memory.ContainsKey(t), $"FixKeys.Memory is missing {t}");
        Assert.Equal(FixKeys.Remediation.Count, FixKeys.Remediation.Values.Distinct().Count());
        Assert.Equal(FixKeys.Memory.Count, FixKeys.Memory.Values.Distinct().Count());
    }

    [Fact]
    public void FixIds_ArePinned()
    {
        Assert.Equal("rem:setbalancedpowerplan:", FixCatalog.RemediationId(new AreaAction(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced")));
        Assert.Equal("rem:setpublicdns:wi-fi", FixCatalog.RemediationId(new AreaAction(RemediationKind.SetPublicDns, "Use public DNS", "Wi-Fi")));
        Assert.Equal("rem:cleantempfiles:", FixCatalog.RemediationId(new AreaAction(RemediationKind.CleanTempFiles, "Clean")));
        Assert.Equal("mem:startup-spotify:disablestartup:spotify", FixCatalog.MemoryId("startup-spotify", MemoryActionType.DisableStartup, "Spotify"));
        Assert.Equal("mem:svc-wsearch:setservicemanual:wsearch", FixCatalog.MemoryId("svc-wsearch", MemoryActionType.SetServiceManual, "WSearch"));
        Assert.Equal("mem:widgets:disablewidgets:", FixCatalog.MemoryId("widgets", MemoryActionType.DisableWidgets, ""));
        Assert.Equal("mem:remove-xbox:removexboxapps:", FixCatalog.MemoryId("remove-xbox", MemoryActionType.RemoveXboxApps, ""));
        Assert.Equal("mem:hiberfile-reduced:reducehibernatefile:", FixCatalog.MemoryId("hiberfile-reduced", MemoryActionType.ReduceHibernateFile, ""));
    }

    [Fact]
    public void JournalKinds_ArePinned()
    {
        // The undo journal stores these names (JsonStringEnumConverter). Renaming one would break undo of changes made before.
        string[] pinned =
        [
            "StartupApp", "ServiceStartType", "ServiceRunning", "BrowserSettings", "Transparency", "FastStartup", "PowerPlan", "SystemProxy",
            "AdapterDns", "PageFile", "TempFiles", "DefenderExclusion", "HiberFileType", "RegistryValue", "DefaultPrinter", "NotUndoable",
            "ExtensionBlock", "BrowserLocalStateValue", "ScheduledTask",
        ];
        var json = new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } };
        foreach (var name in pinned)
            Assert.Equal(name, JsonSerializer.Deserialize<ChangeKind>($"\"{name}\"", json).ToString());
    }

    [Fact]
    public void WorkflowAreas_GroupByUntranslatedKey()
    {
        var fix = new WorkflowFix("id", "Title", "why", "Startup-Apps (übersetzt)", SuggestionRisk.Low, FixSource.Memory, 20, AreaKey: "Startup apps");
        Assert.Equal("Startup apps", fix.GroupKey);
        Assert.Equal("Startup apps", (fix with { AreaKey = null, Area = "Startup apps" }).GroupKey);
    }

    [Fact]
    public void Cancelled_IsAFlag_NotTheMessage()
    {
        var translated = new DiagnosticResult("CpuStress", DiagnosticStatus.Warning, "Abgebrochen", DateTimeOffset.Now) { Cancelled = true };
        Assert.True(Cancellation.IsCancelled(translated));
        Assert.Empty(DashboardSummary.Build([new BannerModule("CpuStress", "CPU", true, true, translated.Status, translated.Message, translated.Cancelled)], null).Problems);
        // The message alone never decides it.
        Assert.False(Cancellation.IsCancelled(new DiagnosticResult("X", DiagnosticStatus.Warning, "Stopped by you", DateTimeOffset.Now)));
        Assert.False(Cancellation.IsCancelled(new DiagnosticResult("X", DiagnosticStatus.Warning, "Disk is 92% full", DateTimeOffset.Now)));
        Assert.True((translated with { Message = "x" }).Cancelled); // copies keep it
    }

    [Fact]
    public async Task DiagnosticsService_MarksCancelledRuns()
    {
        using var cts = new CancellationTokenSource();
        var store = new ResultStore();
        var diag = new DiagnosticsService(store, [new FakeModule("Slow", async ct => { cts.Cancel(); await Task.Delay(1000, ct); return new DiagnosticResult("Slow", DiagnosticStatus.Ok, "ok", DateTimeOffset.Now); })]);
        var r = await diag.RunAsync("Slow", null, cts.Token);
        Assert.True(r.Cancelled);
    }

    [Fact]
    public void RemoteWindow_PlaceholderDoesNotRepeatTheLink()
    {
        Assert.DoesNotContain("http", RemoteLinkInfo.LocalPlaceholderHtml);
        Assert.Contains("Keep this window open", RemoteLinkInfo.LocalPlaceholderHtml);
    }
}
