using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public class IntegrityProgressTests
{
    private sealed class FakeScan(SystemCommandRunner c) : WindowsIntegrityModule(c)
    {
        public override string Name => "fake-scan";
        public override Guid Id => Guid.Parse("8f1d2a40-0000-4000-8000-000000000001");
        public override string DisplayName => "Fake scan";
        protected override string ToolExe => SystemCommandRunner.PowerShell;
        protected override string[] Arguments => ["-NoProfile", "-Command",
            "foreach($p in 10,42.5,99){ [Console]::Out.Write(\"`r[==   $p%   ==]\"); [Console]::Out.Flush(); Start-Sleep -Milliseconds 100 }; [Console]::Out.WriteLine(''); 'done'"];
        protected override (DiagnosticStatus Status, string Summary) Interpret(string output, RemotePCDiagnostics.Core.Osquery.ProcessResult? result) => (DiagnosticStatus.Ok, "ok");
    }

    [Fact]
    public async Task Scan_raises_running_updates_with_percent_payload()
    {
        var module = new FakeScan(new SystemCommandRunner());
        var seen = new List<double>();
        module.Updated += (_, r) => { if (r.Payload is double p) seen.Add(p); };
        await module.RefreshAsync(null);
        Assert.Equal([10, 42.5, 99], seen);
    }

    [Fact]
    public async Task Running_scan_keeps_its_percent_in_the_store()
    {
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [new FakeScan(new SystemCommandRunner())]);
        var seen = new List<string>();
        store.Changed += (_, r) => seen.Add($"{r.Status}|{r.Message}|{r.Payload?.GetType().Name}");
        await svc.RunAsync("fake-scan");
        Assert.Contains("Running|Scan 42.5% complete|Double", seen);
        Assert.Equal("Ok|ok|AreaReport", seen[^1]);
    }
}
