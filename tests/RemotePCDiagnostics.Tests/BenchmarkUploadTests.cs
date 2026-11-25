using System.Net;
using System.Text;
using System.Text.Json;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class BenchmarkUploadTests
{
    private static BenchmarkRun Run(BenchmarkPhase phase, params BenchmarkMeasurement[] ms) =>
        new(phase, new DateTimeOffset(2026, 11, 20, 12, 0, 0, TimeSpan.Zero), new BenchmarkConditions(false, 55, "Balanced"), ms);

    [Fact]
    public void Build_sends_each_measured_kind_with_how_to_rank_it_and_skips_unmeasured()
    {
        var run = Run(BenchmarkPhase.After,
            new BenchmarkMeasurement(BenchmarkKind.CpuMulti, [900, 1000, 1100]),
            new BenchmarkMeasurement(BenchmarkKind.DiskLatency, [0.2]),
            new BenchmarkMeasurement(BenchmarkKind.BootTime, [], Note: "no boot recorded"),
            new BenchmarkMeasurement(BenchmarkKind.Speedometer, [20.5], RunIdentity: new SpeedometerRunIdentity("chromium", "Edge", "131.0", "3.1", "headless-new")),
            new BenchmarkMeasurement(BenchmarkKind.EnabledStartupApps, [7]));

        var req = BenchmarkUpload.Build(run, "id-1", "BENCH-PC", new BenchmarkHardware(Model: "Latitude 7420"), "2.3.4")!;

        Assert.Equal("After", req.Phase);
        Assert.Equal("2.3.4", req.AppVersion);
        Assert.Equal(["CpuMulti", "DiskLatency", "Speedometer", "EnabledStartupApps"], req.Results.Select(r => r.Kind));
        var cpu = req.Results[0];
        Assert.Equal(1000, cpu.Value);
        Assert.False(cpu.LowerIsBetter);
        Assert.Equal(1.5, cpu.Weight);
        Assert.Equal(3, cpu.Samples.Count);
        Assert.True(req.Results[1].LowerIsBetter);
        Assert.Equal("Edge 131.0 · Speedometer 3.1", req.Results[2].Detail);
        Assert.Equal(0, req.Results[3].Weight); // inventory counts are listed, not ranked
        Assert.Equal("Balanced", req.Conditions.PowerPlan);
    }

    [Fact]
    public void Developer_build_counts_when_computers_are_compared()
    {
        Assert.Equal(1.0, BenchmarkUpload.CompareWeight(Benchmarks.Info(BenchmarkKind.DeveloperCSharp)));
        Assert.Equal(0.0, BenchmarkUpload.CompareWeight(Benchmarks.Info(BenchmarkKind.DiskFreeGb)));
        Assert.Equal(2.0, BenchmarkUpload.CompareWeight(Benchmarks.Info(BenchmarkKind.BootTime)));
    }

    [Fact]
    public void Nothing_to_upload_without_a_measured_run()
    {
        Assert.Null(BenchmarkUpload.Build(null, "id", "pc", new BenchmarkHardware()));
        Assert.Null(BenchmarkUpload.Build(Run(BenchmarkPhase.Before, new BenchmarkMeasurement(BenchmarkKind.CpuSingle, [])), "id", "pc", new BenchmarkHardware()));
    }

    [Fact]
    public void Latest_run_is_the_after_pass_when_there_is_one()
    {
        var before = Run(BenchmarkPhase.Before);
        var after = Run(BenchmarkPhase.After);
        Assert.Same(after, BenchmarkUpload.LatestRun(before, after));
        Assert.Same(before, BenchmarkUpload.LatestRun(before, null));
    }

    [Fact]
    public void Hardware_probe_output_is_parsed_and_gaps_stay_unknown()
    {
        var hw = HardwareIdentityProbe.Parse("""{"Manufacturer":"Dell Inc.","Model":"Latitude 7420","Memory":17179869184,"Processor":"11th Gen Intel(R) Core(TM) i7-1185G7","Cores":4,"Logical":8,"Gpu":"Intel(R) Iris(R) Xe Graphics","Os":"Microsoft Windows 11 Pro 10.0.26100"}""");
        Assert.Equal("Dell Inc.", hw.Manufacturer);
        Assert.Equal(16.0, hw.MemoryGb);
        Assert.Equal(4, hw.Cores);
        Assert.Equal(8, hw.LogicalProcessors);
        Assert.Equal("Intel(R) Iris(R) Xe Graphics", hw.Gpu);

        var partial = HardwareIdentityProbe.Parse("""{"Model":"","Processor":null,"Cores":"x"}""");
        Assert.Null(partial.Model);
        Assert.Null(partial.Processor);
        Assert.Null(partial.Cores);
        Assert.Equal(new BenchmarkHardware(), HardwareIdentityProbe.Parse("not json"));
    }

    [Fact]
    public void Machine_identity_uses_windows_machine_guid_else_the_name()
    {
        Assert.Equal("6f1c2a52-1111-4a3b-9c1d-0123456789ab", MachineIdentity.Read("PC", () => "6F1C2A52-1111-4A3B-9C1D-0123456789AB"));
        Assert.Equal("name-bench-pc", MachineIdentity.Read("BENCH-PC", () => null));
    }

    private sealed class Handler(Func<HttpRequestMessage, string, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            return respond(request, body);
        }
    }

    private static BenchmarkUploadRequest Sample() =>
        BenchmarkUpload.Build(Run(BenchmarkPhase.Before, new BenchmarkMeasurement(BenchmarkKind.CpuSingle, [500])), "id-1", "BENCH-PC", new BenchmarkHardware(Processor: "Ryzen"), "1.0.0")!;

    [Fact]
    public async Task Upload_posts_to_the_admin_api_with_the_shop_key()
    {
        HttpRequestMessage? seen = null;
        string sent = "";
        var client = new ShopRelayClient(new HttpClient(new Handler((req, body) =>
        {
            seen = req;
            sent = body;
            return new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent("""{"machineId":"id-1","compareUrl":"https://admin.remoteblazorwebview.com/benchmarks","computers":3}""", Encoding.UTF8, "application/json"),
            };
        })));

        var result = await client.UploadBenchmarkAsync(new Uri("https://server.remoteblazorwebview.com:34544"), "rpd_live_abc", Sample());

        var up = Assert.IsType<ShopBenchmarkUploadResult.Uploaded>(result);
        Assert.Equal(3, up.Computers);
        Assert.Equal("https://admin.remoteblazorwebview.com/api/benchmarks", seen!.RequestUri!.ToString());
        Assert.Equal("Bearer", seen.Headers.Authorization!.Scheme);
        Assert.Equal("rpd_live_abc", seen.Headers.Authorization.Parameter);
        using var doc = JsonDocument.Parse(sent);
        Assert.Equal("id-1", doc.RootElement.GetProperty("machineId").GetString());
        Assert.Equal("Ryzen", doc.RootElement.GetProperty("hardware").GetProperty("processor").GetString());
        Assert.Equal("CpuSingle", doc.RootElement.GetProperty("results")[0].GetProperty("kind").GetString());
    }

    [Fact]
    public async Task Upload_reports_a_rejected_key_and_refuses_a_bad_one_without_calling()
    {
        var calls = 0;
        var client = new ShopRelayClient(new HttpClient(new Handler((_, _) =>
        {
            calls++;
            return new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent("""{"error":"unauthorized"}""") };
        })));
        var relay = new Uri("https://server.remoteblazorwebview.com");

        Assert.IsType<ShopBenchmarkUploadResult.InvalidRequest>(await client.UploadBenchmarkAsync(relay, "not-a-key", Sample()));
        Assert.Equal(0, calls);
        Assert.IsType<ShopBenchmarkUploadResult.Unauthorized>(await client.UploadBenchmarkAsync(relay, "rpd_live_x", Sample()));
        Assert.Equal(1, calls);
    }

    [Fact]
    public void PowerMode_maps_windows_overlay_guids_and_travels_in_upload_conditions()
    {
        Assert.Equal("Best power efficiency", PowerModeNames.FromOverlayGuid(PowerModeNames.BestPowerEfficiencyGuid));
        Assert.Equal("Best performance", PowerModeNames.FromOverlayGuid(PowerModeNames.BestPerformanceGuid));
        Assert.Equal("Balanced", PowerModeNames.FromOverlayGuid(PowerModeNames.BalancedPlanGuid));
        Assert.Equal("Balanced", PowerModeNames.FromOverlayGuid(Guid.Empty));
        Assert.Equal("Energy Saver", PowerModeNames.FromOverlayGuid(PowerModeNames.BestPerformanceGuid, energySaver: true));

        var run = new BenchmarkRun(
            BenchmarkPhase.Before,
            DateTimeOffset.UtcNow,
            new BenchmarkConditions(false, 48, "Balanced", "Best performance"),
            [new BenchmarkMeasurement(BenchmarkKind.CpuSingle, [500])]);
        var req = BenchmarkUpload.Build(run, "id-1", "BENCH-PC", new BenchmarkHardware(Processor: "Ryzen"), "1.0.0")!;
        Assert.Equal("Balanced", req.Conditions.PowerPlan);
        Assert.Equal("Best performance", req.Conditions.PowerMode);
    }
}
