using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;

namespace RemotePCDiagnostics.Tests;

public sealed class SpeedometerTests
{
    [Fact]
    public async Task LocalServer_ServesIndexAndAssets_StripsQuery_AndBlocksTraversal()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpd-sm-srv-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var secretOutside = Path.Combine(Path.GetTempPath(), "rpd-sm-secret-" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(Path.Combine(dir, "index.html"), "<html>Speedometer3</html>");
            File.WriteAllText(Path.Combine(dir, "app.js"), "console.log('ok');");
            File.WriteAllText(secretOutside, "secret");

            await using var server = new SpeedometerLocalServer(dir);
            Assert.Equal("127.0.0.1", server.BaseUri.Host);
            Assert.True(server.Port > 0);

            using var http = new HttpClient();
            var idxResp = await http.GetAsync($"{server.BaseUri}?startAutomatically=true");
            Assert.Equal(HttpStatusCode.OK, idxResp.StatusCode);
            Assert.Contains("text/html", idxResp.Content.Headers.ContentType?.ToString());
            Assert.Equal("<html>Speedometer3</html>", await idxResp.Content.ReadAsStringAsync());

            var jsResp = await http.GetAsync($"{server.BaseUri}app.js");
            Assert.Equal(HttpStatusCode.OK, jsResp.StatusCode);
            Assert.Contains("javascript", jsResp.Content.Headers.ContentType?.ToString());

            var traversalResp = await http.GetAsync($"{server.BaseUri}..%2F{Path.GetFileName(secretOutside)}");
            Assert.Equal(HttpStatusCode.NotFound, traversalResp.StatusCode);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
            try { File.Delete(secretOutside); } catch { }
        }
    }

    [Fact]
    public void ExtractZipSafely_VerifiesSha256_AndRejectsMismatchAndZipSlip()
    {
        var dest = Path.Combine(Path.GetTempPath(), "rpd-sm-zip-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var validZip = BuildZip(("Speedometer-3.1/index.html", "<html>ok</html>"), ("Speedometer-3.1/LICENSE", "BSD"));
            var expectedSha = Convert.ToHexString(SHA256.HashData(validZip.ToArray()));

            validZip.Position = 0;
            SpeedometerPackage.ExtractZipSafely(validZip, dest, expectedSha);
            var root = SpeedometerPackage.FindIndexRoot(dest);
            Assert.NotNull(root);
            Assert.True(File.Exists(Path.Combine(root!, "index.html")));

            // Hash mismatch must throw
            validZip.Position = 0;
            Assert.Throws<CryptographicException>(() =>
                SpeedometerPackage.ExtractZipSafely(validZip, dest, new string('0', 64)));

            // Zip-Slip path traversal must throw
            using var evilZip = BuildZip(("../../evil.txt", "pwned"));
            Assert.Throws<InvalidDataException>(() =>
                SpeedometerPackage.ExtractZipSafely(evilZip, dest));
        }
        finally
        {
            try { Directory.Delete(dest, recursive: true); } catch { }
        }
    }

    [Fact]
    public void CdpClient_TryParseScoreJson_HandlesValidAndInvalidPayloads()
    {
        Assert.True(CdpClient.TryParseScoreJson("""{"done":true,"score":14.72,"ci":0.18}""", out var score, out var ci));
        Assert.Equal(14.72, score, 2);
        Assert.Equal(0.18, ci!.Value, 2);

        Assert.True(CdpClient.TryParseScoreJson("""{"done":true,"score":11.5,"ci":null}""", out score, out ci));
        Assert.Equal(11.5, score, 2);
        Assert.Null(ci);

        Assert.False(CdpClient.TryParseScoreJson("""{"done":false}""", out _, out _));
        Assert.False(CdpClient.TryParseScoreJson("""{"done":true,"score":0}""", out _, out _));
        Assert.False(CdpClient.TryParseScoreJson("not-json", out _, out _));
    }

    [Fact]
    public void Baselines_ClassifyCpuAndJudgeBands()
    {
        Assert.Equal(SpeedometerCpuClass.MobileLowPower, SpeedometerBaselines.ClassifyCpu("Intel N100", 4));
        Assert.Equal(SpeedometerCpuClass.MobileMainstream, SpeedometerBaselines.ClassifyCpu("13th Gen Intel Core i7-1365U", 12));
        Assert.Equal(SpeedometerCpuClass.Desktop, SpeedometerBaselines.ClassifyCpu("AMD Ryzen 9 7950X", 32));

        Assert.Equal(SpeedometerBand.Pass, SpeedometerBaselines.Judge(16.0, SpeedometerCpuClass.MobileMainstream));
        Assert.Equal(SpeedometerBand.Warning, SpeedometerBaselines.Judge(10.0, SpeedometerCpuClass.MobileMainstream));
        Assert.Equal(SpeedometerBand.Critical, SpeedometerBaselines.Judge(7.0, SpeedometerCpuClass.MobileMainstream));
    }

    [Fact]
    public async Task Runner_RunsSpeedometerOnce_RecordsBrowserDetail_AndComparesHigherIsBetter()
    {
        var probe = new FakeSpeedometerProbes(new SpeedometerResult(10.0, "edge", "Microsoft Edge", "131.0", 0.15));
        var runner = new BenchmarkRunner(probe);
        var settings = new BenchmarkSettings { Enabled = [BenchmarkKind.Speedometer], Runs = 3 };

        var before = await runner.RunAsync(BenchmarkPhase.Before, settings, null, null, default);
        Assert.Equal(1, probe.Calls); // Speedometer runs 1 pass even when Runs = 3
        var bm = before.Get(BenchmarkKind.Speedometer)!;
        Assert.Equal(10.0, bm.Median);
        Assert.Contains("Microsoft Edge 131.0", bm.Detail);
        Assert.Contains("clean profile", bm.Detail);

        probe.NextResult = new SpeedometerResult(13.5, "edge", "Microsoft Edge", "131.0", 0.12);
        var after = await runner.RunAsync(BenchmarkPhase.After, settings, before.TimeUtc, null, default);
        var cmp = BenchmarkComparison.Build(before, after);
        var delta = cmp.Deltas.Single(d => d.Info.Kind == BenchmarkKind.Speedometer);
        Assert.Equal(BenchmarkVerdict.Better, delta.Verdict);
        Assert.Contains("faster", delta.ChangeSummary);
    }

    [Fact]
    public void BenchmarkService_MigratesSchemaV2ToV3_EnablingSpeedometer()
    {
        var path = Path.Combine(Path.GetTempPath(), "rpd-bench-v2-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var store = new FileBenchmarkStore(path);
            store.Save(new BenchmarkState(new BenchmarkSettings
            {
                SchemaVersion = 2,
                Enabled = [BenchmarkKind.BootTime, BenchmarkKind.CpuMulti],
            }));

            var svc = new BenchmarkService(new BenchmarkRunner(new FakeSpeedometerProbes(null)), store);
            Assert.Contains(BenchmarkKind.Speedometer, svc.Settings.Enabled);
            Assert.Contains(BenchmarkKind.BootTime, svc.Settings.Enabled);
            Assert.DoesNotContain(BenchmarkKind.CpuSingle, svc.Settings.Enabled);
            Assert.Equal(BenchmarkSettings.CurrentSchemaVersion, store.Load()!.Settings.SchemaVersion);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    private static MemoryStream BuildZip(params (string Name, string Content)[] entries)
    {
        var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var e = archive.CreateEntry(name);
                using var w = new StreamWriter(e.Open(), Encoding.UTF8);
                w.Write(content);
            }
        }
        ms.Position = 0;
        return ms;
    }

    private sealed class FakeSpeedometerProbes(SpeedometerResult? next) : IBenchmarkProbes
    {
        public SpeedometerResult? NextResult { get; set; } = next;
        public int Calls { get; private set; }
        public BenchmarkConditions ReadConditions() => new(false, 52, "Balanced");
        public Task<IdleSample?> SampleIdleAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<IdleSample?>(null);
        public Task<double?> StartProgramAsync(BuiltInProgram program, CancellationToken ct) => Task.FromResult<double?>(null);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan duration, CancellationToken ct) => Task.FromResult<double?>(null);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);
        public Task<SpeedometerResult?> RunSpeedometerAsync(TimeSpan timeout, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(NextResult);
        }
    }
}
