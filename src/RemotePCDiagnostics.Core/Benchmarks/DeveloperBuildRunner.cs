using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>Environment readings needed by the developer setup check and developer benchmarks.</summary>
public interface IDeveloperEnvironmentProbe
{
    Task<IReadOnlyList<DetectedToolchain>> DetectToolchainsAsync(CancellationToken ct = default);
    string? FindHyperfine();
    double? ReadTempVolumeFreeGb();
    Task<DevDriveVolumeStatus> QueryDevDriveAsync(string? driveLetter = null, CancellationToken ct = default);
    Task<DefenderProbe.Status?> ReadDefenderAsync(CancellationToken ct = default);
    BenchmarkConditions ReadConditions();
    (string? CpuName, int CoreCount) ReadCpuInfo();
    (int Build, int Ubr) ReadWindowsBuild();
    string? ReadCurrentUserSid();
    bool IsAgentConnected { get; }
}

/// <summary>
/// Deterministic, zero-network-dependency, MIT-licensed mid-size C# multi-project solution used for the Phase 1/2 clean-build benchmark.
/// Exercises multi-core MSBuild, Roslyn parsing/binding/emitting, generics, LINQ, and Release IL generation without any NuGet downloads.
/// </summary>
public static class DeveloperCSharpPin
{
    public const string PinId = "csharp-rpcd-bench-v1";

    /// <summary>
    /// Materializes the pinned 5-project C# solution into <paramref name="targetDir"/> and returns the solution path and SHA-256 hash of all source files.
    /// </summary>
    public static (string SolutionPath, string TreeSha256) Materialize(string targetDir, int sdkMajor = 10)
    {
        var tfm = sdkMajor switch
        {
            >= 10 => "net10.0",
            9 => "net9.0",
            8 => "net8.0",
            _ => "net8.0",
        };

        Directory.CreateDirectory(targetDir);
        var files = BuildFiles(tfm);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        foreach (var (relPath, content) in files.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var full = Path.Combine(targetDir, relPath.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            var bytes = Encoding.UTF8.GetBytes(content);
            File.WriteAllBytes(full, bytes);
            sha.AppendData(Encoding.UTF8.GetBytes(relPath + "\n"));
            sha.AppendData(bytes);
        }

        var hash = Convert.ToHexString(sha.GetHashAndReset());
        return (Path.Combine(targetDir, "BenchApp", "BenchApp.csproj"), hash);
    }

    private static Dictionary<string, string> BuildFiles(string tfm)
    {
        var files = new Dictionary<string, string>(StringComparer.Ordinal);
        string[] libs = ["BenchCore", "BenchMath", "BenchParse", "BenchGraph"];

        foreach (var lib in libs)
        {
            var refs = lib == "BenchCore" ? "" : $"\n  <ItemGroup><ProjectReference Include=\"..\\BenchCore\\BenchCore.csproj\" /></ItemGroup>";
            files[$"{lib}/{lib}.csproj"] =
                $"<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>{tfm}</TargetFramework>\n    <Nullable>enable</Nullable>\n    <ImplicitUsings>enable</ImplicitUsings>\n    <Deterministic>true</Deterministic>\n  </PropertyGroup>{refs}\n</Project>\n";

            for (var i = 0; i < 8; i++)
            {
                files[$"{lib}/Unit{i:00}.cs"] = GenerateUnit(lib, i);
            }
        }

        var appRefs = string.Join("\n", libs.Select(l => $"    <ProjectReference Include=\"..\\{l}\\{l}.csproj\" />"));
        files["BenchApp/BenchApp.csproj"] =
            $"<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>{tfm}</TargetFramework>\n    <Nullable>enable</Nullable>\n    <ImplicitUsings>enable</ImplicitUsings>\n    <Deterministic>true</Deterministic>\n  </PropertyGroup>\n  <ItemGroup>\n{appRefs}\n  </ItemGroup>\n</Project>\n";

        files["BenchApp/Program.cs"] =
            "using BenchCore;\nusing BenchMath;\nusing BenchParse;\nusing BenchGraph;\n" +
            "var sum = BenchCore.Unit00.Compute(42) + BenchMath.Unit00.Compute(42) + BenchParse.Unit00.Compute(42) + BenchGraph.Unit00.Compute(42);\n" +
            "Console.WriteLine(sum);\n";

        return files;
    }

    private static string GenerateUnit(string ns, int idx) =>
        $"namespace {ns};\n" +
        $"public static class Unit{idx:00}\n" +
        "{\n" +
        $"    public sealed record Item{idx:00}(int Id, string Key, double Value);\n" +
        $"    public static long Compute(int seed)\n" +
        "    {\n" +
        $"        var items = Enumerable.Range(1, 32).Select(i => new Item{idx:00}(i + seed, $\"k{{i}}_{idx}\", (i * 1.6180339) / (seed + 1))).ToList();\n" +
        "        var grouped = items.GroupBy(x => x.Id % 7).ToDictionary(g => g.Key, g => g.OrderByDescending(x => x.Value).Select(x => x.Key.Length + x.Id).Sum());\n" +
        "        long acc = seed;\n" +
        "        foreach (var kv in grouped) acc = (acc * 31) ^ (kv.Key * 17L + kv.Value);\n" +
        "        return acc;\n" +
        "    }\n" +
        "}\n";
}

/// <summary>Options controlling repeat counts and timeouts for developer clean builds.</summary>
public sealed record DeveloperBuildOptions(
    int ColdRepeats = 3,
    int WarmWarmups = 1,
    int WarmRepeats = 5,
    TimeSpan? PerCommandTimeout = null,
    bool IncludeAntivirusComparison = false,
    bool AllowHyperfine = true)
{
    public TimeSpan EffectiveTimeout => PerCommandTimeout ?? TimeSpan.FromMinutes(5);
}

/// <summary>
/// Runs clean developer builds (cold + warm, restore timed separately, temp-folder cleanup),
/// optional approval-gated antivirus comparison, and opt-in Phase 2 Dev Drive comparison.
/// </summary>
public sealed class DeveloperBuildRunner(
    IDeveloperEnvironmentProbe env,
    IProcessLauncher? launcher = null,
    IMachineTweaks? machineTweaks = null,
    IDeveloperSampleStore? sampleStore = null,
    DeveloperBaselineCatalog? baselines = null,
    ILogger? log = null,
    string? tempRootOverride = null)
{
    private readonly IProcessLauncher _launcher = launcher ?? new SystemProcessLauncher();
    private readonly DeveloperBaselineCatalog _baselines = baselines ?? DeveloperBaselineCatalog.Empty;

    private void Log(string m) => log.Info("[dev-bench] " + m);

    /// <summary>Evaluates whether the opt-in Dev Drive comparison can be offered on this PC.</summary>
    public async Task<DevDrivePrecheckResult> EvaluateDevDrivePrecheckAsync(CancellationToken ct = default)
    {
        var (build, ubr) = env.ReadWindowsBuild();
        var winStr = build > 0 ? $"{build}.{ubr}" : "unknown";
        var osOk = DeveloperToolchainDetector.IsWindows11DevDriveCapable(build, ubr);
        if (!osOk)
            return new(false, $"Requires Windows 11 build {DeveloperScoring.MinWindows11DevDriveBuild}.{DeveloperScoring.MinWindows11DevDriveRevision} or later (this PC: {winStr}).", winStr);

        var devDrive = await env.QueryDevDriveAsync(null, ct).ConfigureAwait(false);
        if (!devDrive.SupportedByOs || !devDrive.PolicyEnabled)
            return new(false, "Dev Drive is disabled by policy or unavailable on this Windows build.", winStr, false);

        if (!env.IsAgentConnected)
            return new(false, "Requires the elevated Agent helper. " + ElevationService.AdminRepairHint, winStr, true, false);

        var freeGb = env.ReadTempVolumeFreeGb();
        if (freeGb is null || freeGb.Value < DeveloperScoring.MinDevDriveFreeDiskGb)
            return new(false, string.Create(CultureInfo.InvariantCulture, $"Needs at least {DeveloperScoring.MinDevDriveFreeDiskGb:0} GB free for the temporary VHDX ({freeGb?.ToString("0.0", CultureInfo.InvariantCulture) ?? "unknown"} GB free)."), winStr, true, true, freeGb);

        var cond = env.ReadConditions();
        if (cond.OnBattery == true)
            return new(false, "Plug in AC power before running the Dev Drive comparison.", winStr, true, true, freeGb, false);

        return new(true, null, winStr, true, true, freeGb, cond.OnBattery != true);
    }

    /// <summary>Runs the Phase 1 C# clean build benchmark (cold + warm + optional approval-gated AV exclusion comparison).</summary>
    public async Task<DeveloperBuildResult> RunCSharpCleanBuildAsync(
        DeveloperBuildOptions? options = null,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        options ??= new DeveloperBuildOptions();
        var toolchains = await env.DetectToolchainsAsync(ct).ConfigureAwait(false);
        var dotnet = toolchains.FirstOrDefault(t => t.Language == DeveloperLanguage.CSharp);
        if (dotnet is null)
            return Failed(DeveloperLanguage.CSharp, "dotnet SDK is not installed.");

        var freeGb = env.ReadTempVolumeFreeGb();
        if (freeGb is not null && freeGb.Value < DeveloperScoring.MinFreeDiskGb)
            return Failed(DeveloperLanguage.CSharp, string.Create(CultureInfo.InvariantCulture,
                $"Could not run: only {freeGb.Value:0.0} GB free on the temp volume (needs at least {DeveloperScoring.MinFreeDiskGb:0} GB)."), dotnet);

        var tempRoot = tempRootOverride ?? Path.GetTempPath();
        var workDir = Path.Combine(tempRoot, $"{DevDriveRules.BuildTempPrefix}{Guid.NewGuid():N}");
        var tempExclusionAdded = false;

        try
        {
            progress?.Report("Preparing pinned C# benchmark sources…");
            var (projectPath, sha256) = DeveloperCSharpPin.Materialize(workDir, dotnet.MajorVersion ?? 10);

            var conditions = env.ReadConditions();
            var (comparable, condNotes) = DeveloperScoring.CheckComparability(conditions.OnBattery, conditions.PowerPlan, thermallyThrottling: false);
            var defender = await env.ReadDefenderAsync(ct).ConfigureAwait(false);
            var defenderActive = defender?.Active;
            var folderExcluded = defender is { ExclusionsReadable: true } d && d.Paths.Any(p => DefenderProbe.Covers(p, workDir));

            // 1. Restore (timed separately, excluded from build score)
            progress?.Report("Timing C# restore (kept separate from build score)…");
            var (restoreOk, restoreSecs, restoreErr) = await TimedCommandAsync(dotnet.ExecutablePath, ["restore", projectPath, "--ignore-failed-sources", "-v", "q"], options.EffectiveTimeout, ct).ConfigureAwait(false);
            if (!restoreOk)
                return Failed(DeveloperLanguage.CSharp, $"Could not run: dotnet restore failed ({restoreErr ?? "error"}).", dotnet, sha256, restoreSecs);

            var hyperfine = options.AllowHyperfine ? env.FindHyperfine() : null;
            var usedHyperfine = false;

            // 2. Cold clean builds
            progress?.Report($"Running cold C# clean builds ({options.ColdRepeats} repeats)…");
            var coldSamples = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, projectPath, workDir, options.ColdRepeats, warmups: 0, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false);
            if (coldSamples.Count == 0)
                return Failed(DeveloperLanguage.CSharp, "Could not run: cold dotnet build failed.", dotnet, sha256, restoreSecs);
            if (hyperfine is not null) usedHyperfine = true;

            // 3. Warm clean builds (1 warmup discarded, outputs deleted before EVERY repeat so compiler does full work)
            progress?.Report($"Running warm C# clean builds ({options.WarmRepeats} repeats)…");
            var warmSamples = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, projectPath, workDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false);
            if (warmSamples.Count == 0)
                return Failed(DeveloperLanguage.CSharp, "Could not run: warm dotnet build failed.", dotnet, sha256, restoreSecs);

            // 4. Optional approval-gated Antivirus comparison (temporary exclusion through Agent, then removed in finally)
            IReadOnlyList<double>? warmExcludedSamples = null;
            double? warmExcludedMedian = null;
            if (options.IncludeAntivirusComparison && machineTweaks is not null && env.IsAgentConnected)
            {
                progress?.Report("Adding temporary Defender exclusion through Agent for antivirus comparison…");
                var (added, _) = await machineTweaks.AddTempBuildDefenderExclusionAsync(workDir, ct).ConfigureAwait(false);
                if (added)
                {
                    tempExclusionAdded = true;
                    progress?.Report($"Running warm C# clean builds with temporary exclusion ({options.WarmRepeats} repeats)…");
                    warmExcludedSamples = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, projectPath, workDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false);
                    warmExcludedMedian = DeveloperScoring.Median(warmExcludedSamples);
                }
            }

            var coldMedian = DeveloperScoring.Median(coldSamples);
            var warmMedian = DeveloperScoring.Median(warmSamples);
            var (cpuName, coreCount) = env.ReadCpuInfo();
            var cpuClass = DeveloperScoring.ClassifyCpu(cpuName, coreCount);
            var baseline = _baselines.FindUsable(cpuClass, DeveloperLanguage.CSharp, DeveloperCSharpPin.PinId, dotnet.MajorVersion);
            var score = comparable ? DeveloperScoring.ComputeScore(warmMedian, baseline) : null;
            var band = DeveloperScoring.EvaluateBand(warmMedian, baseline, comparable);

            var result = new DeveloperBuildResult(
                DeveloperLanguage.CSharp,
                DeveloperCSharpPin.PinId,
                sha256,
                dotnet.Version,
                dotnet.MajorVersion,
                restoreSecs,
                coldMedian,
                coldSamples,
                warmMedian,
                warmSamples,
                warmExcludedMedian,
                warmExcludedSamples,
                usedHyperfine,
                defenderActive,
                folderExcluded,
                score,
                band,
                comparable,
                condNotes);

            // Append anonymous sample beside benchmarks.json (no computer name, account, serial, or path)
            sampleStore?.Append(new DeveloperBenchmarkSample(
                DeveloperLanguage.CSharp,
                DeveloperCSharpPin.PinId,
                sha256,
                dotnet.Version,
                dotnet.MajorVersion,
                cpuClass,
                cpuName,
                coreCount,
                conditions.OnBattery,
                conditions.PowerPlan,
                defenderActive == true && folderExcluded != true,
                coldMedian,
                warmMedian,
                warmExcludedMedian,
                restoreSecs,
                coldSamples.Count,
                warmSamples.Count,
                DateTimeOffset.UtcNow));

            Log($"C# clean build done: cold={coldMedian:0.00}s warm={warmMedian:0.00}s restore={restoreSecs:0.00}s");
            return result;
        }
        finally
        {
            if (tempExclusionAdded && machineTweaks is not null)
            {
                try { await machineTweaks.RemoveTempBuildDefenderExclusionAsync(workDir, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) { Log("Failed to remove temp Defender exclusion: " + ex.Message); }
            }
            TryDeleteDirectory(workDir);
        }
    }

    /// <summary>
    /// Phase 2 opt-in Dev Drive comparison: builds the same cached C# pin on NTFS first, then on a temporary ~50 GB
    /// Dev Drive VHDX created and removed by the elevated Agent. Always cleans up on success, failure, and cancel.
    /// </summary>
    public async Task<DevDriveComparisonResult> RunDevDriveComparisonAsync(
        DeveloperBuildOptions? options = null,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        options ??= new DeveloperBuildOptions(IncludeAntivirusComparison: false);

        var precheck = await EvaluateDevDrivePrecheckAsync(ct).ConfigureAwait(false);
        if (!precheck.Eligible)
            return new(false, DeveloperCSharpPin.PinId, "", Note: precheck.Reason);

        if (machineTweaks is null)
            return new(false, DeveloperCSharpPin.PinId, "", Note: "The Agent is required to create a temporary Dev Drive. " + ElevationService.AdminRepairHint);

        var toolchains = await env.DetectToolchainsAsync(ct).ConfigureAwait(false);
        var dotnet = toolchains.FirstOrDefault(t => t.Language == DeveloperLanguage.CSharp);
        if (dotnet is null)
            return new(false, DeveloperCSharpPin.PinId, "", Note: "dotnet SDK is not installed.");

        var tempRoot = tempRootOverride ?? Path.GetTempPath();
        var ntfsDir = Path.Combine(tempRoot, $"{DevDriveRules.BuildTempPrefix}ntfs-{Guid.NewGuid():N}");
        string? vhdxPath = null;
        string? devDriveBuildDir = null;

        try
        {
            // 1. NTFS pass first (order: NTFS, then Dev Drive)
            progress?.Report("Preparing pinned C# sources on NTFS…");
            var (ntfsProj, sha256) = DeveloperCSharpPin.Materialize(ntfsDir, dotnet.MajorVersion ?? 10);
            var (rOk, _, rErr) = await TimedCommandAsync(dotnet.ExecutablePath, ["restore", ntfsProj, "--ignore-failed-sources", "-v", "q"], options.EffectiveTimeout, ct).ConfigureAwait(false);
            if (!rOk)
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: $"NTFS restore failed ({rErr ?? "error"}).");

            var hyperfine = options.AllowHyperfine ? env.FindHyperfine() : null;
            progress?.Report("Timing C# clean builds on NTFS (cold & warm)…");
            var ntfsCold = DeveloperScoring.Median(await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ntfsProj, ntfsDir, options.ColdRepeats, 0, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false));
            var ntfsWarm = DeveloperScoring.Median(await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ntfsProj, ntfsDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false));
            if (ntfsCold is null || ntfsWarm is null)
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: "NTFS build failed.");

            // 2. Ask Agent to create & mount temporary ~50 GB Dev Drive VHDX
            progress?.Report("Creating temporary 50 GB Dev Drive VHDX through Agent…");
            var mount = await machineTweaks.CreateTempDevDriveAsync(DevDriveRules.DefaultSizeGb, env.ReadCurrentUserSid(), ct).ConfigureAwait(false);
            if (!mount.Ok || string.IsNullOrWhiteSpace(mount.VhdxPath) || string.IsNullOrWhiteSpace(mount.BuildFolder))
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: mount.Error ?? "Could not create temporary Dev Drive.");

            vhdxPath = mount.VhdxPath;
            devDriveBuildDir = Path.Combine(mount.BuildFolder, $"run-{Guid.NewGuid():N}");

            // Check Defender performance mode on the mounted Dev Drive
            var devDriveStatus = await env.QueryDevDriveAsync(mount.DriveLetter, ct).ConfigureAwait(false);

            // 3. Dev Drive pass
            progress?.Report("Preparing pinned C# sources on temporary Dev Drive…");
            var (ddProj, _) = DeveloperCSharpPin.Materialize(devDriveBuildDir, dotnet.MajorVersion ?? 10);
            var (ddRestoreOk, _, ddRestoreErr) = await TimedCommandAsync(dotnet.ExecutablePath, ["restore", ddProj, "--ignore-failed-sources", "-v", "q"], options.EffectiveTimeout, ct).ConfigureAwait(false);
            if (!ddRestoreOk)
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: $"Dev Drive restore failed ({ddRestoreErr ?? "error"}).");

            progress?.Report("Timing C# clean builds on temporary Dev Drive (cold & warm)…");
            var ddCold = DeveloperScoring.Median(await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ddProj, devDriveBuildDir, options.ColdRepeats, 0, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false));
            var ddWarm = DeveloperScoring.Median(await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ddProj, devDriveBuildDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false));
            if (ddCold is null || ddWarm is null)
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: "Dev Drive build failed.");

            return new(
                Succeeded: true,
                PinId: DeveloperCSharpPin.PinId,
                PinSha256: sha256,
                Order: "NTFS, then Dev Drive",
                NtfsColdMedianSeconds: ntfsCold,
                NtfsWarmMedianSeconds: ntfsWarm,
                DevDriveColdMedianSeconds: ddCold,
                DevDriveWarmMedianSeconds: ddWarm,
                DefenderPerformanceModeActive: devDriveStatus.DefenderPerformanceModeActive,
                CompletedAtUtc: DateTimeOffset.UtcNow);
        }
        finally
        {
            TryDeleteDirectory(ntfsDir);
            if (devDriveBuildDir is not null) TryDeleteDirectory(devDriveBuildDir);
            if (vhdxPath is not null)
            {
                try { await machineTweaks.RemoveTempDevDriveAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) { Log("Failed to remove temporary Dev Drive VHDX: " + ex.Message); }
            }
        }
    }

    private async Task<IReadOnlyList<double>> MeasureCleanBuildsAsync(
        string dotnetExe,
        string projectPath,
        string workDir,
        int repeats,
        int warmups,
        string? hyperfineExe,
        TimeSpan timeout,
        CancellationToken ct)
    {
        if (hyperfineExe is not null)
        {
            var hfSamples = await TryMeasureWithHyperfineAsync(hyperfineExe, dotnetExe, projectPath, workDir, repeats, warmups, timeout, ct).ConfigureAwait(false);
            if (hfSamples is { Count: > 0 }) return hfSamples;
        }

        // In-app loop matching hyperfine's protocol: delete bin/obj before every repeat so the compiler does full work.
        var samples = new List<double>();
        for (var i = 0; i < warmups + Math.Max(1, repeats); i++)
        {
            ct.ThrowIfCancellationRequested();
            CleanBuildOutputs(workDir);
            var (ok, seconds, _) = await TimedCommandAsync(dotnetExe, ["build", projectPath, "-c", "Release", "--no-restore", "-v", "q"], timeout, ct).ConfigureAwait(false);
            if (!ok) return [];
            if (i >= warmups)
                samples.Add(Math.Round(seconds, 3));
        }
        return samples;
    }

    private async Task<IReadOnlyList<double>?> TryMeasureWithHyperfineAsync(
        string hyperfineExe,
        string dotnetExe,
        string projectPath,
        string workDir,
        int repeats,
        int warmups,
        TimeSpan timeout,
        CancellationToken ct)
    {
        var jsonOut = Path.Combine(workDir, $"hf-{Guid.NewGuid():N}.json");
        try
        {
            var prepare = OperatingSystem.IsWindows()
                ? $"powershell -NoProfile -Command \"Get-ChildItem -Path '{workDir}' -Recurse -Directory -Include bin,obj | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue\""
                : $"find '{workDir}' -type d \\( -name bin -o -name obj \\) -exec rm -rf {{}} +";
            var cmd = $"\"{dotnetExe}\" build \"{projectPath}\" -c Release --no-restore -v q";
            var args = new List<string>
            {
                "--runs", Math.Max(1, repeats).ToString(CultureInfo.InvariantCulture),
                "--warmup", Math.Max(0, warmups).ToString(CultureInfo.InvariantCulture),
                "--prepare", prepare,
                "--export-json", jsonOut,
                cmd,
            };
            var totalTimeout = TimeSpan.FromSeconds(timeout.TotalSeconds * (repeats + warmups + 1));
            var r = await _launcher.RunAsync(hyperfineExe, args, totalTimeout, ct).ConfigureAwait(false);
            if (r.ExitCode != 0 || !File.Exists(jsonOut)) return null;
            return ParseHyperfineTimes(await File.ReadAllTextAsync(jsonOut, ct).ConfigureAwait(false));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log("hyperfine failed, falling back to in-app loop: " + ex.Message);
            return null;
        }
        finally
        {
            try { if (File.Exists(jsonOut)) File.Delete(jsonOut); } catch { }
        }
    }

    /// <summary>Parses the <c>results[0].times</c> array from hyperfine's <c>--export-json</c> output.</summary>
    public static IReadOnlyList<double>? ParseHyperfineTimes(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
                return null;
            var first = results.EnumerateArray().FirstOrDefault();
            if (first.ValueKind != JsonValueKind.Object || !first.TryGetProperty("times", out var times) || times.ValueKind != JsonValueKind.Array)
                return null;
            var list = new List<double>();
            foreach (var t in times.EnumerateArray())
            {
                if (t.ValueKind == JsonValueKind.Number && t.TryGetDouble(out var v) && v > 0)
                    list.Add(Math.Round(v, 3));
            }
            return list.Count > 0 ? list : null;
        }
        catch (JsonException) { return null; }
    }

    private async Task<(bool Ok, double Seconds, string? Error)> TimedCommandAsync(string exe, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var r = await _launcher.RunAsync(exe, args, timeout, ct).ConfigureAwait(false);
        sw.Stop();
        var err = r.ExitCode == 0 ? null : (string.IsNullOrWhiteSpace(r.StdErr) ? r.StdOut : r.StdErr)?.Trim();
        return (r.ExitCode == 0, Math.Max(0.001, Math.Round(sw.Elapsed.TotalSeconds, 3)), err);
    }

    /// <summary>Deletes all <c>bin</c> and <c>obj</c> directories under <paramref name="root"/> before each clean build repeat.</summary>
    public static void CleanBuildOutputs(string root)
    {
        if (!Directory.Exists(root)) return;
        foreach (var dir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories).ToList())
        {
            var name = Path.GetFileName(dir);
            if (name.Equals("bin", StringComparison.OrdinalIgnoreCase) || name.Equals("obj", StringComparison.OrdinalIgnoreCase))
                TryDeleteDirectory(dir);
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch { }
    }

    private static DeveloperBuildResult Failed(DeveloperLanguage lang, string note, DetectedToolchain? tc = null, string sha256 = "", double? restoreSecs = null) =>
        new(lang, DeveloperCSharpPin.PinId, sha256, tc?.Version, tc?.MajorVersion, restoreSecs, null, [], null, [], Note: note);
}
