using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Benchmarks;

internal sealed class BenchmarkCleanupException(
    string message = "Could not confirm removal of a temporary Defender benchmark exclusion. Check the Agent logs and Defender settings.")
    : InvalidOperationException(message);

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
    public const string PinId = "csharp-rpcd-bench-v2";

    /// <summary>Oldest SDK major this pin can build. Older SDKs are hidden rather than offered a project they cannot compile.</summary>
    public const int MinSdkMajor = 8;

    /// <summary>
    /// Target framework the installed SDK can build: <c>net8.0</c> for SDK 8, <c>net9.0</c> for SDK 9, and so on.
    /// Null when the major is missing or older than <see cref="MinSdkMajor"/> (those SDKs cannot build this pin).
    /// </summary>
    public static string? TargetFrameworkForSdk(int? sdkMajor) =>
        sdkMajor is >= MinSdkMajor and int major
            ? string.Create(CultureInfo.InvariantCulture, $"net{major}.0")
            : null;

    /// <summary>Why the C# benchmark cannot be offered for this SDK, or null when it can.</summary>
    public static string? UnsupportedSdkReason(string? version, int? major)
    {
        if (TargetFrameworkForSdk(major) is not null) return null;
        var shown = string.IsNullOrWhiteSpace(version) ? "an unrecognized version" : version.Trim();
        return string.Create(CultureInfo.InvariantCulture,
            $"The C# clean-build benchmark needs .NET SDK {MinSdkMajor} or newer (this PC has {shown}).");
    }

    /// <summary>
    /// Materializes the pinned 21-project C# solution into <paramref name="targetDir"/> and returns the entry project path and SHA-256 hash of all source files.
    /// </summary>
    public static (string SolutionPath, string TreeSha256) Materialize(string targetDir, int sdkMajor = 10)
    {
        var tfm = TargetFrameworkForSdk(sdkMajor)
            ?? throw new ArgumentOutOfRangeException(nameof(sdkMajor), sdkMajor, UnsupportedSdkReason(sdkMajor.ToString(CultureInfo.InvariantCulture), sdkMajor));

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

    private const int UnitsPerLibrary = 24;

    private static Dictionary<string, string> BuildFiles(string tfm)
    {
        var files = new Dictionary<string, string>(StringComparer.Ordinal);
        string[] tier0 = ["BenchCore", "BenchCollections", "BenchText", "BenchMath"];
        string[] tier1 = ["BenchParse", "BenchGraph", "BenchQuery", "BenchFormat", "BenchRules", "BenchIndex", "BenchMetrics", "BenchCache"];
        string[] tier2 = ["BenchEngine01", "BenchEngine02", "BenchEngine03", "BenchEngine04", "BenchEngine05", "BenchEngine06", "BenchEngine07", "BenchEngine08"];

        static string ProjectXml(string tfm, IReadOnlyList<string> refs, bool isExe = false)
        {
            var outType = isExe ? "\n    <OutputType>Exe</OutputType>" : "";
            var refBlock = refs.Count == 0
                ? ""
                : "\n  <ItemGroup>\n" + string.Join("\n", refs.Select(r => $"    <ProjectReference Include=\"..\\{r}\\{r}.csproj\" />")) + "\n  </ItemGroup>";
            return $"<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>{outType}\n    <TargetFramework>{tfm}</TargetFramework>\n    <Nullable>enable</Nullable>\n    <ImplicitUsings>enable</ImplicitUsings>\n    <Deterministic>true</Deterministic>\n  </PropertyGroup>{refBlock}\n</Project>\n";
        }

        void AddLibrary(string lib, IReadOnlyList<string> refs, string? upstreamCall)
        {
            files[$"{lib}/{lib}.csproj"] = ProjectXml(tfm, refs);
            for (var i = 0; i < UnitsPerLibrary; i++)
                files[$"{lib}/Unit{i:00}.cs"] = GenerateUnit(lib, i, upstreamCall);
        }

        foreach (var lib in tier0)
            AddLibrary(lib, [], null);

        for (var i = 0; i < tier1.Length; i++)
        {
            var dep = tier0[i % tier0.Length];
            AddLibrary(tier1[i], [tier0[0], dep == tier0[0] ? tier0[1] : dep], $"{dep}.Unit00.Compute(seed)");
        }

        for (var i = 0; i < tier2.Length; i++)
        {
            var depA = tier1[i % tier1.Length];
            var depB = tier1[(i + 1) % tier1.Length];
            AddLibrary(tier2[i], [tier0[0], depA, depB], $"{depA}.Unit00.Compute(seed) ^ {depB}.Unit01.Compute(seed + 1)");
        }

        files["BenchApp/BenchApp.csproj"] = ProjectXml(tfm, tier2, isExe: true);
        var usings = string.Join("\n", tier2.Select(l => $"using {l};"));
        var sumExpr = string.Join(" + ", tier2.Select(l => $"{l}.Unit00.Compute(42)"));
        files["BenchApp/Program.cs"] = $"{usings}\nvar sum = {sumExpr};\nConsole.WriteLine(sum);\n";

        return files;
    }

    private static string GenerateUnit(string ns, int idx, string? upstreamCall)
    {
        var upstream = upstreamCall is null ? "0L" : upstreamCall;
        return
            $"namespace {ns};\n" +
            $"public sealed record Item{idx:00}<T>(int Id, string Key, double Value, T Tag) where T : struct;\n" +
            $"public readonly record struct Metric{idx:00}(int Bucket, long Count, double Sum, double Min, double Max);\n" +
            $"public static class Unit{idx:00}\n" +
            "{\n" +
            $"    private static readonly int[] Weights = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41];\n" +
            $"    public static IReadOnlyList<Metric{idx:00}> Analyze<T>(ReadOnlySpan<int> input, T tag) where T : struct\n" +
            "    {\n" +
            $"        var items = new List<Item{idx:00}<T>>(input.Length);\n" +
            "        for (var i = 0; i < input.Length; i++)\n" +
            "        {\n" +
            "            var v = input[i];\n" +
            $"            var score = (v * Weights[i % Weights.Length] * 1.6180339) / ((i % 9) + 1.0);\n" +
            $"            items.Add(new Item{idx:00}<T>(v, $\"k{{v}}_{idx}_{{i}}\", score, tag));\n" +
            "        }\n" +
            "        return items\n" +
            "            .GroupBy(x => Math.Abs(x.Id) % 11)\n" +
            "            .OrderBy(g => g.Key)\n" +
            "            .Select(g =>\n" +
            "            {\n" +
            "                double sum = 0, min = double.MaxValue, max = double.MinValue;\n" +
            "                long count = 0;\n" +
            "                foreach (var x in g)\n" +
            "                {\n" +
            "                    sum += x.Value;\n" +
            "                    if (x.Value < min) min = x.Value;\n" +
            "                    if (x.Value > max) max = x.Value;\n" +
            "                    count++;\n" +
            "                }\n" +
            $"                return new Metric{idx:00}(g.Key, count, sum, min, max);\n" +
            "            })\n" +
            "            .ToList();\n" +
            "    }\n" +
            $"    public static long Classify(Metric{idx:00} m) => m switch\n" +
            "    {\n" +
            "        { Count: <= 0 } => 0L,\n" +
            "        { Max: > 100.0, Count: >= 3 } => (long)(m.Sum * 13) ^ (m.Bucket * 31L),\n" +
            "        { Min: < 0.0 } => (long)(m.Max * 7) + m.Count,\n" +
            "        _ => (long)(m.Sum * 3) + m.Bucket + m.Count,\n" +
            "    };\n" +
            "    public static long Compute(int seed)\n" +
            "    {\n" +
            "        Span<int> buf = stackalloc int[48];\n" +
            "        for (var i = 0; i < buf.Length; i++) buf[i] = ((seed + i) * 31) ^ (i * 17);\n" +
            "        var metrics = Analyze(buf, seed);\n" +
            $"        long acc = {upstream};\n" +
            "        foreach (var m in metrics) acc = unchecked((acc * 397) ^ Classify(m));\n" +
            "        return acc;\n" +
            "    }\n" +
            "}\n";
    }
}

/// <summary>Options controlling repeat counts and timeouts for developer clean builds.</summary>
public sealed record DeveloperBuildOptions(
    int ColdRepeats = 3,
    int WarmWarmups = 2,
    int WarmRepeats = 5,
    TimeSpan? PerCommandTimeout = null,
    bool IncludeAntivirusComparison = false,
    bool AllowHyperfine = true,
    int? TargetDotNetSdkMajor = null,
    string? WorkRootOverride = null,
    string? CustomSolutionPath = null)
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
        if (DeveloperCSharpPin.UnsupportedSdkReason(dotnet.Version, dotnet.MajorVersion) is { } tooOld)
            return Failed(DeveloperLanguage.CSharp, "Could not run: " + tooOld, dotnet);

        var customPath = string.IsNullOrWhiteSpace(options.CustomSolutionPath) ? null : options.CustomSolutionPath.Trim().Trim('"');
        var isCustomSolution = customPath is not null;
        if (isCustomSolution)
        {
            var ext = Path.GetExtension(customPath);
            if (!File.Exists(customPath) || !(ext.Equals(".sln", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".slnx", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".csproj", StringComparison.OrdinalIgnoreCase)))
            {
                return Failed(DeveloperLanguage.CSharp, "Selected solution/project file was not found or is not a .sln, .slnx, or .csproj file.", dotnet);
            }
        }
        else
        {
            var freeGb = env.ReadTempVolumeFreeGb();
            if (freeGb is not null && freeGb.Value < DeveloperScoring.MinFreeDiskGb)
                return Failed(DeveloperLanguage.CSharp, string.Create(CultureInfo.InvariantCulture,
                    $"Could not run: only {freeGb.Value:0.0} GB free on the temp volume (needs at least {DeveloperScoring.MinFreeDiskGb:0} GB)."), dotnet);
        }

        var tempRoot = !string.IsNullOrWhiteSpace(options.WorkRootOverride)
            ? options.WorkRootOverride
            : (tempRootOverride ?? Path.GetTempPath());
        var workDir = isCustomSolution
            ? Path.GetDirectoryName(Path.GetFullPath(customPath!))!
            : Path.Combine(tempRoot, $"{DevDriveRules.BuildTempPrefix}{Guid.NewGuid():N}");
        var tempExclusionAdded = false;
        string? tempGlobalJsonPath = null;
        string? originalGlobalJson = null;

        try
        {
            var effectiveMajor = options.TargetDotNetSdkMajor ?? dotnet.MajorVersion!.Value;
            string projectPath;
            string pinId;
            string sha256;
            if (isCustomSolution)
            {
                projectPath = Path.GetFullPath(customPath!);
                pinId = Path.GetFileName(projectPath);
                sha256 = "custom";
                progress?.Report($"Preparing {pinId}…");
            }
            else
            {
                progress?.Report("Preparing pinned C# benchmark sources…");
                (projectPath, sha256) = DeveloperCSharpPin.Materialize(workDir, effectiveMajor);
                pinId = DeveloperCSharpPin.PinId;
            }

            var actualSdkVersion = dotnet.Version;
            int? actualSdkMajor = dotnet.MajorVersion;
            if (options.TargetDotNetSdkMajor is { } pinMajor)
            {
                // dotnet picks the SDK from the nearest global.json. A solution's own global.json (RemotePCDiagnostics has one
                // for the test runner only) used to stop the pin from being written, so the build ran on the newest SDK.
                // Pin the sdk section in that file for the run, keep everything else in it, and put the original back after.
                var globalJsonPath = Path.Combine(workDir, "global.json");
                if (isCustomSolution && File.Exists(globalJsonPath))
                {
                    originalGlobalJson = await File.ReadAllTextAsync(globalJsonPath, ct).ConfigureAwait(false);
                    if (DotNetSdkPin.WithSdkPin(originalGlobalJson, pinMajor) is not { } pinned)
                    {
                        originalGlobalJson = null;
                        return Failed(DeveloperLanguage.CSharp, $"Could not run: {globalJsonPath} could not be read as JSON, so the .NET {pinMajor} SDK could not be selected.", dotnet);
                    }
                    tempGlobalJsonPath = globalJsonPath;
                    await File.WriteAllTextAsync(globalJsonPath, pinned, ct).ConfigureAwait(false);
                }
                else
                {
                    await File.WriteAllTextAsync(globalJsonPath, DotNetSdkPin.WithSdkPin(null, pinMajor)!, ct).ConfigureAwait(false);
                    if (isCustomSolution)
                        tempGlobalJsonPath = globalJsonPath;
                }
                var verRes = await _launcher.RunAsync(dotnet.ExecutablePath, ["--version"], TimeSpan.FromSeconds(15), ct, workDir).ConfigureAwait(false);
                if (verRes is { ExitCode: 0, TimedOut: false } && !string.IsNullOrWhiteSpace(verRes.StdOut))
                {
                    var v = verRes.StdOut.Trim().Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)[0].Trim();
                    actualSdkVersion = v;
                    if (int.TryParse(v.Split('.')[0], out var parsedMaj))
                        actualSdkMajor = parsedMaj;
                }
                else
                {
                    actualSdkMajor = pinMajor;
                }
                // Measuring another SDK and labelling it as the pinned one would make the comparison meaningless.
                if (actualSdkMajor != pinMajor)
                    return Failed(DeveloperLanguage.CSharp,
                        $"Could not run: dotnet chose SDK {actualSdkVersion} instead of the .NET {pinMajor} SDK in {workDir}. Install the .NET {pinMajor} SDK or check global.json there.", dotnet);
            }
            Log($"C# clean build benchmark ({pinId}) running on .NET SDK {actualSdkVersion} in {workDir}");

            var conditions = env.ReadConditions();
            var (comparable, condNotes) = DeveloperScoring.CheckComparability(conditions.OnBattery, conditions.PowerPlan, thermallyThrottling: false);
            var defender = await env.ReadDefenderAsync(ct).ConfigureAwait(false);
            var defenderActive = defender?.Active;
            var folderExcluded = defender is { ExclusionsReadable: true } d && d.Paths.Any(p => DefenderProbe.Covers(p, workDir));

            var totalSteps = !isCustomSolution && options.IncludeAntivirusComparison && machineTweaks is not null && env.IsAgentConnected ? 4 : 3;
            var step = 0;

            // 1. Restore (timed separately, excluded from build score)
            progress.ReportStep(++step, totalSteps, "Timing C# restore (kept separate from build score)…");
            var (restoreOk, restoreSecs, restoreFail) = await TimedCommandAsync(dotnet.ExecutablePath, ["restore", projectPath, "--ignore-failed-sources", "-v", "q"], options.EffectiveTimeout, ct, workDir).ConfigureAwait(false);
            if (!restoreOk)
                return FailCommand(DeveloperLanguage.CSharp, "dotnet restore", restoreFail, dotnet, sha256, restoreSecs);

            var hyperfine = !isCustomSolution && options.AllowHyperfine ? env.FindHyperfine() : null;
            var usedHyperfine = false;

            // 2. Cold clean builds (shut down build servers & disable node reuse / shared compilation so Before and After start equally cold)
            progress.ReportStep(++step, totalSteps, $"Running cold C# clean builds ({options.ColdRepeats} repeats)…");
            await ShutdownBuildServersAsync(dotnet.ExecutablePath, workDir, ct).ConfigureAwait(false);
            var (coldSamples, coldFail) = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, projectPath, workDir, options.ColdRepeats, warmups: 0, hyperfine, options.EffectiveTimeout, ct, isolateBuildServer: true, useDotnetClean: isCustomSolution).ConfigureAwait(false);
            if (coldFail is not null || coldSamples.Count == 0)
                return FailCommand(DeveloperLanguage.CSharp, "cold dotnet build", coldFail, dotnet, sha256, restoreSecs);
            if (hyperfine is not null) usedHyperfine = true;

            // 3. Warm clean builds (2 warmups discarded by default so VBCSCompiler/MSBuild nodes reach steady state; compiler outputs deleted before EVERY repeat)
            progress.ReportStep(++step, totalSteps, $"Running warm C# clean builds ({options.WarmRepeats} repeats)…");
            var (warmSamples, warmFail) = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, projectPath, workDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct, isolateBuildServer: false, useDotnetClean: isCustomSolution).ConfigureAwait(false);
            if (warmFail is not null || warmSamples.Count == 0)
                return FailCommand(DeveloperLanguage.CSharp, "warm dotnet build", warmFail, dotnet, sha256, restoreSecs);

            // 4. Optional approval-gated Antivirus comparison (temporary exclusion through Agent, then removed in finally)
            IReadOnlyList<double>? warmExcludedSamples = null;
            double? warmExcludedMedian = null;
            if (!isCustomSolution && options.IncludeAntivirusComparison && machineTweaks is not null && env.IsAgentConnected)
            {
                progress.ReportStep(++step, totalSteps, $"Running warm C# clean builds with temporary Defender exclusion ({options.WarmRepeats} repeats)…");
                var (added, _) = await machineTweaks.AddTempBuildDefenderExclusionAsync(workDir, ct).ConfigureAwait(false);
                if (added)
                {
                    tempExclusionAdded = true;
                    var (excluded, excludedFail) = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, projectPath, workDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false);
                    if (excludedFail is null && excluded.Count > 0)
                    {
                        warmExcludedSamples = excluded;
                        warmExcludedMedian = DeveloperScoring.Median(excluded);
                    }
                    else
                        Log((excludedFail ?? CommandFailure.Empty).Format("warm dotnet build with temporary exclusion"));
                }
            }

            var coldMedian = DeveloperScoring.Median(coldSamples);
            var warmMedian = DeveloperScoring.Median(warmSamples);
            var (cpuName, coreCount) = env.ReadCpuInfo();
            var cpuClass = DeveloperScoring.ClassifyCpu(cpuName, coreCount);
            var baseline = isCustomSolution ? null : _baselines.FindUsable(cpuClass, DeveloperLanguage.CSharp, pinId, actualSdkMajor);
            var score = comparable ? DeveloperScoring.ComputeScore(warmMedian, baseline) : null;
            var band = DeveloperScoring.EvaluateBand(warmMedian, baseline, comparable);

            var result = new DeveloperBuildResult(
                DeveloperLanguage.CSharp,
                pinId,
                sha256,
                actualSdkVersion,
                actualSdkMajor,
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

            // Append anonymous sample beside benchmarks.json (built-in pin only; never log custom solution names/samples)
            if (!isCustomSolution)
            {
                sampleStore?.Append(new DeveloperBenchmarkSample(
                    DeveloperLanguage.CSharp,
                    pinId,
                    sha256,
                    actualSdkVersion,
                    actualSdkMajor,
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
            }

            Log($"C# clean build ({pinId}) done: cold={coldMedian:0.00}s warm={warmMedian:0.00}s restore={restoreSecs:0.00}s");
            return result;
        }
        finally
        {
            if (tempGlobalJsonPath is not null)
            {
                try
                {
                    if (originalGlobalJson is not null)
                        File.WriteAllText(tempGlobalJsonPath, originalGlobalJson);
                    else if (File.Exists(tempGlobalJsonPath))
                        File.Delete(tempGlobalJsonPath);
                }
                catch (Exception ex) { Log("Failed to restore global.json: " + ex.Message); }
            }
            if (tempExclusionAdded && machineTweaks is not null)
            {
                if (!await RemoveDefenderExclusionAsync(workDir).ConfigureAwait(false)
                    && !await RemoveDefenderExclusionAsync(workDir).ConfigureAwait(false))
                    throw new BenchmarkCleanupException();
            }
            if (!isCustomSolution)
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
        if (DeveloperCSharpPin.UnsupportedSdkReason(dotnet.Version, dotnet.MajorVersion) is { } tooOld)
            return new(false, DeveloperCSharpPin.PinId, "", Note: tooOld);

        var tempRoot = tempRootOverride ?? Path.GetTempPath();
        var ntfsDir = Path.Combine(tempRoot, $"{DevDriveRules.BuildTempPrefix}ntfs-{Guid.NewGuid():N}");
        string? vhdxPath = null;
        string? devDriveBuildDir = null;
        var tempExclusionAdded = false;
        var devDriveExclusionAdded = false;
        var includeAv = options.IncludeAntivirusComparison && env.IsAgentConnected;
        var totalSteps = includeAv ? 9 : 7;
        var step = 0;

        try
        {
            // 1. NTFS pass first (order: NTFS, [optional NTFS+AV exclusion,] Dev Drive, [optional Dev Drive+AV exclusion])
            progress.ReportStep(++step, totalSteps, "Preparing pinned C# sources on NTFS…");
            var (ntfsProj, sha256) = DeveloperCSharpPin.Materialize(ntfsDir, dotnet.MajorVersion!.Value);
            var (rOk, _, rFail) = await TimedCommandAsync(dotnet.ExecutablePath, ["restore", ntfsProj, "--ignore-failed-sources", "-v", "q"], options.EffectiveTimeout, ct, ntfsDir).ConfigureAwait(false);
            if (!rOk)
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: (rFail ?? CommandFailure.Empty).Format("NTFS dotnet restore"));

            var hyperfine = options.AllowHyperfine ? env.FindHyperfine() : null;
            progress.ReportStep(++step, totalSteps, $"Timing cold C# clean builds on NTFS ({options.ColdRepeats} repeats)…");
            await ShutdownBuildServersAsync(dotnet.ExecutablePath, ntfsDir, ct).ConfigureAwait(false);
            var (ntfsColdSamples, ntfsColdFail) = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ntfsProj, ntfsDir, options.ColdRepeats, 0, hyperfine, options.EffectiveTimeout, ct, isolateBuildServer: true).ConfigureAwait(false);
            progress.ReportStep(++step, totalSteps, $"Timing warm C# clean builds on NTFS ({options.WarmRepeats} repeats)…");
            var (ntfsWarmSamples, ntfsWarmFail) = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ntfsProj, ntfsDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct, isolateBuildServer: false).ConfigureAwait(false);
            var ntfsCold = DeveloperScoring.Median(ntfsColdSamples);
            var ntfsWarm = DeveloperScoring.Median(ntfsWarmSamples);
            if (ntfsColdFail is not null || ntfsWarmFail is not null || ntfsCold is null || ntfsWarm is null)
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: (ntfsColdFail ?? ntfsWarmFail ?? CommandFailure.Empty).Format("NTFS dotnet build"));

            // Optional NTFS + temporary Defender exclusion pass (same NTFS folder before Dev Drive)
            double? ntfsExcludedWarm = null;
            if (includeAv)
            {
                progress.ReportStep(++step, totalSteps, $"Timing warm C# builds on NTFS with Defender exclusion ({options.WarmRepeats} repeats)…");
                var (added, _) = await machineTweaks.AddTempBuildDefenderExclusionAsync(ntfsDir, ct).ConfigureAwait(false);
                if (added)
                {
                    tempExclusionAdded = true;
                    try
                    {
                        var (exclSamples, exclFail) = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ntfsProj, ntfsDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false);
                        if (exclFail is null && exclSamples.Count > 0)
                            ntfsExcludedWarm = DeveloperScoring.Median(exclSamples);
                        else
                            Log((exclFail ?? CommandFailure.Empty).Format("NTFS warm dotnet build with temporary exclusion"));
                    }
                    finally
                    {
                        tempExclusionAdded = !await RemoveDefenderExclusionAsync(ntfsDir).ConfigureAwait(false);
                        if (tempExclusionAdded)
                            throw new BenchmarkCleanupException("The comparison stopped when temporary Defender exclusion cleanup failed. See the Agent logs for the cleanup retry.");
                    }
                }
            }

            // 2. Ask Agent to create & mount temporary ~50 GB Dev Drive VHDX
            progress.ReportStep(++step, totalSteps, "Creating temporary 50 GB Dev Drive VHDX through Agent…");
            var mount = await machineTweaks.CreateTempDevDriveAsync(DevDriveRules.DefaultSizeGb, env.ReadCurrentUserSid(), ct).ConfigureAwait(false);
            if (!mount.Ok || string.IsNullOrWhiteSpace(mount.VhdxPath) || string.IsNullOrWhiteSpace(mount.BuildFolder))
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: mount.Error ?? "Could not create temporary Dev Drive.");

            vhdxPath = mount.VhdxPath;
            devDriveBuildDir = Path.Combine(mount.BuildFolder, $"{DevDriveRules.BuildTempPrefix}{Guid.NewGuid():N}");

            // Check Defender performance mode on the mounted Dev Drive
            var devDriveStatus = await env.QueryDevDriveAsync(mount.DriveLetter, ct).ConfigureAwait(false);

            // 3. Dev Drive pass
            progress.ReportStep(++step, totalSteps, "Preparing pinned C# sources on temporary Dev Drive…");
            var (ddProj, _) = DeveloperCSharpPin.Materialize(devDriveBuildDir, dotnet.MajorVersion!.Value);
            var (ddRestoreOk, _, ddRestoreFail) = await TimedCommandAsync(dotnet.ExecutablePath, ["restore", ddProj, "--ignore-failed-sources", "-v", "q"], options.EffectiveTimeout, ct, devDriveBuildDir).ConfigureAwait(false);
            if (!ddRestoreOk)
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: (ddRestoreFail ?? CommandFailure.Empty).Format("Dev Drive dotnet restore"));

            progress.ReportStep(++step, totalSteps, $"Timing cold C# clean builds on Dev Drive ({options.ColdRepeats} repeats)…");
            await ShutdownBuildServersAsync(dotnet.ExecutablePath, devDriveBuildDir, ct).ConfigureAwait(false);
            var (ddColdSamples, ddColdFail) = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ddProj, devDriveBuildDir, options.ColdRepeats, 0, hyperfine, options.EffectiveTimeout, ct, isolateBuildServer: true).ConfigureAwait(false);
            progress.ReportStep(++step, totalSteps, $"Timing warm C# clean builds on Dev Drive ({options.WarmRepeats} repeats)…");
            var (ddWarmSamples, ddWarmFail) = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ddProj, devDriveBuildDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct, isolateBuildServer: false).ConfigureAwait(false);
            var ddCold = DeveloperScoring.Median(ddColdSamples);
            var ddWarm = DeveloperScoring.Median(ddWarmSamples);
            if (ddColdFail is not null || ddWarmFail is not null || ddCold is null || ddWarm is null)
                return new(false, DeveloperCSharpPin.PinId, sha256, Note: (ddColdFail ?? ddWarmFail ?? CommandFailure.Empty).Format("Dev Drive dotnet build"));

            // 4. Optional Dev Drive + temporary Defender exclusion pass
            double? devDriveExcludedWarm = null;
            if (includeAv)
            {
                progress.ReportStep(++step, totalSteps, $"Timing warm C# builds on Dev Drive with Defender exclusion ({options.WarmRepeats} repeats)…");
                var (ddAdded, _) = await machineTweaks.AddTempBuildDefenderExclusionAsync(devDriveBuildDir, ct).ConfigureAwait(false);
                if (ddAdded)
                {
                    devDriveExclusionAdded = true;
                    try
                    {
                        var (ddExclSamples, ddExclFail) = await MeasureCleanBuildsAsync(dotnet.ExecutablePath, ddProj, devDriveBuildDir, options.WarmRepeats, options.WarmWarmups, hyperfine, options.EffectiveTimeout, ct).ConfigureAwait(false);
                        if (ddExclFail is null && ddExclSamples.Count > 0)
                            devDriveExcludedWarm = DeveloperScoring.Median(ddExclSamples);
                        else
                            Log((ddExclFail ?? CommandFailure.Empty).Format("Dev Drive warm dotnet build with temporary exclusion"));
                    }
                    finally
                    {
                        devDriveExclusionAdded = !await RemoveDefenderExclusionAsync(devDriveBuildDir).ConfigureAwait(false);
                        if (devDriveExclusionAdded)
                            throw new BenchmarkCleanupException("The comparison stopped when temporary Defender exclusion cleanup failed. See the Agent logs for the cleanup retry.");
                    }
                }
            }

            return new(
                Succeeded: true,
                PinId: DeveloperCSharpPin.PinId,
                PinSha256: sha256,
                Order: includeAv ? "NTFS, NTFS + AV exclusion, Dev Drive, then Dev Drive + AV exclusion" : "NTFS, then Dev Drive",
                NtfsColdMedianSeconds: ntfsCold,
                NtfsWarmMedianSeconds: ntfsWarm,
                DevDriveColdMedianSeconds: ddCold,
                DevDriveWarmMedianSeconds: ddWarm,
                DefenderPerformanceModeActive: devDriveStatus.DefenderPerformanceModeActive,
                CompletedAtUtc: DateTimeOffset.UtcNow,
                NtfsExcludedWarmMedianSeconds: ntfsExcludedWarm,
                DevDriveExcludedWarmMedianSeconds: devDriveExcludedWarm);
        }
        finally
        {
            if (tempExclusionAdded)
                tempExclusionAdded = !await RemoveDefenderExclusionAsync(ntfsDir).ConfigureAwait(false);
            if (devDriveExclusionAdded && devDriveBuildDir is not null)
                devDriveExclusionAdded = !await RemoveDefenderExclusionAsync(devDriveBuildDir).ConfigureAwait(false);
            TryDeleteDirectory(ntfsDir);
            if (devDriveBuildDir is not null) TryDeleteDirectory(devDriveBuildDir);
            if (vhdxPath is not null)
            {
                try { await machineTweaks.RemoveTempDevDriveAsync(vhdxPath, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception ex) { Log("Failed to remove temporary Dev Drive VHDX: " + ex.Message); }
            }
            if (tempExclusionAdded || devDriveExclusionAdded)
                throw new BenchmarkCleanupException();
        }
    }

    private async Task<bool> RemoveDefenderExclusionAsync(string folder)
    {
        try
        {
            return await machineTweaks!.RemoveTempBuildDefenderExclusionAsync(folder, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log("Failed to remove temporary Defender exclusion: " + ex.Message);
            return false;
        }
    }

    private async Task ShutdownBuildServersAsync(string dotnetExe, string workDir, CancellationToken ct)
    {
        try
        {
            await _launcher.RunAsync(dotnetExe, ["build-server", "shutdown"], TimeSpan.FromSeconds(10), ct, workDir).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log("build-server shutdown skipped: " + ex.Message);
        }
    }

    private async Task<(IReadOnlyList<double> Samples, CommandFailure? Failure)> MeasureCleanBuildsAsync(
        string dotnetExe,
        string projectPath,
        string workDir,
        int repeats,
        int warmups,
        string? hyperfineExe,
        TimeSpan timeout,
        CancellationToken ct,
        bool isolateBuildServer = false,
        bool useDotnetClean = false)
    {
        if (hyperfineExe is not null && !useDotnetClean)
        {
            var hfSamples = await TryMeasureWithHyperfineAsync(hyperfineExe, dotnetExe, projectPath, workDir, repeats, warmups, timeout, ct, isolateBuildServer).ConfigureAwait(false);
            if (hfSamples is { Count: > 0 }) return (hfSamples, null);
        }

        // In-app loop matching hyperfine's protocol: delete compiler outputs before every repeat so the compiler
        // does full work, but keep the NuGet restore assets. `dotnet build --no-restore` fails with NETSDK1004
        // when project.assets.json (written by the separately timed restore) has been deleted.
        string[] buildArgs = isolateBuildServer
            ? ["build", projectPath, "-c", "Release", "--no-restore", "-nr:false", "-p:UseSharedCompilation=false", "-v", "q"]
            : ["build", projectPath, "-c", "Release", "--no-restore", "-v", "q"];

        var samples = new List<double>();
        for (var i = 0; i < warmups + Math.Max(1, repeats); i++)
        {
            ct.ThrowIfCancellationRequested();
            if (useDotnetClean)
                await _launcher.RunAsync(dotnetExe, ["clean", projectPath, "-c", "Release", "-v", "q"], timeout, ct, workDir).ConfigureAwait(false);
            else
                CleanBuildOutputs(workDir);
            var (ok, seconds, failure) = await TimedCommandAsync(dotnetExe, buildArgs, timeout, ct, workDir).ConfigureAwait(false);
            if (!ok) return ([], failure ?? CommandFailure.Empty);
            if (i >= warmups)
                samples.Add(Math.Round(seconds, 3));
        }
        return (samples, null);
    }

    private async Task<IReadOnlyList<double>?> TryMeasureWithHyperfineAsync(
        string hyperfineExe,
        string dotnetExe,
        string projectPath,
        string workDir,
        int repeats,
        int warmups,
        TimeSpan timeout,
        CancellationToken ct,
        bool isolateBuildServer = false)
    {
        var jsonOut = Path.Combine(workDir, $"hf-{Guid.NewGuid():N}.json");
        try
        {
            var prepare = CleanPrepareCommand(workDir);
            var extraFlags = isolateBuildServer ? " -nr:false -p:UseSharedCompilation=false" : "";
            var cmd = $"\"{dotnetExe}\" build \"{projectPath}\" -c Release --no-restore{extraFlags} -v q";
            var args = new List<string>
            {
                "--runs", Math.Max(1, repeats).ToString(CultureInfo.InvariantCulture),
                "--warmup", Math.Max(0, warmups).ToString(CultureInfo.InvariantCulture),
                "--prepare", prepare,
                "--export-json", jsonOut,
                cmd,
            };
            var totalTimeout = TimeSpan.FromSeconds(timeout.TotalSeconds * (repeats + warmups + 1));
            var r = await _launcher.RunAsync(hyperfineExe, args, totalTimeout, ct, workDir).ConfigureAwait(false);
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

    private async Task<(bool Ok, double Seconds, CommandFailure? Failure)> TimedCommandAsync(
        string exe, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken ct, string? workingDirectory)
    {
        var sw = Stopwatch.StartNew();
        var r = await _launcher.RunAsync(exe, args, timeout, ct, workingDirectory).ConfigureAwait(false);
        sw.Stop();
        var seconds = Math.Max(0.001, Math.Round(sw.Elapsed.TotalSeconds, 3));
        if (r.ExitCode == 0 && !r.TimedOut) return (true, seconds, null);
        return (false, seconds, new CommandFailure(r.ExitCode, r.TimedOut, r.StdOut, r.StdErr, workingDirectory));
    }

    /// <summary>
    /// True for the files <c>dotnet restore</c> writes into <c>obj</c> that <c>dotnet build --no-restore</c> still needs.
    /// </summary>
    public static bool IsNuGetRestoreAsset(string fileName)
    {
        if (fileName.Equals("project.assets.json", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.Equals("project.nuget.cache", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.EndsWith(".nuget.g.props", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.EndsWith(".nuget.g.targets", StringComparison.OrdinalIgnoreCase)) return true;
        if (fileName.EndsWith(".nuget.dgspec.json", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>
    /// Command hyperfine runs before each repeat. Deletes <c>bin</c> and compiler outputs under <c>obj</c>,
    /// and leaves the NuGet restore assets in place. Windows PowerShell's <c>-Include</c> does not match
    /// <c>bin</c>/<c>obj</c> unless the path itself contains a wildcard, so this uses <c>-Filter</c>.
    /// </summary>
    public static string CleanPrepareCommand(string workDir)
    {
        if (OperatingSystem.IsWindows())
        {
            var path = workDir.Replace("'", "''");
            return "powershell -NoProfile -Command \""
                + "$root='" + path + "'; "
                + "$bins=@(Get-ChildItem -LiteralPath $root -Recurse -Directory -Filter bin -ErrorAction SilentlyContinue); "
                + "foreach($b in $bins){ Remove-Item -LiteralPath $b.FullName -Recurse -Force -ErrorAction SilentlyContinue }; "
                + "$objs=@(Get-ChildItem -LiteralPath $root -Recurse -Directory -Filter obj -ErrorAction SilentlyContinue); "
                + "foreach($o in $objs){ Get-ChildItem -LiteralPath $o.FullName -Force -ErrorAction SilentlyContinue | "
                + "Where-Object { $n=$_.Name; $n -ne 'project.assets.json' -and $n -ne 'project.nuget.cache' -and $n -notlike '*.nuget.g.props' -and $n -notlike '*.nuget.g.targets' -and $n -notlike '*.nuget.dgspec.json' } | "
                + "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }\"";
        }

        var quoted = workDir.Replace("'", "'\\''");
        return "find '" + quoted + "' -type d -name bin -prune -exec rm -rf {} + ; "
            + "find '" + quoted + "' -type d -name obj -exec sh -c '"
            + "for p in \"$1\"/*; do [ -e \"$p\" ] || continue; b=$(basename \"$p\"); "
            + "case \"$b\" in project.assets.json|project.nuget.cache|*.nuget.g.props|*.nuget.g.targets|*.nuget.dgspec.json) ;; *) rm -rf \"$p\" ;; esac; "
            + "done' _ {} \\;";
    }

    /// <summary>
    /// Deletes compiler outputs under <paramref name="root"/> before each clean build repeat.
    /// <c>bin</c> is removed entirely. Under <c>obj</c>, compile artifacts go and NuGet restore assets stay,
    /// so the timed <c>dotnet build --no-restore</c> recompiles without repeating restore.
    /// </summary>
    public static void CleanBuildOutputs(string root)
    {
        if (!Directory.Exists(root)) return;
        List<string> dirs;
        try { dirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories).ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }

        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;
            if (Path.GetFileName(dir).Equals("bin", StringComparison.OrdinalIgnoreCase))
                TryDeleteDirectory(dir);
        }

        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;
            if (!Path.GetFileName(dir).Equals("obj", StringComparison.OrdinalIgnoreCase)) continue;
            CleanObjKeepRestoreAssets(dir);
        }
    }

    private static void CleanObjKeepRestoreAssets(string objDir)
    {
        string[] entries;
        try { entries = Directory.GetFileSystemEntries(objDir); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }

        foreach (var entry in entries)
        {
            if (IsNuGetRestoreAsset(Path.GetFileName(entry))) continue;
            try
            {
                if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
                else File.Delete(entry);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// Failure text for the Benchmark page and the Admin export: the process exit code (or a timeout)
    /// plus the first compiler/restore error lines, or the tail of the output when it named no error.
    /// </summary>
    public static string FormatToolFailure(string what, int exitCode, bool timedOut, string? stdOut, string? stdErr, string? workDir = null)
    {
        var how = timedOut
            ? "timed out"
            : "exit " + exitCode.ToString(CultureInfo.InvariantCulture);
        var detail = ScrubPaths(SummarizeToolOutput(stdOut, stdErr), workDir, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        return detail is null
            ? $"Could not run: {what} failed ({how})."
            : $"Could not run: {what} failed ({how}). {detail}";
    }

    /// <summary>First error lines from a dotnet/MSBuild log, or the last few lines when none are marked as errors.</summary>
    public static string? SummarizeToolOutput(string? stdOut, string? stdErr)
    {
        var lines = ReadOutputLines(stdErr).Concat(ReadOutputLines(stdOut)).ToList();
        var picked = lines.Where(IsToolErrorLine).Distinct(StringComparer.Ordinal).Take(4).ToList();
        if (picked.Count == 0)
            picked = lines.TakeLast(4).Distinct(StringComparer.Ordinal).ToList();
        if (picked.Count == 0) return null;
        var text = string.Join(" | ", picked.Select(TrimDetailLine));
        const int max = 700;
        if (text.Length <= max) return text;
        return text[..(max - 1)].TrimEnd() + "…";
    }

    /// <summary>A compiler, NuGet, or MSBuild error line (<c>error CS…</c>, <c>: error NETSDK…</c>), not the trailing "N Error(s)" summary.</summary>
    public static bool IsToolErrorLine(string line)
    {
        var span = line.AsSpan().Trim();
        if (span.Length == 0) return false;
        if (span.Contains(": error", StringComparison.OrdinalIgnoreCase)) return true;
        return span.StartsWith("error", StringComparison.OrdinalIgnoreCase)
            && (span.Length == 5 || span[5] is ' ' or ':' or '\t');
    }

    private static IEnumerable<string> ReadOutputLines(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) yield break;
        foreach (var raw in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            if (line.Length > 0) yield return line;
        }
    }

    private static string TrimDetailLine(string line)
    {
        const int max = 240;
        var trimmed = line.Trim();
        return trimmed.Length <= max ? trimmed : trimmed[..(max - 1)].TrimEnd() + "…";
    }

    /// <summary>
    /// Keeps the Windows user name out of the note shown on the page and sent in the Admin export.
    /// dotnet error lines name full paths such as <c>C:\Users\name\AppData\Local\Temp\rpcd-build-…\BenchApp\Program.cs</c>:
    /// the build folder becomes <c>&lt;build folder&gt;</c> and the rest of the profile becomes <c>%USERPROFILE%</c>.
    /// </summary>
    public static string? ScrubPaths(string? text, string? workDir, string? userProfile)
    {
        if (string.IsNullOrEmpty(text)) return text;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        foreach (var (path, label) in new[] { (workDir, "<build folder>"), (userProfile, "%USERPROFILE%") })
        {
            var trimmed = path?.TrimEnd('\\', '/');
            if (string.IsNullOrEmpty(trimmed) || trimmed.Length < 3) continue;
            text = text.Replace(trimmed, label, comparison);
        }
        return MaskUsersFolderNames(text);
    }

    /// <summary>
    /// Replaces the folder after any <c>\Users\</c> with <c>&lt;user&gt;</c>. Catches profile paths the exact
    /// replacement misses, such as the 8.3 short form (<c>C:\Users\BUDCR~1\…</c>) that the temp folder can use.
    /// </summary>
    private static string MaskUsersFolderNames(string text)
    {
        const string marker = "\\Users\\";
        var sb = new StringBuilder(text.Length);
        var i = 0;
        while (i < text.Length)
        {
            var hit = text.IndexOf(marker, i, StringComparison.OrdinalIgnoreCase);
            if (hit < 0) { sb.Append(text, i, text.Length - i); break; }
            var nameStart = hit + marker.Length;
            var nameEnd = nameStart;
            while (nameEnd < text.Length && text[nameEnd] is not ('\\' or '/' or '\'' or '"' or ':' or '|'))
                nameEnd++;
            sb.Append(text, i, nameStart - i);
            if (nameEnd > nameStart) sb.Append("<user>");
            i = nameEnd;
        }
        return sb.ToString();
    }

    private readonly record struct CommandFailure(int ExitCode, bool TimedOut, string? StdOut, string? StdErr, string? WorkDir = null)
    {
        public static CommandFailure Empty { get; } = new(-1, false, null, null);
        public string Format(string what) => FormatToolFailure(what, ExitCode, TimedOut, StdOut, StdErr, WorkDir);
    }

    private DeveloperBuildResult FailCommand(DeveloperLanguage lang, string what, CommandFailure? failure, DetectedToolchain? tc, string sha256, double? restoreSecs)
    {
        var fail = failure ?? CommandFailure.Empty;
        var note = fail.Format(what);
        Log(note);
        return Failed(lang, note, tc, sha256, restoreSecs, fail.ExitCode);
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

    private static DeveloperBuildResult Failed(DeveloperLanguage lang, string note, DetectedToolchain? tc = null, string sha256 = "", double? restoreSecs = null, int? toolExitCode = null) =>
        new(lang, DeveloperCSharpPin.PinId, sha256, tc?.Version, tc?.MajorVersion, restoreSecs, null, [], null, [], Note: note, ToolExitCode: toolExitCode);
}

/// <summary>global.json text that makes <c>dotnet</c> pick a given SDK major for a benchmark build.</summary>
public static class DotNetSdkPin
{
    /// <summary>
    /// <paramref name="existing"/> with its <c>sdk</c> section replaced by <c>{major}.0.100</c> and <c>latestFeature</c>, keeping every
    /// other section (such as <c>test</c>). A fresh file when <paramref name="existing"/> is null. Null when the text is not a JSON object.
    /// </summary>
    public static string? WithSdkPin(string? existing, int major)
    {
        System.Text.Json.Nodes.JsonObject root;
        if (string.IsNullOrWhiteSpace(existing))
            root = [];
        else
        {
            try
            {
                if (System.Text.Json.Nodes.JsonNode.Parse(existing, documentOptions: new JsonDocumentOptions
                    { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }) is not System.Text.Json.Nodes.JsonObject parsed)
                    return null;
                root = parsed;
            }
            catch (JsonException)
            {
                return null;
            }
        }
        root["sdk"] = new System.Text.Json.Nodes.JsonObject
        {
            ["version"] = string.Create(CultureInfo.InvariantCulture, $"{major}.0.100"),
            ["rollForward"] = "latestFeature",
        };
        return root.ToJsonString();
    }
}
