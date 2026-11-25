using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>Parsed output of <c>fsutil devdrv query</c>.</summary>
public sealed record DevDriveVolumeStatus(
    bool SupportedByOs,
    bool IsDevDrive,
    bool PolicyEnabled,
    bool? DefenderPerformanceModeActive = null,
    string? RawSummary = null);

/// <summary>
/// Read-only detection of installed developer toolchains (<c>dotnet</c>, <c>cargo</c>, <c>go</c>, <c>node</c>/<c>npm</c>/<c>tsc</c>,
/// <c>python</c>, MSBuild/CMake) and <c>hyperfine</c>. Never downloads or installs anything.
/// </summary>
public sealed class DeveloperToolchainDetector(
    IProcessLauncher? launcher = null,
    Func<string, bool>? fileExists = null,
    Func<string, string?>? getEnv = null,
    bool? isWindows = null)
{
    private readonly IProcessLauncher _launcher = launcher ?? new SystemProcessLauncher();
    private readonly Func<string, bool> _fileExists = fileExists ?? File.Exists;
    private readonly Func<string, string?> _getEnv = getEnv ?? Environment.GetEnvironmentVariable;
    private readonly bool _isWindows = isWindows ?? OperatingSystem.IsWindows();

    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Detects all installed toolchains. Absent languages are omitted (never returned as empty rows).</summary>
    public async Task<IReadOnlyList<DetectedToolchain>> DetectAllAsync(CancellationToken ct = default)
    {
        var found = new List<DetectedToolchain>();

        if (await TryDetectDotnetAsync(ct).ConfigureAwait(false) is { } dotnet) found.Add(dotnet);
        if (await TryDetectRustAsync(ct).ConfigureAwait(false) is { } rust) found.Add(rust);
        if (await TryDetectGoAsync(ct).ConfigureAwait(false) is { } go) found.Add(go);
        if (await TryDetectNodeTypeScriptAsync(ct).ConfigureAwait(false) is { } ts) found.Add(ts);
        if (await TryDetectPythonAsync(ct).ConfigureAwait(false) is { } py) found.Add(py);
        if (await TryDetectCppAsync(ct).ConfigureAwait(false) is { } cpp) found.Add(cpp);

        return found;
    }

    /// <summary>Finds <c>hyperfine</c> on PATH when present, or null.</summary>
    public string? FindHyperfine() => ResolveExecutable(_isWindows ? "hyperfine.exe" : "hyperfine", []);

    public async Task<DetectedToolchain?> TryDetectDotnetAsync(CancellationToken ct = default)
    {
        var exe = ResolveExecutable(_isWindows ? "dotnet.exe" : "dotnet", _isWindows
            ? [@"C:\Program Files\dotnet\dotnet.exe", @"C:\Program Files (x86)\dotnet\dotnet.exe"]
            : ["/usr/bin/dotnet", "/usr/local/bin/dotnet"]);
        if (exe is null) return null;
        var ver = await ReadVersionAsync(exe, ["--version"], ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(ver)) return null;
        return new(DeveloperLanguage.CSharp, ".NET SDK (C#)", exe, ver, DeveloperScoring.ParseMajorVersion(ver));
    }

    /// <summary>Returns distinct installed .NET SDK major versions from <c>dotnet --list-sdks</c> (sorted ascending).</summary>
    public async Task<IReadOnlyList<int>> DetectInstalledDotNetSdkMajorsAsync(CancellationToken ct = default)
    {
        var exe = ResolveExecutable(_isWindows ? "dotnet.exe" : "dotnet", _isWindows
            ? [@"C:\Program Files\dotnet\dotnet.exe", @"C:\Program Files (x86)\dotnet\dotnet.exe"]
            : ["/usr/bin/dotnet", "/usr/local/bin/dotnet"]);
        if (exe is null) return [];
        try
        {
            var r = await _launcher.RunAsync(exe, ["--list-sdks"], ProbeTimeout, ct).ConfigureAwait(false);
            return r.ExitCode == 0 ? ParseInstalledDotNetSdkMajors(r.StdOut) : [];
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return [];
        }
    }

    public static IReadOnlyList<int> ParseInstalledDotNetSdkMajors(string? listSdksOutput)
    {
        if (string.IsNullOrWhiteSpace(listSdksOutput)) return [];
        var majors = new SortedSet<int>();
        foreach (var line in listSdksOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            var space = trimmed.IndexOf(' ');
            var ver = space > 0 ? trimmed[..space] : trimmed;
            if (DeveloperScoring.ParseMajorVersion(ver) is > 0 and var m)
                majors.Add(m);
        }
        return majors.ToList();
    }

    public async Task<DetectedToolchain?> TryDetectRustAsync(CancellationToken ct = default)
    {
        var profile = _getEnv("USERPROFILE") ?? _getEnv("HOME") ?? "";
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(profile))
            candidates.Add(Path.Combine(profile, ".cargo", "bin", _isWindows ? "cargo.exe" : "cargo"));
        var exe = ResolveExecutable(_isWindows ? "cargo.exe" : "cargo", candidates);
        if (exe is null) return null;
        var ver = await ReadVersionAsync(exe, ["--version"], ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(ver)) return null;
        return new(DeveloperLanguage.Rust, "Rust (cargo)", exe, ver, DeveloperScoring.ParseMajorVersion(ver));
    }

    public async Task<DetectedToolchain?> TryDetectGoAsync(CancellationToken ct = default)
    {
        var exe = ResolveExecutable(_isWindows ? "go.exe" : "go", _isWindows
            ? [@"C:\Program Files\Go\bin\go.exe"]
            : ["/usr/local/go/bin/go", "/usr/bin/go"]);
        if (exe is null) return null;
        var ver = await ReadVersionAsync(exe, ["version"], ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(ver)) return null;
        return new(DeveloperLanguage.Go, "Go", exe, ver, DeveloperScoring.ParseMajorVersion(ver));
    }

    public async Task<DetectedToolchain?> TryDetectNodeTypeScriptAsync(CancellationToken ct = default)
    {
        var exe = ResolveExecutable(_isWindows ? "node.exe" : "node", _isWindows
            ? [@"C:\Program Files\nodejs\node.exe"]
            : ["/usr/local/bin/node", "/usr/bin/node"]);
        if (exe is null) return null;
        var ver = await ReadVersionAsync(exe, ["--version"], ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(ver)) return null;
        var npm = ResolveExecutable(_isWindows ? "npm.cmd" : "npm", _isWindows ? [@"C:\Program Files\nodejs\npm.cmd"] : []);
        return new(DeveloperLanguage.TypeScript, "Node.js / TypeScript", exe, ver, DeveloperScoring.ParseMajorVersion(ver), npm);
    }

    public async Task<DetectedToolchain?> TryDetectPythonAsync(CancellationToken ct = default)
    {
        var localApp = _getEnv("LOCALAPPDATA") ?? "";
        var candidates = new List<string>();
        if (_isWindows && !string.IsNullOrWhiteSpace(localApp))
        {
            foreach (var minor in new[] { "313", "312", "311", "310" })
                candidates.Add(Path.Combine(localApp, "Programs", "Python", $"Python{minor}", "python.exe"));
        }
        var exe = ResolveExecutable(_isWindows ? "python.exe" : "python3", candidates)
                  ?? (_isWindows ? null : ResolveExecutable("python", []));
        if (exe is null) return null;
        var ver = await ReadVersionAsync(exe, ["--version"], ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(ver) || !ver.Contains("Python", StringComparison.OrdinalIgnoreCase)) return null;
        return new(DeveloperLanguage.Python, "Python", exe, ver, DeveloperScoring.ParseMajorVersion(ver));
    }

    public async Task<DetectedToolchain?> TryDetectCppAsync(CancellationToken ct = default)
    {
        var cmake = ResolveExecutable(_isWindows ? "cmake.exe" : "cmake", _isWindows
            ? [@"C:\Program Files\CMake\bin\cmake.exe"]
            : ["/usr/bin/cmake", "/usr/local/bin/cmake"]);
        if (cmake is not null)
        {
            var ver = await ReadVersionAsync(cmake, ["--version"], ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(ver))
                return new(DeveloperLanguage.Cpp, "C/C++ (CMake)", cmake, ver, DeveloperScoring.ParseMajorVersion(ver));
        }

        if (_isWindows)
        {
            var msbuildCandidates = new List<string>();
            foreach (var pf in new[] { @"C:\Program Files", @"C:\Program Files (x86)" })
            {
                foreach (var year in new[] { "2022", "18", "2019" })
                {
                    foreach (var ed in new[] { "Enterprise", "Professional", "Community", "BuildTools" })
                        msbuildCandidates.Add(Path.Combine(pf, "Microsoft Visual Studio", year, ed, "MSBuild", "Current", "Bin", "MSBuild.exe"));
                }
            }
            var msbuild = ResolveExecutable("MSBuild.exe", msbuildCandidates);
            if (msbuild is not null)
            {
                var ver = await ReadVersionAsync(msbuild, ["-version", "-nologo"], ct).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(ver))
                    return new(DeveloperLanguage.Cpp, "C/C++ (MSBuild)", msbuild, ver, DeveloperScoring.ParseMajorVersion(ver));
            }
        }

        return null;
    }

    private string? ResolveExecutable(string name, IEnumerable<string> fallbackPaths)
    {
        var pathEnv = _getEnv("PATH") ?? "";
        var sep = _isWindows ? ';' : ':';
        foreach (var rawDir in pathEnv.Split(sep, StringSplitOptions.RemoveEmptyEntries))
        {
            var dir = rawDir.Trim().Trim('"');
            if (dir.Length == 0) continue;
            var candidate = Path.Combine(dir, name);
            if (_fileExists(candidate)) return candidate;
        }

        foreach (var fallback in fallbackPaths)
        {
            if (_fileExists(fallback)) return fallback;
        }
        return null;
    }

    private async Task<string?> ReadVersionAsync(string exe, IReadOnlyList<string> args, CancellationToken ct)
    {
        try
        {
            var r = await _launcher.RunAsync(exe, args, ProbeTimeout, ct).ConfigureAwait(false);
            if (r.ExitCode != 0) return null;
            var text = string.IsNullOrWhiteSpace(r.StdOut) ? r.StdErr : r.StdOut;
            return FirstNonEmptyLine(text);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    private static string? FirstNonEmptyLine(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        foreach (var line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (trimmed.Length > 0) return trimmed;
        }
        return null;
    }

    /// <summary>Parses the output of <c>fsutil devdrv query [drive:]</c> on Windows 11.</summary>
    public static DevDriveVolumeStatus ParseFsutilDevDriveQuery(int exitCode, string? output, bool isWindows11Capable)
    {
        if (!isWindows11Capable)
            return new(false, false, false, null, "Dev Drive requires Windows 11 (build 22621.2338 or later).");

        var text = output ?? "";
        if (exitCode != 0 && text.Contains("invalid", StringComparison.OrdinalIgnoreCase))
            return new(false, false, false, null, "This version of Windows does not support Dev Drive.");

        var isDevDrive = text.Contains("is a developer volume", StringComparison.OrdinalIgnoreCase)
            && !text.Contains("is NOT a developer volume", StringComparison.OrdinalIgnoreCase);

        var policyDisabled = text.Contains("disabled by policy", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Dev Drive is not enabled", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Developer volumes are disabled", StringComparison.OrdinalIgnoreCase);

        bool? perfMode = null;
        if (text.Contains("Performance mode", StringComparison.OrdinalIgnoreCase)
            || text.Contains("trusted", StringComparison.OrdinalIgnoreCase))
        {
            perfMode = !text.Contains("untrusted", StringComparison.OrdinalIgnoreCase)
                && !text.Contains("disabled", StringComparison.OrdinalIgnoreCase);
        }

        return new(true, isDevDrive, !policyDisabled, perfMode, FirstNonEmptyLine(text));
    }

    /// <summary>Checks whether a Windows build/revision meets the Dev Drive minimum (22621.2338).</summary>
    public static bool IsWindows11DevDriveCapable(int build, int ubr) =>
        build > DeveloperScoring.MinWindows11DevDriveBuild
        || (build == DeveloperScoring.MinWindows11DevDriveBuild && ubr >= DeveloperScoring.MinWindows11DevDriveRevision);
}
