using System.Runtime.InteropServices;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One developer package cache definition. Only pure caches are on the write allowlist; tool homes like CARGO_HOME stay info-only.</summary>
public sealed record PackageCacheSpec(
    string EnvVar,
    string ToolName,
    DeveloperLanguage? Language,
    string Subfolder,
    bool PureCache,
    Func<string> DefaultPathResolver);

/// <summary>Observed state of one developer package cache on this PC.</summary>
public sealed record PackageCacheInfo(
    PackageCacheSpec Spec,
    string CurrentPath,
    bool FromEnvironmentVariable,
    bool OnDevDrive,
    long? SizeBytes);

/// <summary>Reads and writes allowlisted per-user environment variables in <c>HKCU\Environment</c> and broadcasts <c>WM_SETTINGCHANGE</c>.</summary>
public interface IUserEnvironmentStore
{
    string? Read(string name);
    void Write(string name, string value);
    void Delete(string name);
    void EnsureDirectory(string path);
}

public sealed class WindowsUserEnvironmentStore : IUserEnvironmentStore
{
    private const int HwndBroadcast = 0xFFFF;
    private const uint WmSettingChange = 0x001A;
    private const uint SmtoAbortIfHung = 0x0002;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);

    public string? Read(string name)
    {
        if (!OperatingSystem.IsWindows()) return Environment.GetEnvironmentVariable(name);
        using var key = Registry.CurrentUser.OpenSubKey("Environment", writable: false);
        return key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
    }

    public void Write(string name, string value)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("User environment variables require Windows.");
        using var key = Registry.CurrentUser.CreateSubKey("Environment", writable: true)
            ?? throw new InvalidOperationException("Couldn't open HKCU\\Environment.");
        key.SetValue(name, value, RegistryValueKind.String);
        BroadcastEnvironmentChange();
    }

    public void Delete(string name)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("User environment variables require Windows.");
        using var key = Registry.CurrentUser.OpenSubKey("Environment", writable: true);
        if (key?.GetValue(name) is not null)
        {
            key.DeleteValue(name, throwOnMissingValue: false);
            BroadcastEnvironmentChange();
        }
    }

    public void EnsureDirectory(string path) => Directory.CreateDirectory(path);

    private static void BroadcastEnvironmentChange()
    {
        try { SendMessageTimeout((IntPtr)HwndBroadcast, WmSettingChange, UIntPtr.Zero, "Environment", SmtoAbortIfHung, 2000, out _); }
        catch { }
    }
}

public static class DevDrivePackageCaches
{
    public const string LongPathsKey = @"SYSTEM\CurrentControlSet\Control\FileSystem";
    public const string LongPathsValueName = "LongPathsEnabled";

    private static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    /// <summary>Pure-cache user environment variables RPCD may redirect to a Dev Drive (and undo cleanly).</summary>
    public static readonly IReadOnlyList<PackageCacheSpec> WritableSpecs =
    [
        new("NUGET_PACKAGES", "NuGet (.NET)", DeveloperLanguage.CSharp, "nuget", PureCache: true,
            () => Path.Combine(UserProfile, ".nuget", "packages")),
        new("npm_config_cache", "npm (Node.js)", DeveloperLanguage.TypeScript, "npm", PureCache: true,
            () => Path.Combine(LocalAppData, "npm-cache")),
        new("PIP_CACHE_DIR", "pip (Python)", DeveloperLanguage.Python, "pip", PureCache: true,
            () => Path.Combine(LocalAppData, "pip", "Cache")),
        new("VCPKG_DEFAULT_BINARY_CACHE", "vcpkg (C++)", DeveloperLanguage.Cpp, "vcpkg", PureCache: true,
            () => Path.Combine(LocalAppData, "vcpkg", "archives")),
    ];

    /// <summary>Tool homes that contain binaries/config in addition to caches: shown as info ("move by hand") only, never written by RPCD.</summary>
    public static readonly IReadOnlyList<PackageCacheSpec> InfoOnlySpecs =
    [
        new("CARGO_HOME", "Cargo (Rust)", DeveloperLanguage.Rust, "cargo", PureCache: false,
            () => Path.Combine(UserProfile, ".cargo")),
        new("GRADLE_USER_HOME", "Gradle (Java)", null, "gradle", PureCache: false,
            () => Path.Combine(UserProfile, ".gradle")),
    ];

    public static IReadOnlyList<PackageCacheInfo> CollectCaches(
        IReadOnlyList<DetectedToolchain> toolchains,
        string? devDriveRoot,
        IUserEnvironmentStore? envStore = null,
        Func<string, long?>? measureDirectoryBytes = null,
        Func<string, bool>? directoryExists = null)
    {
        var store = envStore ?? new WindowsUserEnvironmentStore();
        var exists = directoryExists ?? Directory.Exists;
        var measure = measureDirectoryBytes ?? MeasureDirectoryBytesBounded;
        var langs = toolchains.Select(t => t.Language).ToHashSet();
        var results = new List<PackageCacheInfo>();

        foreach (var spec in WritableSpecs.Concat(InfoOnlySpecs))
        {
            var envVal = store.Read(spec.EnvVar);
            var hasEnv = !string.IsNullOrWhiteSpace(envVal);
            var defaultPath = spec.DefaultPathResolver();
            var detected = spec.Language is { } lang
                ? langs.Contains(lang)
                : hasEnv || exists(defaultPath);
            if (!detected) continue;

            var path = hasEnv ? envVal!.Trim() : defaultPath;
            var onDevDrive = IsPathOnDrive(path, devDriveRoot);
            long? size = exists(Environment.ExpandEnvironmentVariables(path)) ? measure(Environment.ExpandEnvironmentVariables(path)) : null;
            results.Add(new(spec, path, hasEnv, onDevDrive, size));
        }

        return results;
    }

    public static long? MeasureDirectoryBytesBounded(string path)
    {
        try
        {
            if (!Directory.Exists(path)) return null;
            long total = 0;
            var count = 0;
            var stack = new Stack<string>();
            stack.Push(path);
            while (stack.Count > 0 && count < 20_000)
            {
                var dir = stack.Pop();
                try
                {
                    foreach (var f in Directory.EnumerateFiles(dir))
                    {
                        if (++count > 20_000) break;
                        try { total += new FileInfo(f).Length; } catch { }
                    }
                    foreach (var sub in Directory.EnumerateDirectories(dir))
                        stack.Push(sub);
                }
                catch { }
            }
            return total;
        }
        catch { return null; }
    }

    public static PackageCacheSpec? FindWritable(string? envVar) =>
        string.IsNullOrWhiteSpace(envVar) ? null : WritableSpecs.FirstOrDefault(s => string.Equals(s.EnvVar, envVar.Trim(), StringComparison.OrdinalIgnoreCase));

    public static bool IsAllowlisted(string? envVar) => FindWritable(envVar) is not null;

    /// <summary>Action target format: <c>"NUGET_PACKAGES|D:\"</c>.</summary>
    public static string MakeActionTarget(string envVar, string devDriveRoot) => $"{envVar}|{NormalizeDriveRoot(devDriveRoot)}";

    public static string TargetEnvVar(string? actionTarget)
    {
        if (string.IsNullOrWhiteSpace(actionTarget)) return "";
        var pipe = actionTarget.IndexOf('|');
        return (pipe >= 0 ? actionTarget[..pipe] : actionTarget).Trim();
    }

    public static bool TryParseActionTarget(string? actionTarget, out PackageCacheSpec spec, out string targetFolder)
    {
        spec = null!;
        targetFolder = "";
        if (string.IsNullOrWhiteSpace(actionTarget)) return false;
        var pipe = actionTarget.IndexOf('|');
        if (pipe <= 0 || pipe >= actionTarget.Length - 1) return false;
        var envVar = actionTarget[..pipe].Trim();
        var root = NormalizeDriveRoot(actionTarget[(pipe + 1)..]);
        if (FindWritable(envVar) is not { } found) return false;
        if (root.Length != 3 || !char.IsAsciiLetter(root[0]) || root[1] != ':' || root[2] != '\\') return false;
        spec = found;
        targetFolder = $"{root}packages\\{found.Subfolder}";
        return true;
    }

    public static string NormalizeDriveRoot(string? root)
    {
        var t = (root ?? "").Trim();
        if (t.Length >= 2 && char.IsAsciiLetter(t[0]) && t[1] == ':')
            return $"{char.ToUpperInvariant(t[0])}:\\";
        return "";
    }

    public static bool IsPathOnDrive(string? path, string? driveRoot)
    {
        var normRoot = NormalizeDriveRoot(driveRoot);
        if (normRoot.Length == 0 || string.IsNullOrWhiteSpace(path)) return false;
        var expanded = Environment.ExpandEnvironmentVariables(path.Trim());
        return expanded.Length >= 2 && char.ToUpperInvariant(expanded[0]) == normRoot[0] && expanded[1] == ':';
    }

    /// <summary>Parses <c>[wsl2]</c> → <c>memory=</c> from <c>.wslconfig</c> by hand (no regexes).</summary>
    public static string? ParseWslConfigMemory(string? iniText)
    {
        if (string.IsNullOrWhiteSpace(iniText)) return null;
        var inWsl2 = false;
        foreach (var raw in iniText.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or ';') continue;
            if (line[0] == '[' && line[^1] == ']')
            {
                inWsl2 = string.Equals(line[1..^1].Trim(), "wsl2", StringComparison.OrdinalIgnoreCase);
                continue;
            }
            if (!inWsl2) continue;
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            if (!string.Equals(key, "memory", StringComparison.OrdinalIgnoreCase)) continue;
            var val = line[(eq + 1)..].Trim();
            var commentIdx = val.IndexOfAny(['#', ';']);
            if (commentIdx >= 0) val = val[..commentIdx].Trim();
            return val.Length > 0 ? val : null;
        }
        return null;
    }

    public static async Task<bool?> ReadLongPathsEnabledAsync(IRegistrySource registry, CancellationToken ct)
    {
        var r = await registry.ReadAsync(new RegistryRead(DataSources.RegistryRoot.LocalMachine, LongPathsKey, [LongPathsValueName]), ct).ConfigureAwait(false);
        return r.Success ? r.Rows?.FirstOrDefault()?.Long(LongPathsValueName) is { } v ? v != 0 : null : null;
    }
}
