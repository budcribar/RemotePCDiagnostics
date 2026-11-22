using System.Runtime.Versioning;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.DataSources;

/// <summary>Which registry root a read is under.</summary>
public enum RegistryRoot { LocalMachine, Users, CurrentUser }

/// <summary>
/// One registry read: the named values of a key, or of each of its subkeys (<see cref="SubKeys"/>). <see cref="View32"/> reads the 32-bit view
/// (WOW6432Node). Reads only; nothing is written.
/// </summary>
public sealed record RegistryRead(RegistryRoot Root, string Path, IReadOnlyList<string> Values, bool SubKeys = false, bool View32 = false)
{
    /// <summary>The name of a row's subkey, in each row of a <see cref="SubKeys"/> read.</summary>
    public const string KeyColumn = "_Key";

    /// <summary>Where the read goes: the root and view (as a recording keys it).</summary>
    public string Location => (Root switch { RegistryRoot.LocalMachine => "HKLM", RegistryRoot.Users => "HKU", _ => "HKCU" }) + (View32 ? " (32-bit)" : "");

    /// <summary>What is read, in one line: "subkeys of PATH: Value1, Value2".</summary>
    public string Describe() => (SubKeys ? "subkeys of " : "") + Path + ": " + string.Join(", ", Values);
}

/// <summary>
/// The registry, for the checks that read it, so a PC's answers can be recorded and replayed like WMI. The answer reuses
/// <see cref="WmiQueryResult"/>: <c>Namespace</c> is <see cref="RegistryRead.Location"/>, <c>Query</c> is <see cref="RegistryRead.Describe"/>,
/// and each row holds the values (strings, numbers, string arrays), plus <see cref="RegistryRead.KeyColumn"/> for a subkey. A key that doesn't
/// exist is no rows, not an error.
/// </summary>
public interface IRegistrySource
{
    /// <summary>Never throws except on cancellation.</summary>
    Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default);
}

/// <summary>
/// Reads this PC's registry with the process's own rights (the keys checks read are readable by a standard user; another user's hive under
/// HKEY_USERS is skipped when it can't be opened, as osquery does). Off Windows every read fails.
/// </summary>
public sealed class SystemRegistrySource(ILogger? log = null) : IRegistrySource
{
    public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        WmiQueryResult result;
        if (!OperatingSystem.IsWindows()) result = WmiQueryResult.Failed(read.Location, read.Describe(), "The registry is only available on Windows.");
        else
        {
            try { result = Read(read); }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
                result = WmiQueryResult.Failed(read.Location, read.Describe(), ex.Message);
            }
        }
        try
        {
            log.Line($"registry {read.Location} \"{read.Describe()}\" {(result.Success ? "ok" : "FAILED")} rows={result.Rows?.Count ?? 0} ms={sw.ElapsedMilliseconds}" +
                     (result.Error is null ? "" : $" error=\"{result.Error}\""));
        }
        catch { /* logging never breaks a read */ }
        return Task.FromResult(result);
    }

    [SupportedOSPlatform("windows")]
    private static WmiQueryResult Read(RegistryRead read)
    {
        var hive = read.Root switch
        {
            RegistryRoot.LocalMachine => Microsoft.Win32.RegistryHive.LocalMachine,
            RegistryRoot.Users => Microsoft.Win32.RegistryHive.Users,
            _ => Microsoft.Win32.RegistryHive.CurrentUser,
        };
        using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(hive, read.View32 ? Microsoft.Win32.RegistryView.Registry32 : Microsoft.Win32.RegistryView.Registry64);
        using var key = read.Path.Length == 0 ? root : root.OpenSubKey(read.Path, writable: false);
        var rows = new List<WmiRow>();
        if (key is null) return new(read.Location, read.Describe(), rows);
        if (!read.SubKeys)
        {
            rows.Add(Row(key, read.Values, null));
            return new(read.Location, read.Describe(), rows);
        }
        foreach (var name in key.GetSubKeyNames())
        {
            Microsoft.Win32.RegistryKey? sub;
            try { sub = key.OpenSubKey(name, writable: false); }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException) { continue; }
            if (sub is null) continue;
            using (sub) rows.Add(Row(sub, read.Values, name));
        }
        return new(read.Location, read.Describe(), rows);
    }

    [SupportedOSPlatform("windows")]
    private static WmiRow Row(Microsoft.Win32.RegistryKey key, IReadOnlyList<string> names, string? subKey)
    {
        var values = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
        if (subKey is not null) values[RegistryRead.KeyColumn] = JsonSerializer.SerializeToElement(subKey);
        foreach (var n in names)
        {
            // Strings, numbers and string lists; binary values aren't read.
            object? v = key.GetValue(n, null, Microsoft.Win32.RegistryValueOptions.DoNotExpandEnvironmentNames) switch
            {
                string s => s,
                int i => i,
                long l => l,
                string[] a => a,
                _ => null,
            };
            if (v is not null) values[n] = JsonSerializer.SerializeToElement(v);
        }
        return new WmiRow(values);
    }
}
