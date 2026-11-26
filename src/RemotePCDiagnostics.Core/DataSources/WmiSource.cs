using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.DataSources;

/// <summary>
/// One WMI query: rows back, or an error. Every check that reads WMI goes through this, so a PC's answers can be recorded and later replayed
/// in tests (<see cref="Recording"/>). Values are kept as JSON from the start, so a live answer and a replayed one look the same to a check.
/// </summary>
public interface IWmiSource
{
    /// <summary>Runs <paramref name="wql"/> in <paramref name="wmiNamespace"/> (for example <c>root\cimv2</c>). Never throws except on cancellation.</summary>
    Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default);
}

/// <summary>The answer to one WMI query. <see cref="Rows"/> is null when the query failed (<see cref="Error"/> says why).</summary>
public sealed record WmiQueryResult(string Namespace, string Query, IReadOnlyList<WmiRow>? Rows, string? Error = null)
{
    public bool Success => Error is null;

    public static WmiQueryResult Failed(string ns, string query, string error) => new(ns, query, null, error);
}

/// <summary>One WMI object's properties, as JSON values (string, number, bool, array or null).</summary>
public sealed class WmiRow(IReadOnlyDictionary<string, JsonElement> values)
{
    public IReadOnlyDictionary<string, JsonElement> Values { get; } = new Dictionary<string, JsonElement>(values, StringComparer.OrdinalIgnoreCase);

    public bool Has(string name) => Values.TryGetValue(name, out var v) && v.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined);

    /// <summary>The property as trimmed text ("" when missing or null).</summary>
    public string Str(string name)
    {
        if (!Values.TryGetValue(name, out var v)) return "";
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString()!.Trim(),
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => v.GetRawText(),
            _ => "",
        };
    }

    /// <summary>The property as a whole number, or null when missing, null or not a number.</summary>
    public long? Long(string name)
    {
        if (!Values.TryGetValue(name, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number)
        {
            if (v.TryGetInt64(out var l)) return l;
            if (v.TryGetDouble(out var d) && double.IsFinite(d) && d is >= long.MinValue and <= long.MaxValue) return (long)d;
            return null;
        }
        if (v.ValueKind == JsonValueKind.String && long.TryParse(v.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var s)) return s;
        return null;
    }

    /// <summary>The property as a flag, or null when missing or not a flag.</summary>
    public bool? Bool(string name) =>
        Values.TryGetValue(name, out var v) ? v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null } : null;

    public static WmiRow From(IEnumerable<KeyValuePair<string, object?>> properties) =>
        new(properties.ToDictionary(p => p.Key, p => JsonSerializer.SerializeToElement(p.Value), StringComparer.OrdinalIgnoreCase));
}

/// <summary>Reads WMI on this PC through System.Management. Off Windows every query fails.</summary>
public sealed class SystemWmiSource(ILogger? log = null, TimeSpan? timeout = null) : IWmiSource
{
    public TimeSpan Timeout { get; } = timeout ?? TimeSpan.FromSeconds(30);

    public async Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) return WmiQueryResult.Failed(wmiNamespace, wql, "WMI is only available on Windows.");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        WmiQueryResult result;
        try
        {
            result = await Task.Run(() => OperatingSystem.IsWindows() ? Run(wmiNamespace, wql) : throw new PlatformNotSupportedException(), ct).WaitAsync(Timeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (TimeoutException) { result = WmiQueryResult.Failed(wmiNamespace, wql, $"The query timed out after {Timeout.TotalSeconds:0}s."); }
        catch (Exception ex) { result = WmiQueryResult.Failed(wmiNamespace, wql, Describe(ex)); }
        try
        {
            log.Line($"wmi {wmiNamespace} \"{wql}\" {(result.Success ? "ok" : "FAILED")} rows={result.Rows?.Count ?? 0} ms={sw.ElapsedMilliseconds}" +
                     (result.Error is null ? "" : $" error=\"{result.Error}\""));
        }
        catch { /* logging never breaks a query */ }
        return result;
    }

    /// <summary>The error's text. Some WMI failures come with an empty message, so the status (ManagementException: its name and code) or the
    /// exception type is kept too.</summary>
    private static string Describe(Exception ex)
    {
        // The status name and its code ("InvalidClass (0x80041010)"): the code is what Microsoft's documentation and searches use.
        var code = OperatingSystem.IsWindows() && ex is System.Management.ManagementException me ? $"{me.ErrorCode} (0x{(uint)me.ErrorCode:X8})" : null;
        var message = ex.Message.Trim();
        if (code is null) return message.Length > 0 ? message : $"{ex.GetType().Name} (0x{ex.HResult:X8})";
        return message.Length > 0 ? $"{code}: {message}" : code;
    }

    [SupportedOSPlatform("windows")]
    private static WmiQueryResult Run(string ns, string wql)
    {
        var rows = new List<WmiRow>();
        using var searcher = new System.Management.ManagementObjectSearcher(ns, wql);
        using var found = searcher.Get();
        foreach (var o in found)
        {
            using (o)
            {
                var props = new List<KeyValuePair<string, object?>>();
                foreach (var p in o.Properties) props.Add(new(p.Name, p.Value));
                rows.Add(WmiRow.From(props));
            }
        }
        return new(ns, wql, rows);
    }
}
