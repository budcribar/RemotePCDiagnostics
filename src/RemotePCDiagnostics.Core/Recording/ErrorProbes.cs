using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>
/// WMI reads meant to fail, run by the recorder on each PC so a recording holds the errors that PC's WMI really gives (their status name, code
/// and wording). The fault-injection tests answer with these when a recording has them (<see cref="FaultPlan.UseRecordedErrors"/>), instead
/// of <see cref="Faults"/>' standard wording. Read-only: each is a SELECT that WMI refuses.
/// </summary>
public static class ErrorProbes
{
    public static readonly IReadOnlyList<(string Fault, string Namespace, string Query)> Wmi =
    [
        (Faults.MissingClass, @"root\cimv2", "SELECT Name FROM Win32_RpcdNoSuchClass"),
        (Faults.MissingNamespace, @"root\RpcdNoSuchNamespace", "SELECT Name FROM Win32_OperatingSystem"),
        (Faults.InvalidQuery, @"root\cimv2", "SELECT RpcdNoSuchProperty FROM Win32_OperatingSystem"),
    ];

    /// <summary>Runs every probe through <paramref name="wmi"/> (the recorder's recording source keeps the answers).</summary>
    public static async Task RunAsync(IWmiSource wmi, CancellationToken ct = default)
    {
        foreach (var (_, ns, query) in Wmi) await wmi.QueryAsync(ns, query, ct).ConfigureAwait(false);
    }

    /// <summary>Each fault's error text as this recording's PC gave it (only the probes that did fail).</summary>
    public static IReadOnlyDictionary<string, string> From(MachineRecording recording)
    {
        var errors = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (fault, ns, query) in Wmi)
        {
            var key = RecordingReplay.WmiKey(ns, query);
            var answer = recording.Calls.FirstOrDefault(c => c.Kind == RecordedCall.WmiKind && RecordingReplay.Key(c) == key);
            if (answer?.Error is { Length: > 0 } error) errors[fault] = error;
        }
        return errors;
    }
}
