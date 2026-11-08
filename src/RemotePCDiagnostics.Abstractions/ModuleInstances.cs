using System.Security.Cryptography;
using System.Text;

namespace RemotePCDiagnostics.Core;

/// <summary>
/// One thing a per-device module runs against (a drive, a GPU, a webcam). <see cref="Key"/> must survive reboots and port changes (disk serial
/// or WWN, PCI ids plus location, PnP container id), hashed with <see cref="InstanceKeys.From"/>. <see cref="Label"/> is for display only.
/// </summary>
public sealed record ModuleInstance(string Key, string Label, string? Details = null)
{
    /// <summary>Set when this instance exists but the test doesn't apply to it (a surface scan on a USB stick).</summary>
    public string? NotApplicableReason { get; init; }
    public bool Applies => NotApplicableReason is null;
}

/// <summary>The answer to "does this test apply to this PC?": not applicable (with the reason), or the instances it runs against.</summary>
public sealed record ModuleDetection(string? NotApplicableReason, IReadOnlyList<ModuleInstance> Instances)
{
    public bool Applies => NotApplicableReason is null && Instances.Any(i => i.Applies);

    public static ModuleDetection NotApplicable(string reason) => new(reason, []);
    public static ModuleDetection For(IEnumerable<ModuleInstance> instances)
    {
        var list = instances.ToList();
        return list.Count == 0 ? NotApplicable("No matching hardware found") : new(null, list);
    }
}

/// <summary>
/// The one pre-run check: fast, side-effect free, never throws. Runs at startup and on hardware changes. Not applicable modules are hidden
/// from lists and Run All; History still names their results. Replaces <see cref="IHardwareGatedModule"/> for new modules.
/// </summary>
public interface IDetectableModule : IDiagnosticModule
{
    Task<ModuleDetection> DetectAsync(CancellationToken ct = default);
}

/// <summary>
/// A module with one run per hardware instance. Results are keyed on (module id, <see cref="ModuleInstance.Key"/>): each instance result
/// carries <see cref="DiagnosticResult.InstanceKey"/> and <see cref="DiagnosticResult.InstanceLabel"/>, is logged on its own and shows in
/// History under the module, then the instance.
/// </summary>
public interface IPerDeviceModule : IDetectableModule
{
    Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken ct = default);
}

public static class InstanceKeys
{
    /// <summary>A short stable key from a raw hardware id (trimmed, case-insensitive): 16 hex characters of its SHA-256.</summary>
    public static string From(string rawId) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawId.Trim().ToUpperInvariant())))[..16].ToLowerInvariant();
}

/// <summary>
/// Payload of a run that couldn't happen: a bundled tool missing, the device busy (a webcam held by another app), the sensor driver failing
/// to start. Recorded in History as "Couldn't run" with the reason. A test that doesn't apply to the PC is hidden instead (see
/// <see cref="IDetectableModule"/>).
/// </summary>
public sealed record CouldNotRun(string Reason) : IRunEnd
{
    public const string OutcomeText = "Couldn't run";
    public string Outcome => OutcomeText;
    [System.Text.Json.Serialization.JsonIgnore] public RunEnd RunEnd => RunEnd.CouldNotRun;

    public static DiagnosticResult Result(string moduleName, string reason) =>
        new(moduleName, DiagnosticStatus.Error, reason, DateTimeOffset.Now, new CouldNotRun(reason));
}

/// <summary>Payload of a per-device module's overall result: the result for each instance, in run order.</summary>
public sealed record InstanceResults(IReadOnlyList<DiagnosticResult> Results)
{
    /// <summary>The module's own combined report of all devices (<see cref="IInstanceSummary.Combine"/>), for pages that show one report.</summary>
    public object? Summary { get; init; }
}

/// <summary>
/// Optional on an <see cref="IPerDeviceModule"/>: folds the per-device results into the single report its page already knows how to show
/// (one AreaReport with a card per drive, one NpuTestReport listing every NPU). Read it with <see cref="InstanceResultExtensions.Report"/>.
/// </summary>
public interface IInstanceSummary
{
    /// <summary>The latest result of each device, in detection order. Never throws for a result without a payload.</summary>
    object? Combine(IReadOnlyList<DiagnosticResult> instanceResults);
}

public static class InstanceResultExtensions
{
    /// <summary>The payload to show for a module result: a per-device module's combined report, otherwise the payload itself.</summary>
    public static object? Report(this DiagnosticResult r) => r.Payload is InstanceResults ir ? ir.Summary : r.Payload;
}

