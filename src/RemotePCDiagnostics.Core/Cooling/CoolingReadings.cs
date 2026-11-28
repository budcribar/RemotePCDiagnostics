using System.Runtime.InteropServices;
using System.Text.Json;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Cooling;

/// <summary>
/// One sample of what the cooling test watches: the hottest CPU temperature, the CPU's Tj max when it reports one, how busy the CPU was
/// since the last sample, and the fastest fan. Null fields were not readable.
/// </summary>
/// <param name="CpuC">Hottest live CPU temperature (Intel "Distance to TjMax" sensors left out: they are distances, not temperatures).</param>
/// <param name="TjMaxC">The CPU's reported Tj max (an Intel core temperature plus its distance to TjMax), or null when it reports none.</param>
/// <param name="LoadPercent">CPU busy since the previous sample, 0 to 100 (Windows' system times), or null on the first sample.</param>
/// <param name="FanRpm">The fastest fan, or null when the PC reports no fan speed. 0 is a stopped fan.</param>
/// <param name="Fans">Fans with a reading.</param>
/// <param name="Approximate">The CPU temperature is the ACPI thermal zone's (an estimate), not a CPU sensor.</param>
public sealed record CoolingReading(double? CpuC, double? TjMaxC, double? LoadPercent, double? FanRpm, int Fans = 0, bool Approximate = false)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static CoolingReading? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<CoolingReading>(json, Json); }
        catch (JsonException) { return null; }
    }

    public const string DistanceMarker = "Distance to TjMax";

    /// <summary>The cooling test's view of one sensor read (load comes from elsewhere).</summary>
    public static CoolingReading From(SensorSnapshot snap, double? load)
    {
        var cpu = snap.Readings.Where(r => r.HardwareType == HardwareKind.Cpu && r.SensorType == SensorKind.Temperature && r.IsLive).ToList();
        var temps = cpu.Where(r => !IsDistance(r)).ToList();
        var hottest = temps.OrderByDescending(r => r.Value).FirstOrDefault();
        var fans = snap.Readings.Where(r => r.SensorType == SensorKind.Fan && r.HasData).ToList();
        return new(hottest?.Value, TjMax(cpu), load, fans.Count == 0 ? null : fans.Max(f => f.Value), fans.Count, hottest?.IsApproximate == true);
    }

    private static bool IsDistance(SensorReading r) => r.SensorName.Contains(DistanceMarker, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Tj max from an Intel CPU's own sensors: "CPU Core #1" plus "CPU Core #1 Distance to TjMax" is that core's Tj max. The most common
    /// sum wins (they agree on a healthy CPU). Null when the CPU reports no distances (AMD, ARM, or no LibreHardwareMonitor).
    /// </summary>
    public static double? TjMax(IReadOnlyList<SensorReading> cpu)
    {
        var sums = new List<double>();
        foreach (var d in cpu.Where(IsDistance))
        {
            var core = d.SensorName.Replace(DistanceMarker, "", StringComparison.OrdinalIgnoreCase).Trim();
            var temp = cpu.FirstOrDefault(r => !IsDistance(r) && r.HardwareName == d.HardwareName && r.SensorName.Trim().Equals(core, StringComparison.OrdinalIgnoreCase));
            if (temp?.Value is { } t && d.Value is { } dist && dist >= 0) sums.Add(Math.Round(t + dist));
        }
        if (sums.Count == 0) return null;
        var best = sums.GroupBy(s => s).OrderByDescending(g => g.Count()).ThenByDescending(g => g.Key).First().Key;
        return best is >= 60 and <= 130 ? best : null;
    }
}

/// <summary>How busy all the CPU's cores are, from Windows' system times (no administrator rights).</summary>
public interface ICpuLoadSource
{
    /// <summary>Percent busy since the previous call (0 to 100), or null on the first call or when unreadable.</summary>
    double? Sample();
}

/// <summary><c>GetSystemTimes</c>: idle, kernel (which includes idle) and user time since boot, across all processors.</summary>
public sealed partial class WindowsCpuLoadSource : ICpuLoadSource
{
    private readonly object _gate = new();
    private (ulong Idle, ulong Total)? _last;

    public double? Sample()
    {
        if (!OperatingSystem.IsWindows() || !GetSystemTimes(out var idle, out var kernel, out var user)) return null;
        ulong i = idle, total = kernel + user;
        lock (_gate)
        {
            var last = _last;
            _last = (i, total);
            return last is { } l ? Busy(l.Idle, l.Total, i, total) : null;
        }
    }

    /// <summary>Busy percent between two readings of (idle, kernel + user).</summary>
    public static double? Busy(ulong idle0, ulong total0, ulong idle1, ulong total1)
    {
        if (total1 <= total0 || idle1 < idle0) return null;
        var dt = total1 - total0;
        var di = Math.Min(idle1 - idle0, dt);
        return Math.Round(100.0 * (dt - di) / dt, 1);
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetSystemTimes(out ulong idleTime, out ulong kernelTime, out ulong userTime);
}

/// <summary>
/// Where the cooling test reads the PC: a temperature, load and fan sample, and the Agent's thermal mode answers. One interface so a
/// recording keeps every answer in order (<see cref="Recording.RecordedCall.CoolingKind"/>) and replays the run.
/// </summary>
public interface ICoolingSource
{
    /// <summary>A sample now. Never throws: unreadable values are null.</summary>
    Task<CoolingReading> SampleAsync(CancellationToken ct);

    /// <summary>One <see cref="Session.AgentScripts.CoolingModes"/> request: <c>list</c>, <c>set windows|maker VALUE</c>, <c>restore</c>.</summary>
    Task<CoolingModesReply> ModesAsync(IReadOnlyList<string> args, CancellationToken ct);
}

/// <summary>The real source: the app's sensor provider (the same one Temperatures &amp; fans reads), Windows' CPU times, and the Agent.</summary>
public sealed class CoolingSource(ISensorProvider sensors, ICpuLoadSource load, Areas.SystemCommandRunner? commands, ILogger? log = null) : ICoolingSource
{
    public static readonly TimeSpan ModesTimeout = TimeSpan.FromSeconds(45);

    public Task<CoolingReading> SampleAsync(CancellationToken ct) => Task.Run(() =>
    {
        var busy = SafeLoad();
        try { return CoolingReading.From(sensors.Read(), busy); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Warn($"[cooling] sensor read failed: {ex.Message}");
            return new CoolingReading(null, null, busy, null);
        }
    }, ct);

    private double? SafeLoad()
    {
        try { return load.Sample(); }
        catch (Exception ex) { log.Warn($"[cooling] CPU load read failed: {ex.Message}"); return null; }
    }

    public async Task<CoolingModesReply> ModesAsync(IReadOnlyList<string> args, CancellationToken ct)
    {
        if (commands is null) return CoolingModesReply.Failed("The Agent isn't connected.", noAgent: true);
        var r = await commands.RunAgentScriptAsync(Session.AgentScripts.Of(Session.AgentScripts.CoolingModes, [.. args]), ModesTimeout, ct).ConfigureAwait(false);
        return CoolingModesReply.Read(r, commands.HasAdminRights);
    }
}
