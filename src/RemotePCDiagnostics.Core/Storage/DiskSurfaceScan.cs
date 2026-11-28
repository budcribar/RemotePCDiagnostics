using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>Quick samples the whole disk in about a minute; Full reads every block in order.</summary>
public enum DiskScanMode { Quick, Full }

/// <summary>
/// One physical disk opened for reading only, with unbuffered reads (so Windows' cache can't hide an error). The Agent opens
/// <c>\\.\PhysicalDriveN</c> (<see cref="WindowsDiskBlockDevice"/>); tests use a fake with injected errors and latency.
/// </summary>
public interface IDiskBlockDevice : IDisposable
{
    long SizeBytes { get; }
    /// <summary>The logical sector size: every read starts and ends on it.</summary>
    int SectorBytes { get; }
    /// <summary>True for a spinning drive (Windows' seek penalty), false for an SSD, null when Windows didn't say.</summary>
    bool? IncursSeekPenalty { get; }
    IReadOnlyList<DiskPartitionInfo> Partitions { get; }
    /// <summary>Reads <paramref name="length"/> bytes at <paramref name="offset"/> and throws the data away. 0, or the Windows error code.</summary>
    int Read(long offset, int length);
}

/// <param name="Volume">The volume's drive letter ("C:") when it has one.</param>
public sealed record DiskPartitionInfo(int Number, long Offset, long Length, string? Volume = null);

/// <summary>Why the scan should slow down right now (on battery below 30 %, the drive over its temperature warning), or null.</summary>
public interface IDiskScanConditions
{
    string? ThrottleReason();
}

/// <summary>The scan's clock: real time on the PC, a clock the fake disk moves forward in tests.</summary>
public interface IScanClock
{
    TimeSpan Elapsed { get; }
    void Sleep(TimeSpan time);
}

public sealed class StopwatchScanClock : IScanClock
{
    private readonly Stopwatch _sw = Stopwatch.StartNew();
    public TimeSpan Elapsed => _sw.Elapsed;
    public void Sleep(TimeSpan time) => Thread.Sleep(time);
}

/// <param name="TimeLimit">Full mode only: stop after this long (null for no limit).</param>
public sealed record DiskScanOptions(int DiskNumber, DiskScanMode Mode, TimeSpan? TimeLimit = null)
{
    /// <summary>Every block is 1 MB (the spec allows 1–4 MB): small enough that a USB 2 stick isn't "slow" for its bus alone.</summary>
    public const int BlockBytes = 1 << 20;
    public const int QuickSamples = 1000;
    public const int SlowHddMs = 150, SlowSsdMs = 50;
    /// <summary>At most this many bad sectors are listed (the counts still cover every one).</summary>
    public const int MaxBadLbas = 50;
    public static readonly TimeSpan MaxTimeLimit = TimeSpan.FromHours(24);
    /// <summary>How often the battery and the drive's temperature are looked at.</summary>
    public static readonly TimeSpan ConditionsEvery = TimeSpan.FromSeconds(5);
    /// <summary>The pause after each block while the scan is throttled.</summary>
    public static readonly TimeSpan ThrottlePause = TimeSpan.FromMilliseconds(500);
}

/// <summary>One unreadable spot: its first sector (LBA), how many sectors it covers, the Windows error and the partition it is in.</summary>
public sealed record DiskBadBlock(long Lba, long Sectors, int Error, string ErrorText, string Where);

/// <summary>
/// What the Agent answers to <c>disk_read_scan</c>: the scan so far, or how it ended. The app builds its report from this alone, so a
/// recorded answer replays the same report.
/// </summary>
public sealed record DiskScanStatus
{
    public const string Running = "running", Finished = "finished", Stopped = "stopped", TimeLimit = "timeLimit", Failed = "failed";

    public int Disk { get; init; }
    public string Mode { get; init; } = "quick";
    /// <summary><see cref="Running"/>, <see cref="Finished"/>, <see cref="Stopped"/>, <see cref="TimeLimit"/> or <see cref="Failed"/>.</summary>
    public string State { get; init; } = Running;
    public string? Error { get; init; }
    public long SizeBytes { get; init; }
    public int SectorBytes { get; init; }
    /// <summary>"HDD", "SSD" or "" (not known: judged as an HDD, the more patient threshold).</summary>
    public string Media { get; init; } = "";
    public int SlowMs { get; init; }
    public long Planned { get; init; }
    public long Read { get; init; }
    public long Unreadable { get; init; }
    public long Retried { get; init; }
    public long Slow { get; init; }
    public double MaxLatencyMs { get; init; }
    public double AverageLatencyMs { get; init; }
    public long BytesRead { get; init; }
    public double ElapsedSeconds { get; init; }
    public double ThrottledSeconds { get; init; }
    /// <summary>Why the scan is (or last was) slowed down, or null.</summary>
    public string? Throttle { get; init; }
    /// <summary><see cref="DiskSurfaceMap.Bins"/> characters, each the worst block in that part of the disk (<see cref="DiskSurfaceMap"/>).</summary>
    public string Map { get; init; } = "";
    public IReadOnlyList<DiskBadBlock> BadBlocks { get; init; } = [];

    public bool IsRunning => State == Running;
    public double Fraction => Planned > 0 ? Math.Clamp((double)Read / Planned, 0, 1) : 0;

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    /// <summary>The status in <paramref name="json"/>, or null when it isn't one.</summary>
    public static DiskScanStatus? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<DiskScanStatus>(json, Json); }
        catch (JsonException) { return null; }
    }
}

/// <summary>The surface map: the disk in <see cref="Bins"/> equal parts, each shown as its worst block.</summary>
public static class DiskSurfaceMap
{
    public const int Bins = 100;
    public const char NotRead = '.', Ok = 'o', Slow = 's', Retried = 'r', Unreadable = 'x';

    /// <summary>Worse wins: unreadable, then retried, then slow, then read fine.</summary>
    public static int Rank(char c) => c switch { Unreadable => 4, Retried => 3, Slow => 2, Ok => 1, _ => 0 };

    public static int BinOf(long offset, long size) => size <= 0 ? 0 : (int)Math.Clamp(offset / (double)size * Bins, 0, Bins - 1);

    public static string Describe(char c) => c switch
    {
        Unreadable => "unreadable", Retried => "read on the second try", Slow => "slow", Ok => "read fine", _ => "not read",
    };
}

/// <summary>Which blocks a scan reads, in order.</summary>
public static class DiskScanPlan
{
    public static IEnumerable<(long Offset, int Length)> Blocks(long size, int sector, DiskScanMode mode)
    {
        if (size <= 0 || sector <= 0) yield break;
        var usable = size / sector * sector;
        var maxBlock = DiskScanOptions.BlockBytes / sector * sector;
        var block = (int)Math.Min(maxBlock, usable);
        if (block <= 0) yield break;
        var lastSector = usable - sector;
        if (mode == DiskScanMode.Full)
        {
            for (long at = 0; at <= lastSector; at += block)
                yield return (at, (int)Math.Min(block, usable - at));
            yield break;
        }
        // Quick: the first, middle and last sectors (what a minimal surface test reads), then blocks spread evenly over the whole disk.
        yield return (0, sector);
        yield return (size / 2 / sector * sector, sector);
        yield return (lastSector, sector);
        var blocks = Math.Max(1, size / block);
        var samples = Math.Min(DiskScanOptions.QuickSamples, blocks);
        var stride = size / (double)samples;
        for (var i = 0; i < samples; i++)
        {
            var at = (long)(i * stride + stride / 2 - block / 2.0);
            at = Math.Clamp(at, 0, Math.Max(0, usable - block)) / sector * sector;
            yield return (at, block);
        }
    }

    public static long Count(long size, int sector, DiskScanMode mode)
    {
        if (size <= 0 || sector <= 0) return 0;
        var usable = size / sector * sector;
        var maxBlock = DiskScanOptions.BlockBytes / sector * sector;
        var block = Math.Min(maxBlock, usable);
        if (block <= 0) return 0;
        return mode == DiskScanMode.Full ? (usable + block - 1) / block : 3 + Math.Min(DiskScanOptions.QuickSamples, Math.Max(1, size / block));
    }
}

/// <summary>Windows error codes a read can end with, in words.</summary>
public static class DiskReadErrors
{
    public const int NotReady = 21, Crc = 23, SectorNotFound = 27, ReadFault = 30, GenFailure = 31, IoDevice = 1117,
        DeviceNotConnected = 1167, NoSuchDevice = 433, DeviceHardware = 483, DeviceRemoved = 1617;

    public static string Text(int code) => code switch
    {
        Crc => "data error (CRC)",
        SectorNotFound => "sector not found",
        ReadFault => "read fault",
        GenFailure => "device not functioning",
        IoDevice => "I/O device error",
        DeviceHardware => "hardware error",
        NotReady => "device not ready",
        DeviceNotConnected or NoSuchDevice or DeviceRemoved => "device disconnected",
        _ => $"Windows error {code}",
    };

    /// <summary>The disk itself went away: carrying on would only list every block as unreadable.</summary>
    public static bool IsGone(int code) => code is NotReady or DeviceNotConnected or NoSuchDevice or DeviceRemoved;
}

/// <summary>
/// Reads a disk block by block and keeps count. Read-only: the only call it makes on the disk is <see cref="IDiskBlockDevice.Read"/>.
/// <see cref="Run"/> blocks until the scan ends (finished, stopped, time limit, or the disk failed); <see cref="Snapshot"/> may be called
/// from any thread meanwhile.
/// </summary>
public sealed class DiskSurfaceScanner(IDiskBlockDevice device, DiskScanOptions options, IDiskScanConditions? conditions = null, IScanClock? clock = null,
    Func<bool>? isAbandoned = null)
{
    private enum BlockOutcome { Continue, Stopped, Gone }

    private readonly IScanClock _clock = clock ?? new StopwatchScanClock();
    private readonly object _gate = new();
    private readonly char[] _map = Enumerable.Repeat(DiskSurfaceMap.NotRead, DiskSurfaceMap.Bins).ToArray();
    private readonly List<DiskBadBlock> _bad = [];
    private string _state = DiskScanStatus.Running;
    private string? _error, _throttle, _lastThrottle;
    private long _read, _unreadable, _retried, _slow, _bytes;
    private double _maxMs, _totalMs, _throttled, _elapsed;
    /// <summary>Refining a bad 1 MB block into sectors is capped, so a dying disk can't make the scan read forever.</summary>
    private int _refineBudget = 4096;

    /// <summary>Blocks slower than this count as slow: 150 ms for a spinning (or unknown) drive, 50 ms for an SSD.</summary>
    public int SlowMs { get; } = device.IncursSeekPenalty == false ? DiskScanOptions.SlowSsdMs : DiskScanOptions.SlowHddMs;

    private string Media => device.IncursSeekPenalty switch { true => "HDD", false => "SSD", null => "" };

    private bool ShouldStop(CancellationToken ct) => ct.IsCancellationRequested || isAbandoned?.Invoke() == true;

    public DiskScanStatus Snapshot()
    {
        lock (_gate)
        {
            return new DiskScanStatus
            {
                Disk = options.DiskNumber,
                Mode = options.Mode == DiskScanMode.Full ? "full" : "quick",
                State = _state,
                Error = _error,
                SizeBytes = device.SizeBytes,
                SectorBytes = device.SectorBytes,
                Media = Media,
                SlowMs = SlowMs,
                Planned = DiskScanPlan.Count(device.SizeBytes, device.SectorBytes, options.Mode),
                Read = _read,
                Unreadable = _unreadable,
                Retried = _retried,
                Slow = _slow,
                MaxLatencyMs = Math.Round(_maxMs, 1),
                AverageLatencyMs = _read > 0 ? Math.Round(_totalMs / _read, 2) : 0,
                BytesRead = _bytes,
                ElapsedSeconds = Math.Round(_elapsed, 1),
                ThrottledSeconds = Math.Round(_throttled, 1),
                Throttle = _state == DiskScanStatus.Running ? _throttle : _lastThrottle,
                Map = new string(_map),
                BadBlocks = [.. _bad],
            };
        }
    }

    public DiskScanStatus Run(CancellationToken ct)
    {
        var start = _clock.Elapsed;
        var nextConditions = TimeSpan.Zero;
        string? throttle = null;
        string end = DiskScanStatus.Finished;
        try
        {
            foreach (var (offset, length) in DiskScanPlan.Blocks(device.SizeBytes, device.SectorBytes, options.Mode))
            {
                if (ShouldStop(ct)) { end = DiskScanStatus.Stopped; break; }
                var elapsed = _clock.Elapsed - start;
                if (options.TimeLimit is { } limit && elapsed >= limit) { end = DiskScanStatus.TimeLimit; break; }
                if (conditions is not null && elapsed >= nextConditions)
                {
                    throttle = SafeThrottle();
                    nextConditions = elapsed + DiskScanOptions.ConditionsEvery;
                    lock (_gate)
                    {
                        _throttle = throttle;
                        if (throttle is not null) _lastThrottle = throttle;
                    }
                }

                var outcome = ReadBlock(offset, length, ct);
                if (outcome == BlockOutcome.Gone) { end = DiskScanStatus.Failed; break; }
                if (outcome == BlockOutcome.Stopped) { end = DiskScanStatus.Stopped; break; }

                if (throttle is not null)
                {
                    _clock.Sleep(DiskScanOptions.ThrottlePause);
                    lock (_gate) _throttled += DiskScanOptions.ThrottlePause.TotalSeconds;
                }
                lock (_gate) _elapsed = (_clock.Elapsed - start).TotalSeconds;
            }
        }
        catch (Exception ex)
        {
            lock (_gate) _error ??= ex.Message;
            end = DiskScanStatus.Failed;
        }
        lock (_gate)
        {
            _state = end;
            _elapsed = (_clock.Elapsed - start).TotalSeconds;
        }
        return Snapshot();
    }

    private string? SafeThrottle()
    {
        try { return conditions!.ThrottleReason(); }
        catch { return null; }
    }

    /// <summary>Reads one block, retrying once on error and narrowing persistent errors down to bad sectors.</summary>
    private BlockOutcome ReadBlock(long offset, int length, CancellationToken ct)
    {
        var (error, ms) = Timed(offset, length);
        char mark;
        if (error == 0) mark = ms > SlowMs ? DiskSurfaceMap.Slow : DiskSurfaceMap.Ok;
        else
        {
            if (DiskReadErrors.IsGone(error)) { Gone(error); return BlockOutcome.Gone; }
            if (ShouldStop(ct)) return BlockOutcome.Stopped;
            // Once more: a read that works the second time is a weak spot, not a bad one.
            var (again, ms2) = Timed(offset, length);
            ms = Math.Max(ms, ms2);
            if (again == 0) mark = DiskSurfaceMap.Retried;
            else
            {
                if (DiskReadErrors.IsGone(again)) { Gone(again); return BlockOutcome.Gone; }
                mark = DiskSurfaceMap.Unreadable;
                var refined = LocateBadSectors(offset, length, again, ct);
                if (refined != BlockOutcome.Continue) return refined;
            }
        }

        lock (_gate)
        {
            _read++;
            _bytes += length;
            _totalMs += ms;
            _maxMs = Math.Max(_maxMs, ms);
            switch (mark)
            {
                case DiskSurfaceMap.Slow: _slow++; break;
                case DiskSurfaceMap.Retried: _retried++; break;
                case DiskSurfaceMap.Unreadable: _unreadable++; break;
            }
            var bin = DiskSurfaceMap.BinOf(offset, device.SizeBytes);
            if (DiskSurfaceMap.Rank(mark) > DiskSurfaceMap.Rank(_map[bin])) _map[bin] = mark;
        }
        return BlockOutcome.Continue;
    }

    private void Gone(int error)
    {
        lock (_gate) _error = $"The disk stopped answering ({DiskReadErrors.Text(error)}, error {error}).";
    }

    private (int Error, double Ms) Timed(long offset, int length)
    {
        var t0 = _clock.Elapsed;
        var error = device.Read(offset, length);
        return (error, (_clock.Elapsed - t0).TotalMilliseconds);
    }

    /// <summary>Narrows an unreadable block down to its bad sectors (64 KB pieces, then single sectors), within the refine budget.</summary>
    private BlockOutcome LocateBadSectors(long offset, int length, int blockError, CancellationToken ct)
    {
        var sector = device.SectorBytes;
        var found = 0;
        const int Piece = 64 * 1024;
        var piece = Math.Max(sector, Piece / sector * sector);
        for (long at = offset; at < offset + length && _refineBudget > 0; at += piece)
        {
            if (ShouldStop(ct)) return BlockOutcome.Stopped;
            var len = (int)Math.Min(piece, offset + length - at);
            _refineBudget--;
            var pe = device.Read(at, len);
            if (pe == 0) continue;
            if (DiskReadErrors.IsGone(pe)) { Gone(pe); return BlockOutcome.Gone; }
            for (long s = at; s < at + len && _refineBudget > 0; s += sector)
            {
                if (ShouldStop(ct)) return BlockOutcome.Stopped;
                _refineBudget--;
                var e = device.Read(s, sector);
                if (e == 0) continue;
                if (DiskReadErrors.IsGone(e)) { Gone(e); return BlockOutcome.Gone; }
                found++;
                AddBad(s / sector, 1, e);
            }
        }
        // Couldn't single it out (out of budget, or the error came and went): list the whole block.
        if (found == 0) AddBad(offset / sector, length / sector, blockError);
        return BlockOutcome.Continue;
    }

    private void AddBad(long lba, long sectors, int error)
    {
        lock (_gate)
        {
            if (_bad.Count >= DiskScanOptions.MaxBadLbas) return;
            var last = _bad.Count > 0 ? _bad[^1] : null;
            // Neighbouring bad sectors with the same error read as one run.
            if (last is not null && last.Error == error && last.Lba + last.Sectors == lba)
            {
                _bad[^1] = last with { Sectors = last.Sectors + sectors };
                return;
            }
            _bad.Add(new DiskBadBlock(lba, sectors, error, DiskReadErrors.Text(error), Where(lba * device.SectorBytes)));
        }
    }

    private string Where(long byteOffset)
    {
        var p = device.Partitions.FirstOrDefault(p => byteOffset >= p.Offset && byteOffset < p.Offset + p.Length);
        return p is null ? "Outside any partition" : p.Volume is { Length: > 0 } v ? $"Partition {p.Number} ({v})" : $"Partition {p.Number}";
    }
}
