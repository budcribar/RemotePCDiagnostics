using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// Disk speed test on a single temporary file in a dedicated folder: sequential write → sequential read-back (verified),
/// random 4 KB writes → random 4 KB reads (verified). Free-space guarded, time-limited, stoppable, aborts on any critical
/// temperature, and always deletes its temporary file (also stale ones left by a crash). Never touches any other file.
/// </summary>
public sealed class DiskSpeedTest(IDiskTestFileSystem fs, ISensorProvider sensors, IStressClock? clock = null, Action<string>? log = null)
{
    public const string TempFilePrefix = "rpd-speedtest-";
    public const string TempFilePattern = TempFilePrefix + "*.tmp";
    public const int PageBytes = 4096;

    private const int StopNone = 0, StopUser = 1, StopHot = 2;

    /// <summary>Bytes to use: min(requested, fraction of free, free minus reserve), whole sequential blocks; null when too little space.</summary>
    public static long? PlanSize(long freeBytes, DiskSpeedOptions o)
    {
        var size = Math.Min(o.RequestedSizeBytes, Math.Min((long)(freeBytes * o.MaxFreeFraction), freeBytes - o.MinFreeLeftBytes));
        size -= size % o.SequentialBlockBytes;
        return size >= o.MinTestBytes ? size : null;
    }

    public static double? MBps(long bytes, TimeSpan t) => t > TimeSpan.Zero && bytes > 0 ? bytes / 1e6 / t.TotalSeconds : null;
    public static double? Iops(long ops, TimeSpan t) => t > TimeSpan.Zero && ops > 0 ? ops / t.TotalSeconds : null;

    public static bool IsSlow(DiskSpeedOptions o, double? seqWrite, double? seqRead, double? randRead) =>
        seqRead < o.SlowSequentialReadMBps || seqWrite < o.SlowSequentialWriteMBps || randRead < o.SlowRandomReadIops;

    /// <summary>Deterministic content for one 4 KB page (differs per run, page and generation).</summary>
    public static void FillPage(Span<byte> page, ulong runSeed, long pageIndex, int generation)
    {
        var words = MemoryMarshal.Cast<byte, ulong>(page);
        ulong x = (runSeed ^ ((ulong)pageIndex * 0x9E3779B97F4A7C15UL) ^ ((ulong)(generation + 1) * 0xC2B2AE3D27D4EB4FUL)) | 1UL;
        words[0] = (ulong)pageIndex; words[1] = (ulong)generation;
        for (int i = 2; i < words.Length; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; words[i] = x; }
    }

    private sealed class State
    {
        public volatile int Stop;
        public volatile DiskSpeedPhase Phase = DiskSpeedPhase.Preparing;
        public double PhaseFraction;
        public double? DriveTemp, Fan, MaxDriveTemp;
    }

    public async Task<DiskSpeedReport> RunAsync(DiskSpeedOptions o, IProgress<DiskSpeedProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var clk = clock ?? new StopwatchStressClock();
        var duration = o.Duration <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : o.Duration > DiskSpeedOptions.MaxDuration ? DiskSpeedOptions.MaxDuration : o.Duration;
        var start = clk.Elapsed;

        TestDrive? drive;
        try
        {
            var drives = fs.GetFixedDrives();
            drive = o.DriveRoot is null ? drives.FirstOrDefault(d => d.IsSystem) ?? drives.FirstOrDefault()
                : drives.FirstOrDefault(d => string.Equals(d.Root, o.DriveRoot, StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) { log?.Invoke($"Disk speed: listing drives failed: {ex}"); drive = null; }
        if (drive is null)
        {
            log?.Invoke($"Disk speed: drive '{o.DriveRoot ?? "(system)"}' not found");
            return Empty(DiskSpeedOutcome.Failed, "", clk.Elapsed - start);
        }

        var folder = fs.GetTestFolder(drive);
        CleanupStale(folder);

        long free;
        try { free = fs.GetFreeBytes(drive.Root); }
        catch (Exception ex) { log?.Invoke($"Disk speed: free space check failed: {ex.Message}"); return Empty(DiskSpeedOutcome.Failed, drive.DisplayName, clk.Elapsed - start); }
        if (PlanSize(free, o) is not { } size)
        {
            log?.Invoke($"Disk speed: not enough free space on {drive.Root}: free={free}");
            return Empty(DiskSpeedOutcome.NotEnoughSpace, drive.DisplayName, clk.Elapsed - start);
        }

        var path = Path.Combine(folder, $"{TempFilePrefix}{Guid.NewGuid():N}.tmp");
        log?.Invoke($"Disk speed: start drive={drive.Root} file={path} size={size} free={free} duration={duration}");
        var st = new State();
        var sensorsOk = SafeAvailability();
        using var monitorStop = new CancellationTokenSource();
        var monitor = MonitorAsync(st, clk, start, duration, o, sensorsOk, progress, cancellationToken, monitorStop.Token);

        double? sw = null, sr = null, rw = null, rr = null;
        long verified = 0, errors = 0;
        var failed = false;
        var cleaned = false;
        try
        {
            (sw, sr, rw, rr, verified, errors) = await Task.Run(() => RunIo(path, size, o, st, clk, start, duration, cancellationToken), CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            failed = true;
            log?.Invoke($"Disk speed: I/O failed: {ex}");
        }
        finally
        {
            st.Phase = DiskSpeedPhase.CleaningUp;
            monitorStop.Cancel();
            try { await monitor.ConfigureAwait(false); } catch (OperationCanceledException) { }
            cleaned = DeleteTestFile(path, folder);
        }

        var outcome = errors > 0 ? DiskSpeedOutcome.DataErrors
            : st.Stop == StopHot ? DiskSpeedOutcome.Overheated
            : st.Stop == StopUser || cancellationToken.IsCancellationRequested ? DiskSpeedOutcome.StoppedByUser
            : failed ? DiskSpeedOutcome.Failed
            : verified == 0 || IsSlow(o, sw, sr, rr) ? DiskSpeedOutcome.SlowDrive
            : DiskSpeedOutcome.Passed;
        var report = new DiskSpeedReport(outcome, drive.DisplayName, size, clk.Elapsed - start, sw, sr, rw, rr, verified, errors, st.MaxDriveTemp, cleaned);
        log?.Invoke($"Disk speed: done outcome={outcome} seqW={sw:0.0}MB/s seqR={sr:0.0}MB/s randW={rw:0}IOPS randR={rr:0}IOPS verified={verified} errors={errors} cleaned={cleaned}");
        return report;
    }

    private (double?, double?, double?, double?, long, long) RunIo(string path, long size, DiskSpeedOptions o, State st, IStressClock clk, TimeSpan start, TimeSpan duration, CancellationToken ct)
    {
        bool Halt()
        {
            if (st.Stop != StopNone) return true;
            if (ct.IsCancellationRequested) { st.Stop = StopUser; return true; }
            return clk.Elapsed - start >= duration;
        }

        fs.CreateDirectory(Path.GetDirectoryName(path)!);
        var runSeed = (ulong)Random.Shared.NextInt64() | 1UL;
        int block = o.SequentialBlockBytes, pagesPerBlock = block / PageBytes;
        var buf = new AlignedBuffer(block);
        var expect = new byte[PageBytes];
        long verified = 0, errors = 0;
        bool Verify(ReadOnlySpan<byte> page, long pageIndex, int gen)
        {
            FillPage(expect, runSeed, pageIndex, gen);
            verified++;
            if (page.SequenceEqual(expect)) return true;
            if (++errors <= 10) log?.Invoke($"Disk speed: data mismatch at offset {pageIndex * PageBytes} (generation {gen})");
            return false;
        }

        using var stream = fs.OpenTestFile(path, size);

        // Sequential write (reserve half the time budget after the first block so sequential read-back can verify).
        st.Phase = DiskSpeedPhase.SequentialWrite;
        long written = 0; var tw = TimeSpan.Zero; var writeLimit = duration / 2;
        for (long off = 0; off < size && !Halt() && (off == 0 || clk.Elapsed - start < writeLimit); off += block)
        {
            for (int p = 0; p < pagesPerBlock; p++) FillPage(buf.Span.Slice(p * PageBytes, PageBytes), runSeed, off / PageBytes + p, 0);
            var t0 = clk.Elapsed;
            stream.Position = off;
            stream.Write(buf.Span);
            tw += clk.Elapsed - t0;
            written = off + block;
            st.PhaseFraction = (double)written / size;
        }
        var t1 = clk.Elapsed; stream.Flush(); tw += clk.Elapsed - t1;
        double? seqW = MBps(written, tw);

        // Sequential read-back with verification.
        st.Phase = DiskSpeedPhase.SequentialRead;
        long read = 0; var tr = TimeSpan.Zero;
        for (long off = 0; off < written && !Halt(); off += block)
        {
            var t0 = clk.Elapsed;
            stream.Position = off;
            stream.ReadExactly(buf.Span);
            tr += clk.Elapsed - t0;
            for (int p = 0; p < pagesPerBlock; p++) Verify(buf.Span.Slice(p * PageBytes, PageBytes), off / PageBytes + p, 0);
            read = off + block;
            st.PhaseFraction = (double)read / written;
        }
        double? seqR = MBps(read, tr);

        // Random 4 KB writes then reads (verified against what each page should now contain).
        long pages = written / PageBytes;
        var gen1 = new HashSet<long>();
        double? randW = null, randR = null;
        if (pages > 0)
        {
            var rng = new Random(unchecked((int)runSeed));
            var page = buf.Slice(PageBytes);
            TimeSpan Budget() { var left = duration - (clk.Elapsed - start); return left / 2 < o.MaxRandomPhase ? left / 2 : o.MaxRandomPhase; }

            st.Phase = DiskSpeedPhase.RandomWrite;
            var phaseStart = clk.Elapsed; var budget = Budget(); long ops = 0; var trw = TimeSpan.Zero;
            while (!Halt() && clk.Elapsed - phaseStart < budget)
            {
                var pi = rng.NextInt64(pages);
                FillPage(page, runSeed, pi, 1);
                var t0 = clk.Elapsed;
                stream.Position = pi * PageBytes;
                stream.Write(page);
                trw += clk.Elapsed - t0;
                gen1.Add(pi); ops++;
                st.PhaseFraction = budget > TimeSpan.Zero ? Math.Min(1, (clk.Elapsed - phaseStart) / budget) : 1;
            }
            randW = Iops(ops, trw);

            st.Phase = DiskSpeedPhase.RandomRead;
            phaseStart = clk.Elapsed; var left = duration - (clk.Elapsed - start); budget = left < o.MaxRandomPhase ? left : o.MaxRandomPhase; ops = 0; var trr = TimeSpan.Zero;
            while (!Halt() && clk.Elapsed - phaseStart < budget)
            {
                var pi = rng.NextInt64(pages);
                var t0 = clk.Elapsed;
                stream.Position = pi * PageBytes;
                stream.ReadExactly(page);
                trr += clk.Elapsed - t0;
                Verify(page, pi, gen1.Contains(pi) ? 1 : 0);
                ops++;
                st.PhaseFraction = budget > TimeSpan.Zero ? Math.Min(1, (clk.Elapsed - phaseStart) / budget) : 1;
            }
            randR = Iops(ops, trr);
        }
        return (seqW, seqR, randW, randR, verified, errors);
    }

    private async Task MonitorAsync(State st, IStressClock clk, TimeSpan start, TimeSpan duration, DiskSpeedOptions o, bool sensorsOk,
        IProgress<DiskSpeedProgress>? progress, CancellationToken user, CancellationToken stop)
    {
        while (!stop.IsCancellationRequested)
        {
            if (sensorsOk)
            {
                var (temp, fan, critical, what) = ReadSensors();
                st.DriveTemp = temp; st.Fan = fan;
                if (temp is { } t) st.MaxDriveTemp = Math.Max(st.MaxDriveTemp ?? t, t);
                if (critical && st.Stop == StopNone) { st.Stop = StopHot; log?.Invoke($"Disk speed: abort, critical temperature: {what}"); }
            }
            if (user.IsCancellationRequested && st.Stop == StopNone) st.Stop = StopUser;
            progress?.Report(new DiskSpeedProgress(st.Phase, clk.Elapsed - start, duration, st.PhaseFraction, st.DriveTemp, st.Fan, sensorsOk));
            try { await clk.DelayAsync(o.SampleInterval, stop).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    /// <summary>Removes test files left behind by an earlier crash. Only names matching <see cref="TempFilePattern"/> in the test folder.</summary>
    private void CleanupStale(string folder)
    {
        try
        {
            foreach (var f in fs.FindFiles(folder, TempFilePattern))
            {
                if (!Path.GetFileName(f).StartsWith(TempFilePrefix, StringComparison.OrdinalIgnoreCase)) continue;
                try { fs.DeleteFile(f); log?.Invoke($"Disk speed: removed leftover test file {f}"); }
                catch (Exception ex) { log?.Invoke($"Disk speed: couldn't remove leftover {f}: {ex.Message}"); }
            }
        }
        catch (Exception ex) { log?.Invoke($"Disk speed: leftover scan failed: {ex.Message}"); }
    }

    private bool DeleteTestFile(string path, string folder)
    {
        for (int i = 0; i < 3; i++)
        {
            try
            {
                if (fs.FileExists(path)) fs.DeleteFile(path);
                try { fs.DeleteDirectoryIfEmpty(folder); } catch (Exception ex) { log?.Invoke($"Disk speed: folder cleanup: {ex.Message}"); }
                return !fs.FileExists(path);
            }
            catch (Exception ex) { log?.Invoke($"Disk speed: delete attempt {i + 1} failed: {ex.Message}"); Thread.Sleep(200); }
        }
        return false;
    }

    private bool SafeAvailability()
    {
        try { var a = sensors.CheckAvailability(); if (!a.IsAvailable) log?.Invoke($"Disk speed: sensors unavailable: {a.Reason}"); return a.IsAvailable; }
        catch (Exception ex) { log?.Invoke($"Disk speed: sensor availability failed: {ex.Message}"); return false; }
    }

    /// <summary>Hottest drive temperature, fastest fan, and whether any temperature (drive or other) is critical.</summary>
    private (double? Temp, double? Fan, bool Critical, string What) ReadSensors()
    {
        try
        {
            var snap = sensors.Read();
            var temps = snap.Readings.Where(r => r.SensorType == SensorKind.Temperature && r.IsLive).ToList();
            var drive = temps.Where(r => r.HardwareType == HardwareKind.Storage).Select(r => r.Value).DefaultIfEmpty().Max();
            var fan = snap.Readings.Where(r => r.SensorType == SensorKind.Fan && r.HasData).Select(r => r.Value).DefaultIfEmpty().Max();
            var crit = temps.FirstOrDefault(r => SensorThresholds.Evaluate(r) == SensorLevel.Critical);
            return (drive, fan, crit is not null, crit is null ? "" : $"{crit.HardwareName} {crit.SensorName} {crit.Value:0.0}°C");
        }
        catch (Exception ex)
        {
            log?.Invoke($"Disk speed: sensor read failed: {ex.Message}");
            return (null, null, false, "");
        }
    }

    private static DiskSpeedReport Empty(DiskSpeedOutcome o, string drive, TimeSpan ran) => new(o, drive, 0, ran, null, null, null, null, 0, 0, null, true);
}
