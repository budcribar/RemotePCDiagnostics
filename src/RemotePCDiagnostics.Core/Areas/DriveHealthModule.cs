using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One physical drive's health (Windows Storage: MSFT_PhysicalDisk + storage reliability counters). Strings as reported.</summary>
public sealed record DriveHealth(
    string Name, string Serial, string MediaType, string BusType, string Health, string Operational,
    long? SizeBytes, int? TemperatureC, int? Wear, long? ReadErrors, long? WriteErrors, long? PowerOnHours,
    string Letters = "", string UniqueId = "", int? SpindleSpeedRpm = null)
{
    public static DriveHealth FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("Name"), r.Str("Serial"), r.Str("MediaType"), r.Str("BusType"), r.Str("Health"), r.Str("Operational"),
        r.Long("Size") is > 0 and var size ? size : null, Range(r.Int("Temperature"), 1, 150), Range(r.Int("Wear"), 0, 100),
        NonNegative(r.Long("ReadErrors")), NonNegative(r.Long("WriteErrors")), NonNegative(r.Long("PowerOnHours")), r.Str("Letters"), r.Str("Id"));

    /// <summary>True when Windows identifies the disk as a spinning hard drive (MediaType HDD, or Unspecified with SpindleSpeed &gt; 0).</summary>
    public bool IsSpinningHdd =>
        string.Equals(MediaType, "HDD", StringComparison.OrdinalIgnoreCase)
        || (string.Equals(MediaType, "Unspecified", StringComparison.OrdinalIgnoreCase) && SpindleSpeedRpm is > 0);

    // A counter outside what a drive can report is a bad reading, not a value to show (or to warn on).
    internal static int? Range(long? v, int min, int max) => v is { } x && x >= min && x <= max ? (int)x : null;
    internal static long? NonNegative(long? v) => v is >= 0 ? v : null;

    /// <summary>The raw id the instance key is hashed from: the serial number (also known to the osquery fallback), else the storage
    /// UniqueId (WWN/EUI), else the name. Never the disk number, which changes when drives are added.</summary>
    public string RawId => Serial.Trim() is { Length: > 0 } s ? "serial:" + s : UniqueId.Trim() is { Length: > 0 } u ? "id:" + u : "name:" + Name;

    public string Label => (Name.Length > 0 ? Name : "Drive") + (SizeBytes is > 0 ? ", " + HardwareInventory.FormatBytes(SizeBytes) : "")
        + (Letters.Length > 0 ? " (" + string.Join(", ", Letters.Select(c => c + ":")) + ")" : "");

    public const int HotC = 60, WornPercent = 90;

    public AreaLevel Level
    {
        get
        {
            if (Health.Equals("Unhealthy", StringComparison.OrdinalIgnoreCase)) return AreaLevel.Error;
            if (Health.Equals("Warning", StringComparison.OrdinalIgnoreCase)) return AreaLevel.Warning;
            if (ReadErrors is > 0 || WriteErrors is > 0 || Wear >= WornPercent || TemperatureC >= HotC) return AreaLevel.Warning;
            return Health.Equals("Healthy", StringComparison.OrdinalIgnoreCase) ? AreaLevel.Ok : AreaLevel.Neutral;
        }
    }

    public string Verdict => Level switch
    {
        AreaLevel.Error => "Failing – back up your files now",
        AreaLevel.Warning => "Needs attention",
        AreaLevel.Ok => "Healthy",
        _ => "Health not reported",
    };

    public IEnumerable<string> Reasons()
    {
        if (Health.Equals("Unhealthy", StringComparison.OrdinalIgnoreCase)) yield return "Windows reports this drive as failing";
        else if (Health.Equals("Warning", StringComparison.OrdinalIgnoreCase)) yield return "Windows reports a warning for this drive";
        if (ReadErrors is > 0 || WriteErrors is > 0) yield return "it has had read/write errors it couldn't correct";
        if (Wear >= WornPercent) yield return $"about {Wear}% of its rated life is used";
        if (TemperatureC >= HotC) yield return $"it is running hot ({TemperatureC}°C)";
    }

    public string Kind => MediaType switch
    {
        "SSD" => "SSD",
        "HDD" => "Hard drive",
        "SCM" => "Storage-class memory",
        _ when SpindleSpeedRpm is > 0 => "Hard drive",
        _ => BusType.Equals("NVMe", StringComparison.OrdinalIgnoreCase) ? "SSD" : "Drive",
    };
}

/// <summary>
/// Drive health from <paramref name="drives"/>: Windows Storage WMI through the Agent in the app (<see cref="WmiDriveSource"/>; the Agent
/// can read the reliability counters), the app's own source in the module host (<see cref="HostDriveSource"/>), and in the Store edition the
/// legacy Get-PhysicalDisk / osquery reader when no Agent is connected.
/// One instance per physical drive (keyed on <see cref="DriveHealth.RawId"/>); the page still shows one report with a card per drive
/// (<see cref="Combine"/>). One drive read serves every drive of a run.
/// Free space is read with the drives (<see cref="DriveVolumes"/>): each volume counts for the drive it is on, so a drive with a
/// nearly full volume needs attention, in its own result as well as in the report.
/// </summary>
public sealed class DriveHealthModule(IDriveSource drives, IRetrimHistory? retrims = null, Func<DateTimeOffset>? clock = null,
    IDriveHealthHistoryStore? historyStore = null, Func<IReadOnlyList<DriveCapacityInfo>>? volumes = null, ILogger? log = null,
    DataSources.IRegistrySource? registry = null, TimeSpan? reuseReadFor = null)
    : AreaModuleBase(log), IPerDeviceModule, IInstanceSummary, IHasAreaPanels
{
    private readonly IDriveHealthHistoryStore _history = historyStore ?? new DriveHealthHistoryStore(DriveHealthHistoryStore.DefaultPath(), log);
    public AreaPanels Panels => AreaPanels.StorageCleanup;
    /// <summary>The instance used when the drive list itself can't be read, so the failure is still reported as a run.</summary>
    public const string AllDrivesKey = "all";
    /// <summary>Explains which temperature Windows reports, so it can be matched with Temperatures &amp; fans.</summary>
    public const string TemperatureDetail = "The drive's overall temperature as Windows reports it (NVMe composite). Temperatures & fans shows the same overall value and, when one runs hotter, the drive's hottest internal sensor (often the controller).";
    /// <summary>A drive read this recent is reused by the next drive of the same run.</summary>
    public static readonly TimeSpan ReuseReadFor = TimeSpan.FromSeconds(20);
    /// <summary>"Optimize / Retrim SSD" is offered only when a volume of the SSD wasn't retrimmed in this long (or the date is unknown).</summary>
    public static readonly TimeSpan RetrimFreshFor = TimeSpan.FromDays(30);

    public const string ModuleName = ModuleSlugs.DriveHealth;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DriveHealth;
    public override string DisplayName => "Drive health & free space";
    protected override string FailedMessage => "Couldn't check drive health on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var read = await ReadDrivesAsync(progress, ct).ConfigureAwait(false);
        if (read.Drives is null) return AreaReport.Failed(FailedMessage);
        var storageSense = registry is not null ? await StorageSenseReader.ReadAsync(registry, ct).ConfigureAwait(false) : null;
        return BuildReport(read.Drives, read.Retrims, read.Now, _history, read.Volumes, capacityCard: true, storageSense: storageSense) with { Notice = read.Notice };
    }

    /// <summary>The drives as last read: health (or the osquery list with <see cref="Notice"/>), retrim dates, and when.</summary>
    private sealed record DriveRead(List<DriveHealth>? Drives, IReadOnlyDictionary<char, RetrimRecord>? Retrims, DateTimeOffset Now, string? Notice, DateTimeOffset ReadAt)
    {
        /// <summary>The volumes read with the drives, each with the drive it is on.</summary>
        public DriveVolumeMap Volumes { get; init; } = DriveVolumeMap.None;
    }

    private sealed class SharedRead
    {
        public readonly CancellationTokenSource Cts = new();
        public readonly DateTimeOffset StartedAt;
        public readonly Task<DriveRead> Task;
        public int Waiters;

        public SharedRead(DateTimeOffset startedAt, Func<CancellationToken, Task<DriveRead>> start)
        {
            StartedAt = startedAt;
            var cts = Cts;
            Task = start(cts.Token);
            _ = Task.ContinueWith(_ => cts.Dispose(), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    private DateTimeOffset Now() => (clock ?? (() => DateTimeOffset.Now))();

    private readonly object _readGate = new();
    private SharedRead? _sharedRead;
    private volatile DriveRead? _latest;

    /// <summary>
    /// Reads every drive once; a read finished (or started) in the last <see cref="ReuseReadFor"/> (or <c>reuseReadFor</c>: zero in the
    /// replay tests, whose clock stands still at the recording's time) is shared.
    /// </summary>
    private async Task<DriveRead> ReadDrivesCachedAsync(IProgress<string>? progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        SharedRead shared;
        lock (_readGate)
        {
            var now = Now();
            if (_sharedRead is { Task: { IsFaulted: false, IsCanceled: false } } existing && now - existing.StartedAt < (reuseReadFor ?? ReuseReadFor))
                shared = existing;
            else
                shared = _sharedRead = new SharedRead(now, token => ReadDrivesAsync(progress, token));
            shared.Waiters++;
        }
        var decremented = false;
        try
        {
            return ct.CanBeCanceled ? await shared.Task.WaitAsync(ct).ConfigureAwait(false) : await shared.Task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            CancellationTokenSource? toCancel = null;
            lock (_readGate)
            {
                decremented = true;
                if (--shared.Waiters == 0 && !shared.Task.IsCompleted)
                {
                    if (ReferenceEquals(_sharedRead, shared)) _sharedRead = null;
                    toCancel = shared.Cts;
                }
            }
            if (toCancel is not null)
            {
                try { toCancel.Cancel(); } catch (ObjectDisposedException) { }
            }
            throw;
        }
        finally
        {
            if (!decremented)
            {
                lock (_readGate) shared.Waiters--;
            }
        }
    }

    private async Task<DriveRead> ReadDrivesAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var read = await ReadDrivesCoreAsync(progress, ct).ConfigureAwait(false);
        if (read.Drives is { Count: > 0 } drives)
            read = read with { Volumes = DriveVolumeMap.Assign(drives, await ReadVolumesAsync(ct).ConfigureAwait(false)) };
        _latest = read;
        return read;
    }

    /// <summary>Free space per volume. Never fails the drive read: without it the report just has no free space.</summary>
    private async Task<IReadOnlyList<DriveCapacityInfo>> ReadVolumesAsync(CancellationToken ct)
    {
        var read = volumes ?? (() => DriveVolumes.ReadLocal(Logger));
        try { return await Task.Run(read, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn($"{Name}: free space not read: {ex.Message}");
            return [];
        }
    }

    private async Task<DriveRead> ReadDrivesCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var now = Now();
        progress.ReportStep(1, 2, "Checking drive health and SMART status…");
        var list = await drives.ReadDrivesAsync(ct).ConfigureAwait(false);
        if (list is not { Drives.Count: > 0 })
        {
            LogWarn($"{Name}: the drives couldn't be read");
            return new(null, null, now, null, now);
        }
        var found = list.Drives.ToList();
        // A list without health (the legacy osquery list, with its notice) isn't a health reading.
        if (list.Notice is null) _history.Record(found, now);
        progress.ReportStep(2, 2, "Checking SSD optimization history…");
        return new(found, await ReadRetrimsAsync(ct).ConfigureAwait(false), now, list.Notice, now);
    }


    /// <summary>Each drive's instance key, made unique when two drives report the same serial (some USB enclosures do).</summary>
    public static IReadOnlyList<(DriveHealth Drive, ModuleInstance Instance)> Instances(IReadOnlyList<DriveHealth> drives)
    {
        var seen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        return drives.Select(d =>
        {
            var raw = d.RawId;
            var n = seen[raw] = seen.GetValueOrDefault(raw) + 1;
            return (d, new ModuleInstance(InstanceKeys.From(n == 1 ? raw : raw + "#" + n), d.Label));
        }).ToList();
    }

    /// <summary>Reads the drive list (and their health: the same read the first drive's run then reuses). Never throws.</summary>
    public async Task<ModuleDetection> DetectAsync(CancellationToken ct = default)
    {
        DriveRead read;
        try { read = await ReadDrivesCachedAsync(null, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            LogWarn($"{Name}: drive list failed: {ex.Message}");
            read = new(null, null, DateTimeOffset.Now, null, DateTimeOffset.Now);
        }
        // Still listed when the drives can't be read, so the run reports why instead of the test vanishing.
        if (read.Drives is null) return ModuleDetection.For([new ModuleInstance(AllDrivesKey, "All drives")]);
        return read.Drives.Count == 0 ? ModuleDetection.NotApplicable("No drives found") : ModuleDetection.For(Instances(read.Drives).Select(x => x.Instance));
    }

    public async Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        if (instance.Key == AllDrivesKey) return await RefreshAsync(progress, cancellationToken).ConfigureAwait(false);
        AreaReport report;
        string? volumeText = null;
        try
        {
            var read = await ReadDrivesCachedAsync(progress, cancellationToken).ConfigureAwait(false);
            if (read.Drives is null) report = AreaReport.Failed(FailedMessage);
            else if (Instances(read.Drives).FirstOrDefault(x => x.Instance.Key == instance.Key) is { Drive: { } drive })
            {
                // This drive only: its own volumes count for it, and the capacity table of every volume belongs to the combined report.
                report = BuildReport([drive], read.Retrims, read.Now, _history, read.Volumes, capacityCard: false) with { Notice = read.Notice };
                volumeText = VolumeText(read.Volumes.Of(drive));
            }
            else return CouldNotRun.Result(Name, $"{instance.Label} is no longer connected.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            LogError($"{Name}: collection failed: {ex}");
            report = AreaReport.Failed(FailedMessage);
        }
        var card = report.Cards.FirstOrDefault();
        // The verdict and the drive's free space ("Healthy · 120 GB free on C:"): this line is what the Checks list and History show.
        var message = card is null ? report.Summary : volumeText is null ? card.Headline : $"{card.Headline} · {volumeText}";
        return new DiagnosticResult<AreaReport>(Name, report.Status, message, DateTimeOffset.Now, report);
    }

    /// <summary>One report with a card per drive (the page and the fix list read this), rebuilt from the latest drive read so the
    /// summary, the one "Clean up temporary files" action and the card ids come out as for a single read.</summary>
    public object? Combine(IReadOnlyList<DiagnosticResult> instanceResults)
    {
        if (instanceResults.Count == 1 && instanceResults[0].InstanceKey == AllDrivesKey) return instanceResults[0].Payload;
        if (_latest is not { Drives: { } drives } read) return null;
        var byKey = Instances(drives).ToDictionary(x => x.Instance.Key, x => x.Drive);
        var shown = instanceResults.Select(r => r.InstanceKey is { } k ? byKey.GetValueOrDefault(k) : null).OfType<DriveHealth>().ToList();
        // Free space as read with the drives: the same numbers each drive's own result was judged on.
        return shown.Count == 0 ? null : BuildReport(shown, read.Retrims, read.Now, _history, read.Volumes, capacityCard: true) with { Notice = read.Notice };
    }

    private async Task<IReadOnlyDictionary<char, RetrimRecord>?> ReadRetrimsAsync(CancellationToken ct)
    {
        if (retrims is null) return null;
        try { return await retrims.LatestAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"{Name}: last retrim unknown: {ex.Message}"); return null; }
    }

    /// <summary>True when every letter was retrimmed within <see cref="RetrimFreshFor"/>; unknown letters count as not recent.</summary>
    public static bool RecentlyRetrimmed(string letters, IReadOnlyDictionary<char, RetrimRecord>? retrims, DateTimeOffset now) =>
        letters.Length > 0 && retrims is not null && letters.All(c => retrims.TryGetValue(c, out var r) && now - r.When < RetrimFreshFor);

    /// <summary>"6 days ago (by Windows)"; per letter when they differ ("C: today (by this app); D: Not reported").</summary>
    public static string LastOptimizedText(string letters, IReadOnlyDictionary<char, RetrimRecord>? retrims, DateTimeOffset now)
    {
        string One(char c) => retrims is not null && retrims.TryGetValue(c, out var r) ? $"{Ago(r.When, now)} ({r.SourceText})" : "Not reported";
        var parts = letters.Select(c => (c, t: One(c))).ToList();
        return parts.Select(p => p.t).Distinct().Count() <= 1 ? parts.FirstOrDefault().t ?? "Not reported" : string.Join("; ", parts.Select(p => $"{p.c}: {p.t}"));
    }

    private static string Ago(DateTimeOffset when, DateTimeOffset now)
    {
        var days = (int)Math.Floor((now - when).TotalDays);
        return days <= 0 ? "today" : days == 1 ? "yesterday" : $"{days} days ago";
    }

    /// <summary>Id of the card listing every volume's capacity. The other cards are the drives ("drive0", "drive1", …).</summary>
    public const string CapacityCardId = "capacity";

    /// <summary>"120 GB free on C:", "300 GB free on C: and D:", or what is nearly full; null for a drive with no volume known.</summary>
    public static string? VolumeText(IReadOnlyList<DriveCapacityInfo> volumes)
    {
        if (volumes.Count == 0) return null;
        var low = volumes.Where(v => v.IsLowOnSpace).ToList();
        if (low.Count > 0) return string.Join("; ", low.Select(v => v.NearlyFullText));
        var free = HardwareInventory.FormatBytes(volumes.Sum(v => v.FreeBytes));
        return volumes.Count == 1 ? $"{free} free on {volumes[0].Letter}" : $"{free} free on {string.Join(", ", volumes.Take(volumes.Count - 1).Select(v => v.Letter))} and {volumes[^1].Letter}";
    }

    public const string HddBootWarning = "Windows is on a spinning hard drive. An SSD is the single biggest speed-up.";

    internal static char ReadSystemDriveLetter()
    {
        var env = Environment.GetEnvironmentVariable("SystemDrive");
        return env is { Length: >= 1 } && char.IsAsciiLetter(env[0]) ? char.ToUpperInvariant(env[0]) : 'C';
    }

    /// <summary>One report of <paramref name="drives"/>. With <paramref name="capacities"/> (the PC's volumes) each volume counts for
    /// the drive it is on, and a "Drive Capacity" card lists them all first.</summary>
    public static AreaReport Build(
        IReadOnlyList<DriveHealth> drives,
        IReadOnlyDictionary<char, RetrimRecord>? retrims = null,
        DateTimeOffset? now = null,
        IDriveHealthHistoryStore? historyStore = null,
        IReadOnlyList<DriveCapacityInfo>? capacities = null,
        char? systemDriveLetter = null,
        StorageSenseStatus? storageSense = null) =>
        BuildReport(drives, retrims, now ?? DateTimeOffset.Now, historyStore, DriveVolumeMap.Assign(drives, capacities ?? []), capacityCard: true, systemDriveLetter: systemDriveLetter, storageSense: storageSense);

    /// <param name="volumes">The PC's volumes by drive (of every drive read, also when <paramref name="drives"/> is only some of them).</param>
    /// <param name="capacityCard">False for one drive's own result: no table of every volume, and no other drive's volume counts.</param>
    private static AreaReport BuildReport(
        IReadOnlyList<DriveHealth> drives,
        IReadOnlyDictionary<char, RetrimRecord>? retrims,
        DateTimeOffset timestamp,
        IDriveHealthHistoryStore? historyStore,
        DriveVolumeMap volumes,
        bool capacityCard,
        char? systemDriveLetter = null,
        StorageSenseStatus? storageSense = null)
    {
        if (drives.Count == 0)
            return new([], "No drives were found to check.", DiagnosticStatus.Warning);
        var sysLetter = char.ToUpperInvariant(systemDriveLetter ?? ReadSystemDriveLetter());
        string[] cols = ["Detail", "Value"];
        var cards = drives.Select((d, i) =>
        {
            var trend = historyStore?.AnalyzeTrend(d.RawId, d, timestamp);
            var level = d.Level;
            var verdict = d.Verdict;
            var reasons = d.Reasons().ToList();
            if (trend is { IsDegrading: true })
            {
                if (level < AreaLevel.Warning) level = AreaLevel.Warning;
                verdict = "Degrading – check errors and back up files";
                reasons.Insert(0, trend.SummaryText);
            }

            // A nearly full volume makes its drive need attention; it never outranks a failing drive.
            var own = volumes.Of(d);
            var nearlyFull = own.Where(v => v.IsLowOnSpace).ToList();
            if (nearlyFull.Count > 0)
            {
                if (level < AreaLevel.Warning) { level = AreaLevel.Warning; verdict = "Needs attention"; }
                reasons.AddRange(nearlyFull.Select(v => v.NearlyFullText));
            }

            var holdsSystemDrive = d.Letters.Any(c => char.ToUpperInvariant(c) == sysLetter)
                || own.Any(v => v.Letter.Length > 0 && char.ToUpperInvariant(v.Letter[0]) == sysLetter);
            var bootOnHdd = holdsSystemDrive && d.IsSpinningHdd;
            if (bootOnHdd)
            {
                if (level < AreaLevel.Warning) { level = AreaLevel.Warning; verdict = "Needs attention"; }
                reasons.Add(HddBootWarning);
            }

            var meta = string.Join(" · ", new[]
            {
                d.Kind, d.SizeBytes is > 0 ? HardwareInventory.FormatBytes(d.SizeBytes) : null,
                own.Count > 0 ? $"{HardwareInventory.FormatBytes(own.Sum(v => v.FreeBytes))} free" : null,
                d.TemperatureC is > 0 ? $"{d.TemperatureC}°C" : null, d.Wear is not null ? $"{d.Wear}% worn" : null,
                trend is { IsDegrading: true } ? "Degrading" : null,
            }.Where(x => x is not null));
            var rows = new List<AreaRow>();
            void Add(string label, string? v, AreaLevel l = AreaLevel.Neutral, string? detail = null) { if (!string.IsNullOrWhiteSpace(v)) rows.Add(new(l, [label, v], Detail: detail)); }
            Add("Overall", verdict + (reasons.Count > 0 ? ": " + string.Join("; ", reasons) : ""), level);
            Add("Status reported by Windows", d.Health.Length > 0 ? $"{d.Health}{(d.Operational.Length > 0 && d.Operational != "OK" ? $" ({d.Operational})" : "")}" : "Not reported");
            if (trend is not null)
                Add("Health trend", trend.SummaryText, trend.IsDegrading ? AreaLevel.Warning : AreaLevel.Neutral, detail: trend.HistoryDetail);
            Add("Type", d.Kind, bootOnHdd ? AreaLevel.Warning : AreaLevel.Neutral);
            if (bootOnHdd)
                Add("Windows boot drive", HddBootWarning, AreaLevel.Warning);
            Add("Connection", d.BusType);
            Add("Size", d.SizeBytes is > 0 ? HardwareInventory.FormatBytes(d.SizeBytes) : null);
            foreach (var vol in own)
                Add($"Volume {vol.Letter}", $"{HardwareInventory.FormatBytes(vol.FreeBytes)} free of {HardwareInventory.FormatBytes(vol.TotalBytes)} ({vol.UsedPercent:0.#}% used · {vol.DriveFormat})",
                    vol.IsLowOnSpace ? AreaLevel.Warning : AreaLevel.Neutral);
            Add("Temperature", d.TemperatureC is > 0 ? $"{d.TemperatureC}°C" : "Not reported", d.TemperatureC >= DriveHealth.HotC ? AreaLevel.Warning : AreaLevel.Neutral,
                detail: d.TemperatureC is > 0 ? TemperatureDetail : null);
            Add("Life used", d.Wear is not null ? $"{d.Wear}%" : "Not reported", d.Wear >= DriveHealth.WornPercent ? AreaLevel.Warning : AreaLevel.Neutral);
            Add("Uncorrected read errors", d.ReadErrors?.ToString(CultureInfo.InvariantCulture) ?? "Not reported", d.ReadErrors is > 0 ? AreaLevel.Warning : AreaLevel.Neutral);
            Add("Uncorrected write errors", d.WriteErrors?.ToString(CultureInfo.InvariantCulture) ?? "Not reported", d.WriteErrors is > 0 ? AreaLevel.Warning : AreaLevel.Neutral);
            Add("Hours powered on", d.PowerOnHours is >= 0 ? d.PowerOnHours.Value.ToString("N0", CultureInfo.InvariantCulture) : "Not reported");
            var ssdLetters = d.Kind == "SSD" ? RemediationService.DriveLetters(d.Letters) : "";
            if (ssdLetters.Length > 0) Add("Last optimized", LastOptimizedText(ssdLetters, retrims, timestamp));
            Add("Serial number", d.Serial);
            var actions = new List<AreaAction>();
            if (i == 0)
                actions.Add(new(RemediationKind.CleanTempFiles, "Clean up temporary files", "", "Temporary files & Recycle Bin"));
            // Not offered when Windows or this app retrimmed every volume of this SSD in the last 30 days.
            var dueLetters = new string(ssdLetters.Where(letter =>
                !RecentlyRetrimmed(letter.ToString(), retrims, timestamp)).ToArray());
            if (dueLetters.Length > 0)
                actions.Add(new(RemediationKind.OptimizeSsd, "Optimize / Retrim SSD", dueLetters, d.Name.Length > 0 ? d.Name : "SSD"));
            return new AreaCard($"drive{i}", d.Name.Length > 0 ? d.Name : $"Drive {i + 1}", level, verdict, meta, cols, rows,
                Note: bootOnHdd ? HddBootWarning : null,
                Actions: actions.Count > 0 ? actions : null);
        }).ToList();

        var degrading = drives.Count(d => historyStore?.AnalyzeTrend(d.RawId, d, timestamp).IsDegrading == true);
        // Drives only: the capacity card repeats what its drives' cards already say, so it is never counted as a drive.
        var bad = cards.Count(c => c.Level is AreaLevel.Warning or AreaLevel.Error);
        var unknown = cards.All(c => c.Level == AreaLevel.Neutral);
        var freePart = "";
        if (capacityCard && volumes.All.Count > 0)
        {
            cards.Insert(0, DiskSpaceModule.BuildDriveCapacityCard(volumes.All, CapacityCardId));
            var free = HardwareInventory.FormatBytes(volumes.All.Sum(v => v.FreeBytes));
            freePart = volumes.All.Count == 1 ? $" · {free} free on {volumes.All[0].Letter}" : $" · {free} free across {volumes.All.Count} volumes";
            // A nearly full volume on no known drive (Windows gave no drive letters): the capacity card alone carries its warning.
            if (volumes.Unassigned.Where(v => v.IsLowOnSpace).Select(v => v.Letter).ToList() is { Count: > 0 } adrift)
                freePart += $" · {string.Join(", ", adrift)} nearly full";
        }
        if (capacityCard && storageSense is not null)
            cards.Add(BuildStorageSenseCard(storageSense));
        var summary = bad > 0 ? $"{bad} of {Plural(drives.Count, "drive")} need{(bad == 1 ? "s" : "")} attention{freePart}"
            : unknown ? $"{Plural(drives.Count, "drive")} found · health not reported{freePart}"
            : drives.Count == 1 ? $"1 drive · healthy{freePart}" : $"{drives.Count} drives · all healthy{freePart}";
        if (degrading > 0)
            summary = $"{summary} ({Plural(degrading, "drive")} getting worse)";
        // One drive's own result (each drive is its own History series): free space, life used and media errors over time.
        return new(cards, summary, AreaReport.Worst(cards.Select(c => c.Level))) { KeyMetrics = drives.Count == 1 ? KeyMetrics(drives[0], volumes.Of(drives[0])) : null };
    }

    public static AreaCard BuildStorageSenseCard(StorageSenseStatus ss)
    {
        var level = ss.Enabled ? AreaLevel.Ok : AreaLevel.Neutral;
        var headline = ss.Enabled
            ? (ss.PolicyControlled ? "Storage Sense is on (managed by policy)" : "Storage Sense is on")
            : (ss.PolicyControlled ? "Storage Sense is off (managed by policy)" : "Storage Sense is off");
        var rows = new List<AreaRow>
        {
            new(level, ["Status", ss.Enabled ? "On" : "Off"]),
            new(AreaLevel.Neutral, ["Schedule", ss.CadenceText]),
            new(AreaLevel.Neutral, ["Temporary files", ss.TempFilesText]),
            new(AreaLevel.Neutral, ["Recycle Bin", ss.RecycleBinText]),
            new(AreaLevel.Neutral, ["Downloads", ss.DownloadsText]),
        };
        if (ss.PolicyControlled)
            rows.Add(new(AreaLevel.Neutral, ["Group Policy", $"AllowStorageSenseGlobal = {ss.PolicyGlobalValue}"]));

        var actions = ss.CanOfferEnable
            ? new List<AreaAction> { new(RemediationKind.EnableStorageSense, "Turn on Storage Sense", ss.DescribeEffectiveBehavior(), "Windows Storage Sense") }
            : null;
        return new("storage-sense", "Windows Storage Sense", level, headline,
            ss.Enabled ? ss.CadenceText : "Automatic temp file cleanup is off",
            ["Detail", "Value"], rows,
            Note: ss.PolicyControlled
                ? "Storage Sense is controlled by Group Policy and cannot be changed here."
                : ss.Enabled ? null : ss.DescribeEffectiveBehavior(),
            Actions: actions);
    }

    /// <summary>What a drive's History charts: free space shrinking toward full, SMART life used and uncorrected errors climbing.</summary>
    public static IReadOnlyList<KeyMetric>? KeyMetrics(DriveHealth d, IReadOnlyList<DriveCapacityInfo> volumes)
    {
        var list = new List<KeyMetric>();
        if (volumes.Count > 0) list.Add(new("drive.free", "Free space", Math.Round(volumes.Sum(v => v.FreeBytes) / GiB, 1), "GB", MetricTrend.HigherIsBetter));
        if (d.Wear is { } wear) list.Add(new("drive.wear", "Life used", wear, "%", MetricTrend.LowerIsBetter));
        if (d.ReadErrors is not null || d.WriteErrors is not null)
            list.Add(new("drive.errors", "Uncorrected errors", (d.ReadErrors ?? 0) + (d.WriteErrors ?? 0), "", MetricTrend.LowerIsBetter));
        if (d.TemperatureC is > 0) list.Add(new("drive.temp", "Temperature", d.TemperatureC.Value, "°C", MetricTrend.LowerIsBetter));
        return list.Count > 0 ? list : null;
    }

    private const double GiB = 1024d * 1024 * 1024;
}

/// <summary>The PC's volumes and the physical drive each one is on.</summary>
public sealed class DriveVolumeMap
{
    public static readonly DriveVolumeMap None = new([], new Dictionary<DriveHealth, IReadOnlyList<DriveCapacityInfo>>(ReferenceEqualityComparer.Instance), []);

    private readonly IReadOnlyDictionary<DriveHealth, IReadOnlyList<DriveCapacityInfo>> _byDrive;

    private DriveVolumeMap(IReadOnlyList<DriveCapacityInfo> all, IReadOnlyDictionary<DriveHealth, IReadOnlyList<DriveCapacityInfo>> byDrive, IReadOnlyList<DriveCapacityInfo> unassigned)
    {
        All = all;
        _byDrive = byDrive;
        Unassigned = unassigned;
    }

    /// <summary>Every volume read, in drive letter order.</summary>
    public IReadOnlyList<DriveCapacityInfo> All { get; }

    /// <summary>Volumes on no known drive.</summary>
    public IReadOnlyList<DriveCapacityInfo> Unassigned { get; }

    /// <summary>The volumes on <paramref name="drive"/> (one of the drives given to <see cref="Assign"/>).</summary>
    public IReadOnlyList<DriveCapacityInfo> Of(DriveHealth drive) => _byDrive.GetValueOrDefault(drive) ?? [];

    /// <summary>
    /// A volume is on the drive whose letters (<see cref="DriveHealth.Letters"/>) include it. When Windows reported no letter for it
    /// and the PC has a single drive, it is on that drive; a removable volume is never guessed this way.
    /// </summary>
    public static DriveVolumeMap Assign(IReadOnlyList<DriveHealth> drives, IReadOnlyList<DriveCapacityInfo> volumes)
    {
        if (volumes.Count == 0) return None;
        var all = volumes.OrderBy(v => v.DriveName, StringComparer.OrdinalIgnoreCase).ToList();
        var letters = drives.Select(d => RemediationService.DriveLetters(d.Letters)).ToList();
        var byDrive = new Dictionary<DriveHealth, List<DriveCapacityInfo>>(ReferenceEqualityComparer.Instance);
        var unassigned = new List<DriveCapacityInfo>();
        foreach (var v in all)
        {
            var letter = v.DriveName.Length > 0 ? char.ToUpperInvariant(v.DriveName[0]) : '\0';
            var owner = letters.FindIndex(l => l.Contains(letter));
            if (owner < 0 && drives.Count == 1 && !v.Removable) owner = 0;
            if (owner < 0) { unassigned.Add(v); continue; }
            if (!byDrive.TryGetValue(drives[owner], out var list)) byDrive[drives[owner]] = list = [];
            list.Add(v);
        }
        return new(all, byDrive.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<DriveCapacityInfo>)kv.Value, (IEqualityComparer<DriveHealth>)ReferenceEqualityComparer.Instance), unassigned);
    }
}
