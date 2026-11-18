using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One physical drive's health (Windows Storage: MSFT_PhysicalDisk + storage reliability counters). Strings as reported.</summary>
public sealed record DriveHealth(
    string Name, string Serial, string MediaType, string BusType, string Health, string Operational,
    long? SizeBytes, int? TemperatureC, int? Wear, long? ReadErrors, long? WriteErrors, long? PowerOnHours, string Letters = "", string UniqueId = "")
{
    public static DriveHealth FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("Name"), r.Str("Serial"), r.Str("MediaType"), r.Str("BusType"), r.Str("Health"), r.Str("Operational"),
        r.Long("Size"), r.Int("Temperature"), r.Int("Wear"), r.Long("ReadErrors"), r.Long("WriteErrors"), r.Long("PowerOnHours"), r.Str("Letters"), r.Str("Id"));

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
        "SSD" => "SSD", "HDD" => "Hard drive", "SCM" => "Storage-class memory", _ => BusType.Equals("NVMe", StringComparison.OrdinalIgnoreCase) ? "SSD" : "Drive",
    };
}

/// <summary>
/// Drive health. osquery has no SMART table on Windows, so health comes from Windows Storage
/// (Get-PhysicalDisk HealthStatus/OperationalStatus + Get-StorageReliabilityCounter) via PowerShell.
/// If that fails, drives are listed from osquery disk_info with health marked as not reported.
/// One instance per physical drive (keyed on <see cref="DriveHealth.RawId"/>); the page still shows one report with a card per drive
/// (<see cref="Combine"/>). One drive read serves every drive of a run.
/// </summary>
/// <remarks>In user mode (the module host) <paramref name="host"/> is set: the health script and the drive list run in the app
/// (<c>storage.drives</c>, <c>osquery.select</c>), since the reliability counters need administrator rights.</remarks>
public sealed class DriveHealthModule(SystemCommandRunner commands, OsqueryRunner osquery, IRetrimHistory? retrims = null, Func<DateTimeOffset>? clock = null,
    Plugins.IHostQueries? host = null, IDriveHealthHistoryStore? historyStore = null)
    : AreaModuleBase(commands.Log ?? osquery.Options.Log), IPerDeviceModule, IInstanceSummary, IHasAreaPanels
{
    private readonly IDriveHealthHistoryStore _history = historyStore ?? new DriveHealthHistoryStore(DriveHealthHistoryStore.DefaultPath(), commands.Log ?? osquery.Options.Log);
    public AreaPanels Panels => AreaPanels.StorageCleanup;
    /// <summary>The instance used when the drive list itself can't be read, so the failure is still reported as a run.</summary>
    public const string AllDrivesKey = "all";
    /// <summary>A drive read this recent is reused by the next drive of the same run.</summary>
    public static readonly TimeSpan ReuseReadFor = TimeSpan.FromSeconds(20);
    /// <summary>"Optimize / Retrim SSD" is offered only when a volume of the SSD wasn't retrimmed in this long (or the date is unknown).</summary>
    public static readonly TimeSpan RetrimFreshFor = TimeSpan.FromDays(30);

    public const string ModuleName = ModuleSlugs.DriveHealth;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DriveHealth;
    public override string DisplayName => "Drive health & free space";
    protected override string FailedMessage => "Couldn't check drive health on this PC.";

    public static string Script => Scripts.PowerShellScripts.Get("DriveHealth");

    public static IReadOnlyList<string> Arguments => SystemCommandRunner.PowerShellArgs(Script);

    public static IReadOnlyList<DriveCapacityInfo> GetDrives()
    {
        var list = new List<DriveCapacityInfo>();
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                if (d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable))
                {
                    list.Add(new DriveCapacityInfo(
                        d.Name,
                        string.IsNullOrWhiteSpace(d.VolumeLabel) ? d.Name : d.VolumeLabel,
                        d.DriveFormat,
                        d.TotalSize,
                        d.TotalFreeSpace));
                }
            }
        }
        catch { }
        return list;
    }

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var read = await ReadDrivesAsync(progress, ct).ConfigureAwait(false);
        if (read.Drives is null) return AreaReport.Failed(FailedMessage);
        var capacities = await Task.Run(GetDrives, ct).ConfigureAwait(false);
        return Build(read.Drives, read.Retrims, read.Now, _history, capacities) with { Notice = read.Notice };
    }

    /// <summary>The drives as last read: health (or the osquery list with <see cref="Notice"/>), retrim dates, and when.</summary>
    private sealed record DriveRead(List<DriveHealth>? Drives, IReadOnlyDictionary<char, RetrimRecord>? Retrims, DateTimeOffset Now, string? Notice, DateTimeOffset ReadAt);

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

    /// <summary>Reads every drive once; a read finished (or started) in the last <see cref="ReuseReadFor"/> is shared.</summary>
    private async Task<DriveRead> ReadDrivesCachedAsync(IProgress<string>? progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        SharedRead shared;
        lock (_readGate)
        {
            var now = Now();
            if (_sharedRead is { Task: { IsFaulted: false, IsCanceled: false } } existing && now - existing.StartedAt < ReuseReadFor)
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
        _latest = read;
        return read;
    }

    private async Task<DriveRead> ReadDrivesCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var now = Now();
        progress.ReportStep(1, 2, "Checking drive health and SMART status…");
        List<DriveHealth>? drives = null;
        if (commands.ElevatedBridge is { IsConnected: true } bridge)
        {
            try
            {
                var bridgedDrives = await bridge.ReadDrivesAsync(ct).ConfigureAwait(false);
                if (bridgedDrives is { Count: > 0 })
                    drives = bridgedDrives.ToList();
            }
            catch (Exception ex)
            {
                LogWarn($"{Name}: elevated bridge ReadDrivesAsync failed: {ex.Message}");
            }
        }

        if (drives is null || drives.Count == 0)
        {
            var pr = host is null ? await commands.RunPowerShellAsync(Script, ct).ConfigureAwait(false)
                : await Plugins.HostQueryExtensions.AskAsync(host, Name, Logger, h => h.ReadDrivesAsync(ct)).ConfigureAwait(false);
            if (pr is { ExitCode: 0 })
            {
                try { drives = OsqueryJson.ParseRows(pr.StdOut).Select(DriveHealth.FromRow).ToList(); }
                catch (FormatException ex) { LogWarn($"{Name}: storage health output unreadable: {ex.Message}"); }
            }
        }
        if (drives is { Count: > 0 })
        {
            _history.Record(drives, now);
            progress.ReportStep(2, 2, "Checking SSD optimization history…");
            return new(drives, await ReadRetrimsAsync(ct).ConfigureAwait(false), now, null, now);
        }

        LogWarn($"{Name}: Windows storage health unavailable; falling back to osquery disk_info (no health data)");
        progress.ReportStep(2, 2, "Reading drive list…");
        var q = host is null ? await osquery.RunQueryAsync(HardwareInventory.DiskSql, ct).ConfigureAwait(false)
            : await Plugins.HostQueryExtensions.AskAsync(host, Name, Logger, h => h.SelectAsync(HardwareInventory.DiskSql, ct)).ConfigureAwait(false);
        if (q is not { Success: true }) return new(null, null, now, null, now);
        var fallback = q.Rows!.Select(DiskInfo.FromRow)
            .Select(d => new DriveHealth(d.HardwareModel, d.Serial, "", d.Type, "", "", d.SizeBytes, null, null, null, null, null)).ToList();
        return new(fallback, null, now, "Windows didn't report drive health on this PC, so only the drive list is shown.", now);
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
        try
        {
            var read = await ReadDrivesCachedAsync(progress, cancellationToken).ConfigureAwait(false);
            if (read.Drives is null) report = AreaReport.Failed(FailedMessage);
            else if (Instances(read.Drives).FirstOrDefault(x => x.Instance.Key == instance.Key) is { Drive: { } drive })
                report = Build([drive], read.Retrims, read.Now, _history) with { Notice = read.Notice };
            else return CouldNotRun.Result(Name, $"{instance.Label} is no longer connected.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            LogError($"{Name}: collection failed: {ex}");
            report = AreaReport.Failed(FailedMessage);
        }
        var card = report.Cards.FirstOrDefault();
        return new DiagnosticResult<AreaReport>(Name, report.Status, card is null ? report.Summary : card.Headline, DateTimeOffset.Now, report);
    }

    /// <summary>One report with a card per drive (the page and the fix list read this), rebuilt from the latest drive read so the
    /// summary, the one "Clean up temporary files" action and the card ids come out as for a single read.</summary>
    public object? Combine(IReadOnlyList<DiagnosticResult> instanceResults)
    {
        if (instanceResults.Count == 1 && instanceResults[0].InstanceKey == AllDrivesKey) return instanceResults[0].Payload;
        if (_latest is not { Drives: { } drives } read) return null;
        var byKey = Instances(drives).ToDictionary(x => x.Instance.Key, x => x.Drive);
        var shown = instanceResults.Select(r => r.InstanceKey is { } k ? byKey.GetValueOrDefault(k) : null).OfType<DriveHealth>().ToList();
        return shown.Count == 0 ? null : Build(shown, read.Retrims, read.Now, _history, GetDrives()) with { Notice = read.Notice };
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

    public static AreaReport Build(IReadOnlyList<DriveHealth> drives) =>
        Build(drives, null, DateTimeOffset.Now, null, null);

    public static AreaReport Build(
        IReadOnlyList<DriveHealth> drives,
        IReadOnlyDictionary<char, RetrimRecord>? retrims = null,
        DateTimeOffset? now = null,
        IDriveHealthHistoryStore? historyStore = null,
        IReadOnlyList<DriveCapacityInfo>? capacities = null)
    {
        var timestamp = now ?? DateTimeOffset.Now;
        if (drives.Count == 0 && (capacities is null || capacities.Count == 0))
            return new([], "No drives were found to check.", DiagnosticStatus.Warning);
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

            var driveLetters = RemediationService.DriveLetters(d.Letters);
            DriveCapacityInfo? primaryVol = null;
            if (capacities is { Count: > 0 } && driveLetters.Length > 0)
            {
                primaryVol = capacities.FirstOrDefault(cap =>
                    driveLetters.Any(letter => cap.DriveName.StartsWith(letter.ToString(), StringComparison.OrdinalIgnoreCase)));
            }

            var meta = string.Join(" · ", new[]
            {
                d.Kind, d.SizeBytes is > 0 ? HardwareInventory.FormatBytes(d.SizeBytes) : null,
                primaryVol is not null ? $"{HardwareInventory.FormatBytes(primaryVol.FreeBytes)} free" : null,
                d.TemperatureC is > 0 ? $"{d.TemperatureC}°C" : null, d.Wear is not null ? $"{d.Wear}% worn" : null,
                trend is { IsDegrading: true } ? "Degrading" : null,
            }.Where(x => x is not null));
            var rows = new List<AreaRow>();
            void Add(string label, string? v, AreaLevel l = AreaLevel.Neutral, string? detail = null) { if (!string.IsNullOrWhiteSpace(v)) rows.Add(new(l, [label, v], Detail: detail)); }
            Add("Overall", verdict + (reasons.Count > 0 ? ": " + string.Join("; ", reasons) : ""), level);
            Add("Status reported by Windows", d.Health.Length > 0 ? $"{d.Health}{(d.Operational.Length > 0 && d.Operational != "OK" ? $" ({d.Operational})" : "")}" : "Not reported");
            if (trend is not null)
                Add("Health trend", trend.SummaryText, trend.IsDegrading ? AreaLevel.Warning : AreaLevel.Neutral, detail: trend.HistoryDetail);
            Add("Type", d.Kind);
            Add("Connection", d.BusType);
            Add("Size", d.SizeBytes is > 0 ? HardwareInventory.FormatBytes(d.SizeBytes) : null);
            if (capacities is { Count: > 0 } && driveLetters.Length > 0)
            {
                foreach (var letter in driveLetters)
                {
                    if (capacities.FirstOrDefault(cap => cap.DriveName.StartsWith(letter.ToString(), StringComparison.OrdinalIgnoreCase)) is { } vol)
                    {
                        Add($"Volume {vol.DriveName.TrimEnd('\\')}", $"{HardwareInventory.FormatBytes(vol.FreeBytes)} free of {HardwareInventory.FormatBytes(vol.TotalBytes)} ({vol.UsedPercent:0.#}% used · {vol.DriveFormat})",
                            vol.UsedPercent >= 90.0 ? AreaLevel.Warning : AreaLevel.Neutral);
                    }
                }
            }
            Add("Temperature", d.TemperatureC is > 0 ? $"{d.TemperatureC}°C" : "Not reported", d.TemperatureC >= DriveHealth.HotC ? AreaLevel.Warning : AreaLevel.Neutral);
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
                Actions: actions.Count > 0 ? actions : null);
        }).ToList();

        if (capacities is { Count: > 0 })
        {
            cards.Insert(0, DiskSpaceModule.BuildDriveCapacityCard(capacities, "capacity"));
        }

        var degrading = drives.Count(d => historyStore?.AnalyzeTrend(d.RawId, d, timestamp).IsDegrading == true);
        var bad = cards.Count(c => c.Level is AreaLevel.Warning or AreaLevel.Error);
        var unknown = drives.All(d => d.Level == AreaLevel.Neutral);
        string freePart = capacities is { Count: > 0 }
            ? $" · {(capacities.Count == 1 ? $"{HardwareInventory.FormatBytes(capacities[0].FreeBytes)} free on {capacities[0].DriveName.TrimEnd('\\')}" : $"{HardwareInventory.FormatBytes(capacities.Sum(c => c.FreeBytes))} free")}"
            : "";
        var summary = bad > 0 ? $"{bad} of {Plural(drives.Count, "drive")} need{(bad == 1 ? "s" : "")} attention{freePart}"
            : unknown ? $"{Plural(drives.Count, "drive")} found · health not reported{freePart}"
            : drives.Count == 1 ? $"1 drive · healthy{freePart}" : $"{drives.Count} drives · all healthy{freePart}";
        if (degrading > 0)
            summary = $"{summary} ({Plural(degrading, "drive")} getting worse)";
        return new(cards, summary, AreaReport.Worst(cards.Select(c => c.Level)));
    }
}
