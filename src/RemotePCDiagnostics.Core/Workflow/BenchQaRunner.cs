using RemotePCDiagnostics.Core.Preferences;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>
/// Orchestrates a hands-free 10-minute refurbisher bench intake pass:
/// 1) Read-only hardware &amp; Windows checks (SMBIOS, sensors, SMART, battery, drivers, BSOD/WHEA),
/// 2) Read-only Windows image/system file integrity (DISM ScanHealth + SFC verify-only),
/// 3) Short thermal-guarded local hardware stress (CPU, RAM, Disk, GPU — skipping NetworkTest so offline benches pass),
/// 4) Dongle-free WASAPI speaker→mic loopback, webcam frame check, and NPU test when applicable,
/// 5) Automatic save of the 1-page Buyer Hardware QA QR Certificate.
/// </summary>
public sealed class BenchQaRunner(
    DiagnosticsService diag,
    ResultStore store,
    WorkflowService? workflow = null,
    PreferencesService? prefs = null,
    PhysicalBenchQaService? physicalQa = null,
    ILogger? log = null)
{
    public static readonly IReadOnlyList<string> LocalHardwareStressSlugs =
    [
        ModuleSlugs.CpuStress,
        ModuleSlugs.MemoryTest,
        ModuleSlugs.DiskSpeed,
        ModuleSlugs.GpuStress,
    ];

    public static readonly IReadOnlyDictionary<string, string> StressItemToSlug = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["cpu-stress"] = ModuleSlugs.CpuStress,
        ["ram-test"] = ModuleSlugs.MemoryTest,
        ["disk-speed"] = ModuleSlugs.DiskSpeed,
        ["gpu-stress"] = ModuleSlugs.GpuStress,
    };

    private static readonly (string ItemId, string Slug)[] BaseCheckItems =
    [
        ("hardware", ModuleSlugs.Osquery),
        ("battery", ModuleSlugs.BatteryPower),
        ("smart", ModuleSlugs.DriveHealth),
        ("sensors", ModuleSlugs.Sensors),
        ("stability", ModuleSlugs.Crashes),
        ("drivers", ModuleSlugs.DeviceDrivers),
    ];

    private static readonly string[] IntegritySlugs =
    [
        ModuleSlugs.DismScanHealth,
        ModuleSlugs.SfcVerifyOnly,
    ];

    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private int _running;

    public bool IsRunning => Volatile.Read(ref _running) == 1;
    public string? Status { get; private set; }
    public int CompletedSteps { get; private set; }
    public int TotalSteps { get; private set; }
    public string? LastSavedCertificatePath { get; private set; }

    public bool IncludeStress { get; private set; } = true;
    public bool IncludeAudioCamera { get; private set; } = true;
    public bool IncludeSecurityAudit { get; private set; }
    public bool IncludeKeyboard { get; private set; }
    public bool IncludeDisplay { get; private set; }
    public IReadOnlySet<string> SelectedItemIds { get; private set; } =
        new HashSet<string>(HardwareQaCertificate.DefaultSelectedItemIds, StringComparer.OrdinalIgnoreCase);

    public double ProgressFraction =>
        TotalSteps <= 0 ? 0.0 : Math.Clamp((double)CompletedSteps / TotalSteps, 0.0, 1.0);

    // Progress counted in QA items (what the page lists and the person selected), not internal steps: one step can cover
    // several items (the base checks run as one Run all) and one item can take several steps (DISM + SFC).
    private readonly HashSet<string> _doneItems = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The selected items this run checks (in page order).</summary>
    public IReadOnlyList<string> RunItemIds { get; private set; } = [];
    /// <summary>The selected items that can't run on this PC right now (their checks aren't available, e.g. the Agent isn't connected).</summary>
    public IReadOnlyList<string> SkippedItemIds { get; private set; } = [];
    /// <summary>How many of <see cref="RunItemIds"/> have finished.</summary>
    public int CompletedItems { get { lock (_doneItems) return _doneItems.Count; } }

    public double ItemProgressFraction =>
        RunItemIds.Count == 0 ? 0.0 : Math.Clamp((double)CompletedItems / RunItemIds.Count, 0.0, 1.0);

    public event Action? Changed;

    public Task StartBenchQaAsync(
        bool includeStress = true,
        bool includeAudioCamera = true,
        bool includeSecurityAudit = false,
        bool includeKeyboard = false,
        bool includeDisplay = false,
        Func<string, CancellationToken, Task>? waitInteractive = null,
        CancellationToken ct = default) =>
        StartBenchQaAsync(BuildSelection(includeStress, includeAudioCamera, includeSecurityAudit, includeKeyboard, includeDisplay), waitInteractive, ct);

    public Task StartBenchQaAsync(
        IReadOnlyCollection<string> selectedItemIds,
        Func<string, CancellationToken, Task>? waitInteractive = null,
        CancellationToken ct = default) =>
        Task.Run(() => RunIntakeAsync(selectedItemIds, waitInteractive, ct), ct);

    public Task RunIntakeAsync(
        bool includeStress = true,
        bool includeAudioCamera = true,
        bool includeSecurityAudit = false,
        bool includeKeyboard = false,
        bool includeDisplay = false,
        Func<string, CancellationToken, Task>? waitInteractive = null,
        CancellationToken ct = default) =>
        RunIntakeAsync(BuildSelection(includeStress, includeAudioCamera, includeSecurityAudit, includeKeyboard, includeDisplay), waitInteractive, ct);

    private static HashSet<string> BuildSelection(bool includeStress, bool includeAudioCamera, bool includeSecurityAudit, bool includeKeyboard, bool includeDisplay)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "hardware", "battery", "smart", "sensors", "stability", "drivers", "integrity",
        };
        if (includeStress)
        {
            set.Add("cpu-stress");
            set.Add("ram-test");
            set.Add("disk-speed");
            set.Add("gpu-stress");
        }
        if (includeAudioCamera)
        {
            set.Add("audio");
            set.Add("webcam");
        }
        if (includeSecurityAudit) set.Add("security");
        if (includeKeyboard) set.Add("keyboard");
        if (includeDisplay) set.Add("display");
        return set;
    }

    public async Task RunIntakeAsync(
        IReadOnlyCollection<string> selectedItemIds,
        Func<string, CancellationToken, Task>? waitInteractive = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(diag);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(selectedItemIds);

        if (Interlocked.CompareExchange(ref _running, 1, 0) != 0)
            return;

        var selected = new HashSet<string>(selectedItemIds, StringComparer.OrdinalIgnoreCase);
        SelectedItemIds = selected;

        var selectedStressSlugs = StressItemToSlug
            .Where(kv => selected.Contains(kv.Key))
            .Select(kv => kv.Value)
            .ToList();
        var includeStress = selectedStressSlugs.Count > 0;
        var includeAudio = selected.Contains("audio");
        var includeWebcam = selected.Contains("webcam");
        var includeAudioCamera = includeAudio || includeWebcam;
        var includeSecurityAudit = selected.Contains("security");
        var includeKeyboard = selected.Contains("keyboard");
        var includeDisplay = selected.Contains("display");
        var includeIntegrity = selected.Contains("integrity");

        IncludeStress = includeStress;
        IncludeAudioCamera = includeAudioCamera;
        IncludeSecurityAudit = includeSecurityAudit;
        IncludeKeyboard = includeKeyboard;
        IncludeDisplay = includeDisplay;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_gate) _cts = cts;
        var token = cts.Token;

        var runAllBaseChecks = BaseCheckItems.All(b => selected.Contains(b.ItemId));
        var selectiveBaseSlugs = runAllBaseChecks
            ? []
            : BaseCheckItems
                .Where(b => selected.Contains(b.ItemId))
                .Select(b => b.ItemId == "stability" && !diag.CanRun(ModuleSlugs.Crashes) && diag.CanRun(ModuleSlugs.BsodHistory)
                    ? ModuleSlugs.BsodHistory
                    : b.Slug)
                .Where(diag.CanRun)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

        var integrityToConsider = includeIntegrity ? IntegritySlugs.Where(diag.CanRun).ToList() : [];
        var suiteStressSlugs = includeStress
            ? diag.StressOrder.Where(s => selectedStressSlugs.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList()
            : [];
        var plainStressSlugs = includeStress
            ? selectedStressSlugs.Where(s => !suiteStressSlugs.Contains(s, StringComparer.OrdinalIgnoreCase) && diag.CanRun(s)).ToList()
            : [];
        var peripheralSlugs = new List<string>();
        if (includeAudio && diag.CanRun(ModuleSlugs.SpeakerToMic)) peripheralSlugs.Add(ModuleSlugs.SpeakerToMic);
        if (includeWebcam && diag.CanRun(ModuleSlugs.Webcam)) peripheralSlugs.Add(ModuleSlugs.Webcam);
        if ((includeAudioCamera || selected.Contains("npu")) && diag.CanRun(ModuleSlugs.NpuTest))
            peripheralSlugs.Add(ModuleSlugs.NpuTest);

        var securitySlugs = new List<string>();
        if (includeSecurityAudit && diag.CanRun(ModuleSlugs.SecurityAudit))
            securitySlugs.Add(ModuleSlugs.SecurityAudit);

        var runItems = HardwareQaCertificate.AllSelectableItemIds
            .Where(id => selected.Contains(id) && ItemCanRun(id, suiteStressSlugs, plainStressSlugs))
            .ToList();
        RunItemIds = runItems;
        SkippedItemIds = HardwareQaCertificate.AllSelectableItemIds.Where(id => selected.Contains(id) && !runItems.Contains(id)).ToList();
        lock (_doneItems) _doneItems.Clear();
        if (SkippedItemIds.Count > 0)
            log.Info($"[bench-qa] Can't run here: {string.Join(", ", SkippedItemIds)}");

        var baseStepCount = runAllBaseChecks ? 1 : selectiveBaseSlugs.Count;
        var keyboardStep = includeKeyboard ? 1 : 0;
        var displayStep = includeDisplay ? 1 : 0;
        var saveStep = workflow is not null ? 1 : 0;
        TotalSteps = baseStepCount + integrityToConsider.Count + suiteStressSlugs.Count + plainStressSlugs.Count + peripheralSlugs.Count + securitySlugs.Count + keyboardStep + displayStep + saveStep;
        CompletedSteps = 0;
        LastSavedCertificatePath = null;
        Status = runAllBaseChecks
            ? "Running hardware inventory, SMART, battery, driver & WHEA checks…"
            : "Starting selected hardware QA checks…";
        Raise();

        try
        {
            log.Info($"[bench-qa] Starting hardware QA ({selected.Count} selected: {string.Join(", ", selected)})");

            // Step 1: Standard read-only checks (all at once when every base item is selected, or only the selected ones)
            if (runAllBaseChecks)
            {
                // Run all is one step: count each base item as its result lands so the bar moves during it.
                void OnResult(object? sender, DiagnosticResult r)
                {
                    if (r.Status is DiagnosticStatus.Running or DiagnosticStatus.NotRun) return;
                    if (BaseItemFor(r.ModuleName) is { } itemId) MarkItemDone(itemId);
                }
                store.Changed += OnResult;
                try
                {
                    await diag.RunAllAsync(token).ConfigureAwait(false);
                }
                finally
                {
                    store.Changed -= OnResult;
                }
                token.ThrowIfCancellationRequested();
                foreach (var b in BaseCheckItems) MarkItemDone(b.ItemId, raise: false);
                CompletedSteps = 1;
                Raise();
            }
            else
            {
                foreach (var slug in selectiveBaseSlugs)
                {
                    token.ThrowIfCancellationRequested();
                    Status = $"Checking {diag.Catalog.DisplayName(slug)}…";
                    Raise();
                    await RunModuleSafeAsync(slug, token).ConfigureAwait(false);
                    if (BaseItemFor(slug) is { } itemId) MarkItemDone(itemId, raise: false);
                    CompletedSteps++;
                    Raise();
                }
            }

            // Step 2: Read-only Windows integrity checks (DismScanHealth, SfcVerifyOnly) if selected and not already completed
            foreach (var slug in integrityToConsider)
            {
                token.ThrowIfCancellationRequested();
                var display = diag.Catalog.DisplayName(slug);
                var existing = store.Get(slug);
                if (!IsCompletedResult(existing))
                {
                    Status = $"Checking Windows integrity: {display}…";
                    Raise();
                    await RunModuleSafeAsync(slug, token).ConfigureAwait(false);
                }
                CompletedSteps++;
                Raise();
            }
            if (integrityToConsider.Count > 0) MarkItemDone("integrity");

            // Step 3: Short thermal-guarded hardware stress on selected local hardware only
            if (includeStress)
            {
                if (suiteStressSlugs.Count > 0)
                {
                    token.ThrowIfCancellationRequested();
                    var baseSteps = CompletedSteps;
                    Status = "Running short thermal-guarded hardware stress…";
                    Raise();

                    var stressProgress = new StressProgressAdapter(p =>
                    {
                        var finishedCount = p.Steps.Count(s => s.State is StressSuiteStepState.Passed or StressSuiteStepState.Problem or StressSuiteStepState.Skipped);
                        CompletedSteps = baseSteps + Math.Min(finishedCount, suiteStressSlugs.Count);
                        foreach (var step in p.Steps.Where(s => s.State is StressSuiteStepState.Passed or StressSuiteStepState.Problem or StressSuiteStepState.Skipped))
                            if (ItemForSlug(step.ModuleName) is { } stepItem) MarkItemDone(stepItem, raise: false);
                        if (!p.Finished && p.CurrentDisplayName is { Length: > 0 } current)
                            Status = $"Short hardware stress ({p.Index}/{p.Total}): {current}…";
                        Raise();
                    });

                    var suiteResult = await diag.RunStressSuiteAsync(
                        StressSuiteMode.Short,
                        stressProgress,
                        token,
                        only: selectedStressSlugs,
                        runQuickChecks: false).ConfigureAwait(false);

                    token.ThrowIfCancellationRequested();
                    if (suiteResult.Outcome == StressSuiteOutcome.Cancelled)
                        throw new OperationCanceledException(token);

                    foreach (var slug in suiteStressSlugs)
                        if (ItemForSlug(slug) is { } suiteItem) MarkItemDone(suiteItem, raise: false);
                    CompletedSteps = baseSteps + suiteStressSlugs.Count;
                    Raise();
                }

                foreach (var slug in plainStressSlugs)
                {
                    token.ThrowIfCancellationRequested();
                    Status = $"Running short hardware stress: {diag.Catalog.DisplayName(slug)}…";
                    Raise();
                    await RunModuleSafeAsync(slug, token).ConfigureAwait(false);
                    if (ItemForSlug(slug) is { } plainItem) MarkItemDone(plainItem, raise: false);
                    CompletedSteps++;
                    Raise();
                }
            }

            // Step 4: Selected audio loopback, webcam, and NPU checks
            foreach (var slug in peripheralSlugs)
            {
                token.ThrowIfCancellationRequested();
                Status = $"Verifying {diag.Catalog.DisplayName(slug)}…";
                Raise();
                await RunModuleSafeAsync(slug, token).ConfigureAwait(false);
                if (ItemForSlug(slug) is { } peripheralItem) MarkItemDone(peripheralItem, raise: false);
                CompletedSteps++;
                Raise();
            }

            // Step 5: Windows security & baseline audit (HardeningKitty) when selected
            foreach (var slug in securitySlugs)
            {
                token.ThrowIfCancellationRequested();
                Status = $"Running {diag.Catalog.DisplayName(slug)}…";
                Raise();
                await RunModuleSafeAsync(slug, token).ConfigureAwait(false);
                MarkItemDone("security", raise: false);
                CompletedSteps++;
                Raise();
            }

            // Step 6: Physical keyboard matrix & rollover check
            if (includeKeyboard)
            {
                token.ThrowIfCancellationRequested();
                Status = "Physical keyboard check: verify key switches & simultaneous rollover…";
                Raise();
                if (waitInteractive is not null)
                {
                    await waitInteractive("keyboard", token).ConfigureAwait(false);
                }
                MarkItemDone("keyboard", raise: false);
                CompletedSteps++;
                Raise();
            }

            // Step 7: Physical display dead-pixel & touch check
            if (includeDisplay)
            {
                token.ThrowIfCancellationRequested();
                Status = "Physical display check: inspect color uniformity, dead pixels & touch…";
                Raise();
                if (waitInteractive is not null)
                {
                    await waitInteractive("display", token).ConfigureAwait(false);
                }
                MarkItemDone("display", raise: false);
                CompletedSteps++;
                Raise();
            }

            // Step 8: Automatically save the 1-page HTML QR Certificate
            token.ThrowIfCancellationRequested();
            if (workflow is not null)
            {
                Status = "Saving 1-page Buyer Hardware QA Certificate…";
                Raise();
                LastSavedCertificatePath = workflow.SaveHardwareQaCertificate(prefs?.Current.Branding, physicalQa?.Current);
                CompletedSteps = TotalSteps;
            }

            Status = LastSavedCertificatePath is { Length: > 0 } savedPath
                ? $"10-minute QA intake finished · Certificate saved to {savedPath}"
                : "10-minute QA intake finished.";
            log.Info($"[bench-qa] Finished: cert={LastSavedCertificatePath ?? "(in-memory)"}");
        }
        catch (OperationCanceledException)
        {
            Status = "Bench QA intake stopped.";
            log.Info("[bench-qa] Cancelled");
        }
        catch (Exception ex)
        {
            Status = $"Bench QA intake stopped: {ex.Message}";
            log.Warn($"[bench-qa] Failed: {ex}");
        }
        finally
        {
            lock (_gate) _cts = null;
            Volatile.Write(ref _running, 0);
            Raise();
        }
    }

    /// <summary>The checks behind a QA item that Re-run can run again without anyone at the bench; empty for the interactive ones (keyboard, display).</summary>
    public static IReadOnlyList<string> SlugsForItem(string itemId)
    {
        if (BaseCheckItems.FirstOrDefault(b => string.Equals(b.ItemId, itemId, StringComparison.OrdinalIgnoreCase)) is { Slug: { } baseSlug }) return [baseSlug];
        if (StressItemToSlug.TryGetValue(itemId, out var stress)) return [stress];
        return itemId.ToLowerInvariant() switch
        {
            "integrity" => IntegritySlugs,
            "audio" => [ModuleSlugs.SpeakerToMic],
            "webcam" => [ModuleSlugs.Webcam],
            "npu" => [ModuleSlugs.NpuTest],
            "security" => [ModuleSlugs.SecurityAudit],
            _ => [],
        };
    }

    public static bool CanRerun(string itemId) => SlugsForItem(itemId).Count > 0;

    /// <summary>The items of <paramref name="snapshot"/> that failed or have a note and can run again: what "Re-run failed" runs.</summary>
    public static IReadOnlyList<HardwareQaItem> RerunnableProblems(HardwareQaSnapshot snapshot) =>
        snapshot.Items.Where(i => !i.Cancelled && i.Status is DiagnosticStatus.Error or DiagnosticStatus.Warning && CanRerun(i.Id)).ToList();

    /// <summary>
    /// Runs the checks behind <paramref name="itemIds"/> again (normally the ones that failed), then saves the certificate again. The
    /// security audit re-checks only the settings that failed or warned; stress tests run as the short guarded pass, as in the QA check.
    /// Does nothing while a QA check or another re-run is running.
    /// </summary>
    public Task RerunAsync(IReadOnlyCollection<string> itemIds, CancellationToken ct = default) => Task.Run(() => RerunCoreAsync(itemIds, ct), ct);

    private async Task RerunCoreAsync(IReadOnlyCollection<string> itemIds, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(itemIds);
        if (Interlocked.CompareExchange(ref _running, 1, 0) != 0) return;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_gate) _cts = cts;
        var token = cts.Token;
        // A re-run reports progress in steps only; forget the last QA check's item counts.
        RunItemIds = [];
        SkippedItemIds = [];
        lock (_doneItems) _doneItems.Clear();
        var slugs = itemIds.SelectMany(SlugsForItem).Where(diag.CanRun).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var stress = slugs.Where(s => StressItemToSlug.Values.Contains(s, StringComparer.OrdinalIgnoreCase) && diag.StressOrder.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList();
        var others = slugs.Except(stress, StringComparer.OrdinalIgnoreCase).ToList();
        TotalSteps = others.Count + (stress.Count > 0 ? 1 : 0) + (workflow is not null ? 1 : 0);
        CompletedSteps = 0;
        Status = "Re-running the checks that failed…";
        Raise();
        try
        {
            log.Info($"[bench-qa] Re-run: {string.Join(", ", itemIds)} -> {string.Join(", ", slugs)}");
            foreach (var slug in others)
            {
                token.ThrowIfCancellationRequested();
                if (slug == ModuleSlugs.SecurityAudit
                    && diag.Catalog.ModuleFor(ModuleIds.SecurityAudit) is Security.SecurityAuditModule audit
                    && store.Get(slug).Payload is Security.SecurityAuditReport rep && rep.NeedsAttention.Count > 0)
                    audit.RecheckOnNextRun(rep.NeedsAttention.Select(f => f.Id));
                Status = $"Re-running {diag.Catalog.DisplayName(slug)}…";
                Raise();
                await RunModuleSafeAsync(slug, token).ConfigureAwait(false);
                CompletedSteps++;
                Raise();
            }
            if (stress.Count > 0)
            {
                token.ThrowIfCancellationRequested();
                Status = "Re-running short thermal-guarded hardware stress…";
                Raise();
                var suite = await diag.RunStressSuiteAsync(StressSuiteMode.Short, null, token, only: stress, runQuickChecks: false).ConfigureAwait(false);
                if (suite.Outcome == StressSuiteOutcome.Cancelled) throw new OperationCanceledException(token);
                CompletedSteps++;
                Raise();
            }
            token.ThrowIfCancellationRequested();
            if (workflow is not null)
            {
                Status = "Saving the updated certificate…";
                Raise();
                LastSavedCertificatePath = workflow.SaveHardwareQaCertificate(prefs?.Current.Branding, physicalQa?.Current);
                CompletedSteps = TotalSteps;
            }
            Status = LastSavedCertificatePath is { Length: > 0 } saved ? $"Re-run finished · Certificate saved to {saved}" : "Re-run finished.";
        }
        catch (OperationCanceledException)
        {
            Status = "Re-run stopped.";
        }
        catch (Exception ex)
        {
            Status = $"Re-run stopped: {ex.Message}";
            log.Warn($"[bench-qa] Re-run failed: {ex}");
        }
        finally
        {
            lock (_gate) _cts = null;
            Volatile.Write(ref _running, 0);
            Raise();
        }
    }

    public void Cancel()
    {
        CancellationTokenSource? cts;
        lock (_gate) cts = _cts;
        if (cts is null) return;
        Status = "Stopping bench QA intake…";
        Raise();
        try { cts.Cancel(); } catch (ObjectDisposedException) { }
        try { diag.CancelStressSuite(); } catch { }
    }

    private async Task RunModuleSafeAsync(string slug, CancellationToken ct)
    {
        try
        {
            await diag.RunAsync(slug, null, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            log.Warn($"[bench-qa] {slug} failed: {ex.Message}");
        }
    }

    /// <summary>Whether a selected item has a check this PC can run now (keyboard and display are checked by the person, so always).</summary>
    private bool ItemCanRun(string itemId, List<string> suiteStressSlugs, List<string> plainStressSlugs)
    {
        if (itemId is "keyboard" or "display") return true;
        if (itemId == "stability") return diag.CanRun(ModuleSlugs.Crashes) || diag.CanRun(ModuleSlugs.BsodHistory);
        if (StressItemToSlug.TryGetValue(itemId, out var stressSlug))
            return suiteStressSlugs.Contains(stressSlug, StringComparer.OrdinalIgnoreCase) || plainStressSlugs.Contains(stressSlug, StringComparer.OrdinalIgnoreCase);
        return SlugsForItem(itemId).Any(diag.CanRun);
    }

    private static string? BaseItemFor(string slug) =>
        string.Equals(slug, ModuleSlugs.BsodHistory, StringComparison.OrdinalIgnoreCase)
            ? "stability"
            : BaseCheckItems.FirstOrDefault(b => string.Equals(b.Slug, slug, StringComparison.OrdinalIgnoreCase)).ItemId;

    private static string? ItemForSlug(string slug)
    {
        foreach (var (item, stressSlug) in StressItemToSlug)
            if (string.Equals(stressSlug, slug, StringComparison.OrdinalIgnoreCase)) return item;
        if (string.Equals(slug, ModuleSlugs.SpeakerToMic, StringComparison.OrdinalIgnoreCase)) return "audio";
        if (string.Equals(slug, ModuleSlugs.Webcam, StringComparison.OrdinalIgnoreCase)) return "webcam";
        return null;
    }

    /// <summary>Counts an item as finished, once, and only if this run checks it.</summary>
    private void MarkItemDone(string itemId, bool raise = true)
    {
        if (!RunItemIds.Contains(itemId, StringComparer.OrdinalIgnoreCase)) return;
        bool added;
        lock (_doneItems) added = _doneItems.Add(itemId);
        if (added && raise) Raise();
    }

    private static bool IsCompletedResult(DiagnosticResult r) =>
        r.Status is DiagnosticStatus.Ok or DiagnosticStatus.Warning or DiagnosticStatus.Error && !r.Cancelled;

    private void Raise()
    {
        try { Changed?.Invoke(); } catch { }
    }

    private sealed class StressProgressAdapter(Action<StressSuiteProgress> handler) : IProgress<StressSuiteProgress>
    {
        public void Report(StressSuiteProgress value)
        {
            try { handler(value); } catch { }
        }
    }
}
