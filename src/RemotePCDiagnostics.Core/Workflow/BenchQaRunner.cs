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

    public double ProgressFraction =>
        TotalSteps <= 0 ? 0.0 : Math.Clamp((double)CompletedSteps / TotalSteps, 0.0, 1.0);

    public event Action? Changed;

    public async Task RunIntakeAsync(bool includeStress = true, bool includeAudioCamera = true, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(diag);
        ArgumentNullException.ThrowIfNull(store);

        if (Interlocked.CompareExchange(ref _running, 1, 0) != 0)
            return;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_gate) _cts = cts;
        var token = cts.Token;

        var integrityToConsider = IntegritySlugs.Where(diag.CanRun).ToList();
        var suiteStressSlugs = includeStress
            ? diag.StressOrder.Where(s => LocalHardwareStressSlugs.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList()
            : [];
        var plainStressSlugs = includeStress
            ? LocalHardwareStressSlugs.Where(s => !suiteStressSlugs.Contains(s, StringComparer.OrdinalIgnoreCase) && diag.CanRun(s)).ToList()
            : [];
        var peripheralSlugs = new List<string>();
        if (includeAudioCamera)
        {
            if (diag.CanRun(ModuleSlugs.SpeakerToMic)) peripheralSlugs.Add(ModuleSlugs.SpeakerToMic);
            if (diag.CanRun(ModuleSlugs.Webcam)) peripheralSlugs.Add(ModuleSlugs.Webcam);
        }
        if (diag.CanRun(ModuleSlugs.NpuTest))
            peripheralSlugs.Add(ModuleSlugs.NpuTest);

        var saveStep = workflow is not null ? 1 : 0;
        TotalSteps = 1 + integrityToConsider.Count + suiteStressSlugs.Count + plainStressSlugs.Count + peripheralSlugs.Count + saveStep;
        CompletedSteps = 0;
        LastSavedCertificatePath = null;
        Status = "Running hardware inventory, SMART, battery, driver & WHEA checks…";
        Raise();

        try
        {
            log.Info($"[bench-qa] Starting 10-minute hardware intake (stress={includeStress}, audioCamera={includeAudioCamera})");

            // Step 1: Standard read-only checks (Osquery, Sensors, DriveHealth, BatteryPower, DeviceDrivers, Crashes/WHEA, etc.)
            await diag.RunAllAsync(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            CompletedSteps = 1;
            Raise();

            // Step 2: Read-only Windows integrity checks (DismScanHealth, SfcVerifyOnly) if registered and not already completed
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

            // Step 3: Short thermal-guarded hardware stress on local hardware only (skipping NetworkTest for offline benches)
            if (includeStress)
            {
                if (suiteStressSlugs.Count > 0)
                {
                    token.ThrowIfCancellationRequested();
                    var baseSteps = CompletedSteps;
                    Status = "Running short thermal-guarded hardware stress (CPU, RAM, Disk, GPU)…";
                    Raise();

                    var stressProgress = new StressProgressAdapter(p =>
                    {
                        var finishedCount = p.Steps.Count(s => s.State is StressSuiteStepState.Passed or StressSuiteStepState.Problem or StressSuiteStepState.Skipped);
                        CompletedSteps = baseSteps + Math.Min(finishedCount, suiteStressSlugs.Count);
                        if (!p.Finished && p.CurrentModule is { Length: > 0 } current)
                            Status = $"Short hardware stress ({p.CurrentIndex}/{p.Total}): {current}…";
                        Raise();
                    });

                    var suiteResult = await diag.RunStressSuiteAsync(
                        StressSuiteMode.Short,
                        stressProgress,
                        token,
                        only: LocalHardwareStressSlugs,
                        runQuickChecks: false).ConfigureAwait(false);

                    token.ThrowIfCancellationRequested();
                    if (suiteResult.Outcome == StressSuiteOutcome.Cancelled)
                        throw new OperationCanceledException(token);

                    CompletedSteps = baseSteps + suiteStressSlugs.Count;
                    Raise();
                }

                foreach (var slug in plainStressSlugs)
                {
                    token.ThrowIfCancellationRequested();
                    Status = $"Running short hardware stress: {diag.Catalog.DisplayName(slug)}…";
                    Raise();
                    await RunModuleSafeAsync(slug, token).ConfigureAwait(false);
                    CompletedSteps++;
                    Raise();
                }
            }

            // Step 4: Dongle-free WASAPI speaker->mic loopback, webcam check, and NPU accelerator check
            foreach (var slug in peripheralSlugs)
            {
                token.ThrowIfCancellationRequested();
                Status = $"Verifying {diag.Catalog.DisplayName(slug)}…";
                Raise();
                await RunModuleSafeAsync(slug, token).ConfigureAwait(false);
                CompletedSteps++;
                Raise();
            }

            // Step 5: Automatically save the 1-page HTML QR Certificate
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

    public void Cancel()
    {
        CancellationTokenSource? cts;
        lock (_gate) cts = _cts;
        if (cts is null) return;
        try { cts.Cancel(); } catch (ObjectDisposedException) { }
        try { diag.CancelStressSuite(); } catch { }
        Status = "Stopping bench QA intake…";
        Raise();
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
