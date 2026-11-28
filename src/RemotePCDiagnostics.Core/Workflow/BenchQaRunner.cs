using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Cooling;
using RemotePCDiagnostics.Core.GpuMemory;
using RemotePCDiagnostics.Core.Input;
using RemotePCDiagnostics.Core.Preferences;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>
/// Orchestrates a hands-free 10-minute refurbisher bench intake pass:
/// 1) Read-only hardware &amp; Windows checks (SMBIOS, sensors, SMART, battery, drivers, BSOD/WHEA),
/// 2) Read-only Windows image/system file integrity (DISM ScanHealth + SFC verify-only),
/// 3) Short thermal-guarded local hardware stress (CPU, RAM, Disk, GPU — skipping NetworkTest so offline benches pass),
/// 4) Dongle-free WASAPI speaker→mic loopback, webcam frame check, and NPU test when applicable,
/// 5) Guided steps someone at the bench does (keyboard, display, pointer, charger replug, USB ports, video outputs, Ethernet),
/// 6) Automatic save of the 1-page Buyer Hardware QA QR Certificate.
/// The long tests (disk surface scan, extended drive self-test, boot memory test, battery drain) are not part of it.
/// </summary>
public sealed class BenchQaRunner(
    DiagnosticsService diag,
    ResultStore store,
    WorkflowService? workflow = null,
    PreferencesService? prefs = null,
    PhysicalBenchQaService? physicalQa = null,
    ILogger? log = null,
    PointerTestService? pointerTest = null,
    IPowerLineSource? power = null)
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

    /// <summary>The graphics memory test runs after the stress tests (Quick, about 90 s), not in the stress suite.</summary>
    private const string GpuMemoryItemId = "gpu-memory";

    private static readonly (string ItemId, string Slug)[] BaseCheckItems =
    [
        ("hardware", ModuleSlugs.Osquery),
        ("battery", ModuleSlugs.BatteryPower),
        ("smart", ModuleSlugs.DriveHealth),
        ("sensors", ModuleSlugs.Sensors),
        ("stability", ModuleSlugs.Crashes),
        ("drivers", ModuleSlugs.DeviceDrivers),
    ];

    /// <summary>Quick read-only checks and short tests that run right after the base checks, before the stress tests heat the PC.</summary>
    private static readonly (string ItemId, string Slug)[] AddedCheckItems =
    [
        ("usb", ModuleSlugs.UsbPorts),
        ("displays", ModuleSlugs.Displays),
        ("device-sensors", ModuleSlugs.DeviceSensors),
        ("drive-self-test", ModuleSlugs.DriveSelfTest),
        ("cooling", ModuleSlugs.Cooling),
    ];

    /// <summary>
    /// Guided steps someone at the bench does, in the order the run waits on them. Keyboard, display and pointer are shown on the QA page;
    /// the charger test runs here and the page shows its prompts; the USB port, video output and Ethernet checks are done on the
    /// Interactive tests page (<see cref="InteractivePageFor"/>), and the run waits for their result.
    /// </summary>
    public static readonly IReadOnlyList<string> GuidedItemIds = ["keyboard", "display", "pointer", "charger", "usb-port", "video-output", "ethernet"];

    private static readonly IReadOnlyDictionary<string, string> GuidedItemToSlug = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["charger"] = ModuleSlugs.ChargerReplug,
        ["usb-port"] = ModuleSlugs.UsbPortCheck,
        ["video-output"] = ModuleSlugs.DisplayOutputCheck,
        ["ethernet"] = ModuleSlugs.EthernetPort,
    };

    /// <summary>The Interactive tests pane of a guided step done there, or of the pointer and charger tests; null for the others.</summary>
    public static string? InteractivePageFor(string itemId) => itemId.ToLowerInvariant() switch
    {
        "pointer" => "interactive?test=pointer",
        "charger" => "interactive?test=charger",
        "usb-port" => "interactive?test=usbports",
        "video-output" => "interactive?test=displayoutputs",
        "ethernet" => "interactive?test=ethernet",
        _ => null,
    };

    /// <summary>Tests that load the PC: left out of a re-check while someone is at the bench, like the stress tests.</summary>
    private static readonly string[] LoadSlugs = [ModuleSlugs.Cooling, ModuleSlugs.GpuMemory];

    /// <summary>
    /// The QA selection the page starts with: the default items, plus the pointer test on a PC with a battery (a laptop's touchpad is a
    /// common refurb failure).
    /// </summary>
    public static IReadOnlyCollection<string> DefaultSelection(bool? hasBattery)
    {
        var set = new HashSet<string>(HardwareQaCertificate.DefaultSelectedItemIds, StringComparer.OrdinalIgnoreCase);
        if (hasBattery == true) set.Add("pointer");
        return set;
    }

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

    /// <summary>
    /// The guided step the run is waiting on (an item of <see cref="GuidedItemIds"/>: "keyboard", "display", "pointer", "charger", ...), or null. Every automated check has finished by then, so the page
    /// shows what needs attention and its fixes, and <see cref="RerunAsync"/> can re-check a fixed item without stopping the run.
    /// </summary>
    public string? WaitingFor { get; private set; }

    /// <summary>True while a re-check started during a person check (<see cref="WaitingFor"/>) is running.</summary>
    public bool IsRecheckRunning => Volatile.Read(ref _recheckRunning) == 1;
    private int _recheckRunning;

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
        var addedSlugs = AddedCheckItems.Where(a => selected.Contains(a.ItemId) && diag.CanRun(a.Slug)).Select(a => a.Slug).ToList();
        var gpuMemory = selected.Contains(GpuMemoryItemId) && diag.CanRun(ModuleSlugs.GpuMemory);
        // Keyboard and display keep their own steps below; the rest of the guided steps follow them in GuidedItemIds order.
        var guidedItems = GuidedItemIds.Where(id => id is not ("keyboard" or "display") && selected.Contains(id) && GuidedCanRun(id)).ToList();

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
        TotalSteps = baseStepCount + addedSlugs.Count + integrityToConsider.Count + suiteStressSlugs.Count + plainStressSlugs.Count + (gpuMemory ? 1 : 0)
            + peripheralSlugs.Count + securitySlugs.Count + keyboardStep + displayStep + guidedItems.Count + saveStep;
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

            // Step 1b: Quick hardware checks added later (USB, displays, sensors), the short drive self-test and the quick cooling test.
            // The cooling test runs before the stress tests so its low-load reading starts from a PC that isn't already hot.
            foreach (var slug in addedSlugs)
            {
                token.ThrowIfCancellationRequested();
                Status = $"Checking {diag.Catalog.DisplayName(slug)}…";
                Raise();
                await RunModuleSafeAsync(slug, token).ConfigureAwait(false);
                if (ItemForSlug(slug) is { } addedItem) MarkItemDone(addedItem, raise: false);
                CompletedSteps++;
                Raise();
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

            // Step 3b: Graphics memory (VRAM) test, Quick
            if (gpuMemory)
            {
                token.ThrowIfCancellationRequested();
                Status = $"Testing {diag.Catalog.DisplayName(ModuleSlugs.GpuMemory)} (quick)…";
                Raise();
                await RunModuleSafeAsync(ModuleSlugs.GpuMemory, token).ConfigureAwait(false);
                MarkItemDone(GpuMemoryItemId, raise: false);
                CompletedSteps++;
                Raise();
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
                await WaitForPersonAsync("keyboard", waitInteractive, token).ConfigureAwait(false);
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
                await WaitForPersonAsync("display", waitInteractive, token).ConfigureAwait(false);
                MarkItemDone("display", raise: false);
                CompletedSteps++;
                Raise();
            }

            // Step 7b: The other guided steps: pointer, charger replug, USB ports, video outputs, Ethernet
            foreach (var itemId in guidedItems)
            {
                token.ThrowIfCancellationRequested();
                Status = GuidedStatus(itemId);
                Raise();
                await WaitForPersonAsync(itemId, waitInteractive, token).ConfigureAwait(false);
                MarkItemDone(itemId, raise: false);
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

    /// <summary>The checks behind a QA item that Re-run can run again without anyone at the bench; empty for the guided steps.</summary>
    public static IReadOnlyList<string> SlugsForItem(string itemId)
    {
        if (BaseCheckItems.FirstOrDefault(b => string.Equals(b.ItemId, itemId, StringComparison.OrdinalIgnoreCase)) is { Slug: { } baseSlug }) return [baseSlug];
        if (StressItemToSlug.TryGetValue(itemId, out var stress)) return [stress];
        if (AddedCheckItems.FirstOrDefault(a => string.Equals(a.ItemId, itemId, StringComparison.OrdinalIgnoreCase)) is { Slug: { } addedSlug }) return [addedSlug];
        return itemId.ToLowerInvariant() switch
        {
            GpuMemoryItemId => [ModuleSlugs.GpuMemory],
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
    /// While a QA check only waits on the person (<see cref="WaitingFor"/>), re-checks these items beside it instead; otherwise does
    /// nothing while a QA check or another re-run is running.
    /// </summary>
    public Task RerunAsync(IReadOnlyCollection<string> itemIds, CancellationToken ct = default) => Task.Run(() => RerunCoreAsync(itemIds, ct), ct);

    private async Task RerunCoreAsync(IReadOnlyCollection<string> itemIds, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(itemIds);
        if (Interlocked.CompareExchange(ref _running, 1, 0) != 0)
        {
            // A QA check is running. Once it only waits on the person (keyboard, display), re-check the fixed items beside it.
            if (WaitingFor is not null) await RecheckWhileWaitingAsync(itemIds, ct).ConfigureAwait(false);
            return;
        }
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
                PrepareRecheck(slug);
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

    /// <summary>
    /// Runs the checks behind <paramref name="itemIds"/> again while the QA check waits on the person, without touching its progress.
    /// Stress tests are left out (they would heat the PC while someone types on it); the certificate is saved when the QA check ends.
    /// </summary>
    private async Task RecheckWhileWaitingAsync(IReadOnlyCollection<string> itemIds, CancellationToken ct)
    {
        if (Interlocked.CompareExchange(ref _recheckRunning, 1, 0) != 0) return;
        try
        {
            var slugs = itemIds.SelectMany(SlugsForItem).Where(diag.CanRun)
                .Where(s => !StressItemToSlug.Values.Contains(s, StringComparer.OrdinalIgnoreCase) && !LoadSlugs.Contains(s, StringComparer.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            log.Info($"[bench-qa] Re-check while waiting on {WaitingFor}: {string.Join(", ", itemIds)} -> {string.Join(", ", slugs)}");
            Raise();
            foreach (var slug in slugs)
            {
                ct.ThrowIfCancellationRequested();
                PrepareRecheck(slug);
                await RunModuleSafeAsync(slug, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            log.Warn($"[bench-qa] Re-check failed: {ex}");
        }
        finally
        {
            Volatile.Write(ref _recheckRunning, 0);
            Raise();
        }
    }

    /// <summary>The security audit re-checks only the settings that failed or warned, not all 400.</summary>
    private void PrepareRecheck(string slug)
    {
        if (slug == ModuleSlugs.SecurityAudit
            && diag.Catalog.ModuleFor(ModuleIds.SecurityAudit) is Security.SecurityAuditModule audit
            && store.Get(slug).Payload is Security.SecurityAuditReport rep && rep.NeedsAttention.Count > 0)
            audit.RecheckOnNextRun(rep.NeedsAttention.Select(f => f.Id));
    }

    private CancellationTokenSource? _skipCts;

    /// <summary>Skips the guided step the run is waiting on (<see cref="WaitingFor"/>); the run carries on with the next one.</summary>
    public void SkipWaiting()
    {
        CancellationTokenSource? skip;
        lock (_gate) skip = _skipCts;
        if (skip is null) return;
        log.Info($"[bench-qa] Skipped the {WaitingFor} step");
        try { skip.Cancel(); } catch (ObjectDisposedException) { }
    }

    /// <summary>
    /// Waits for the person to finish a guided step. The run owns this wait, not the page: leaving the QA page (to fix a failed item on
    /// its own page, or to do the USB port check on the Interactive tests page) doesn't stop the run, and coming back shows it still waiting.
    /// </summary>
    private async Task WaitForPersonAsync(string section, Func<string, CancellationToken, Task>? waitInteractive, CancellationToken token)
    {
        using var skip = CancellationTokenSource.CreateLinkedTokenSource(token);
        lock (_gate) _skipCts = skip;
        WaitingFor = section;
        Raise();
        try
        {
            var t = skip.Token;
            if (waitInteractive is not null) await waitInteractive(section, t).ConfigureAwait(false);
            else if (section is "keyboard" or "display")
            {
                if (physicalQa is not null) await WaitForOutcomeAsync(physicalQa, section, t).ConfigureAwait(false);
            }
            else if (section == "pointer")
            {
                if (pointerTest is not null) await WaitForPointerAsync(pointerTest, t).ConfigureAwait(false);
            }
            else if (section == "charger")
            {
                // The charger test runs here; its prompts (unplug, plug back in) show as the status.
                await RunModuleSafeAsync(ModuleSlugs.ChargerReplug, t, new Progress<string>(prompt =>
                {
                    Status = $"Charger replug test: {prompt}";
                    Raise();
                })).ConfigureAwait(false);
            }
            else if (GuidedItemToSlug.TryGetValue(section, out var slug))
            {
                await WaitForResultAsync(slug, t).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            // Skipped: the item keeps whatever result it had (usually Not run) and the run goes on.
        }
        finally
        {
            lock (_gate) _skipCts = null;
            WaitingFor = null;
        }
    }

    private static string GuidedStatus(string itemId) => itemId switch
    {
        "pointer" => "Mouse, touchpad & touchscreen test: go through the steps on the device…",
        "charger" => "Charger replug test: unplug the charger, then plug it back in…",
        "usb-port" => "USB port check: open it, then plug a USB stick into each port…",
        "video-output" => "Video output check: open it, then plug a monitor into each video port…",
        "ethernet" => "Ethernet port test: open it, then plug in a network cable or a loopback plug…",
        _ => $"Waiting on the {itemId} check…",
    };

    /// <summary>Whether a guided step other than keyboard and display can run here (the charger test needs a battery).</summary>
    private bool GuidedCanRun(string itemId) => itemId switch
    {
        "pointer" => pointerTest is not null,
        "charger" => diag.CanRun(ModuleSlugs.ChargerReplug) && (power ?? new WindowsPowerLineSource()).Read() is not { HasBattery: false },
        _ => GuidedItemToSlug.TryGetValue(itemId, out var slug) && diag.CanRun(slug),
    };

    /// <summary>Done when the check (run on the Interactive tests page) has a finished result newer than the wait.</summary>
    private async Task WaitForResultAsync(string slug, CancellationToken token)
    {
        var startUtc = DateTimeOffset.UtcNow;
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnChanged(object? sender, DiagnosticResult r)
        {
            if (string.Equals(r.ModuleName, slug, StringComparison.OrdinalIgnoreCase)
                && r.Status is DiagnosticStatus.Ok or DiagnosticStatus.Warning or DiagnosticStatus.Error
                && r.Timestamp.ToUniversalTime() >= startUtc)
                done.TrySetResult();
        }
        store.Changed += OnChanged;
        try
        {
            using var reg = token.Register(() => done.TrySetCanceled(token));
            await done.Task.ConfigureAwait(false);
        }
        finally
        {
            store.Changed -= OnChanged;
        }
    }

    /// <summary>Done when a pointer test that started after the wait began finishes; its result goes onto the certificate.</summary>
    private async Task WaitForPointerAsync(PointerTestService pointer, CancellationToken token)
    {
        var startUtc = DateTimeOffset.UtcNow;
        var done = new TaskCompletionSource<PointerTestSnapshot>(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnChanged()
        {
            var s = pointer.Current;
            if (s.Verdict is not (PointerTestVerdict.NotRun or PointerTestVerdict.Running) && s.StartedUtc >= startUtc && s.FinishedUtc is not null)
                done.TrySetResult(s);
        }
        pointer.Changed += OnChanged;
        try
        {
            using var reg = token.Register(() => done.TrySetCanceled(token));
            var snap = await done.Task.ConfigureAwait(false);
            physicalQa?.Update(q => q with { PointerOutcome = PointerOutcome(snap), PointerSummary = PointerSummary(snap) });
        }
        finally
        {
            pointer.Changed -= OnChanged;
        }
    }

    internal static PhysicalCheckOutcome PointerOutcome(PointerTestSnapshot s) => s.Verdict switch
    {
        PointerTestVerdict.Passed => s.Steps.Any(st => st.State is PointerStepState.Skipped) ? PhysicalCheckOutcome.PassedWithNote : PhysicalCheckOutcome.Passed,
        PointerTestVerdict.Failed => PhysicalCheckOutcome.Failed,
        _ => PhysicalCheckOutcome.NotRun,
    };

    internal static string PointerSummary(PointerTestSnapshot s)
    {
        var name = s.Device?.Name is { Length: > 0 } n ? $"{n}: " : "";
        var passed = s.Steps.Count(st => st.State == PointerStepState.Passed);
        var parts = new List<string> { $"{name}{passed} of {s.Steps.Count} steps passed" };
        var failed = s.Steps.Where(st => st.State == PointerStepState.Failed).Select(st => PointerTestService.Title(st.Step)).ToList();
        if (failed.Count > 0) parts.Add($"failed: {string.Join(", ", failed)}");
        var skipped = s.Steps.Where(st => st.State == PointerStepState.Skipped).Select(st => PointerTestService.Title(st.Step)).ToList();
        if (skipped.Count > 0) parts.Add($"skipped: {string.Join(", ", skipped)}");
        if (s.Verdict == PointerTestVerdict.Cancelled) parts.Add("stopped before the end");
        return string.Join(" · ", parts);
    }

    /// <summary>Done when the check has an outcome that is new since the wait began (set again, or changed).</summary>
    private static async Task WaitForOutcomeAsync(PhysicalBenchQaService qa, string section, CancellationToken token)
    {
        static PhysicalCheckOutcome Outcome(PhysicalBenchQaSnapshot s, string section) => section == "keyboard" ? s.KeyboardOutcome : s.DisplayOutcome;
        var startUtc = DateTimeOffset.UtcNow;
        var initial = Outcome(qa.Current, section);
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnChanged()
        {
            var snap = qa.Current;
            var now = Outcome(snap, section);
            if (now != PhysicalCheckOutcome.NotRun && (snap.UpdatedUtc >= startUtc || now != initial)) done.TrySetResult();
        }
        qa.Changed += OnChanged;
        try
        {
            using var reg = token.Register(() => done.TrySetCanceled(token));
            await done.Task.ConfigureAwait(false);
        }
        finally
        {
            qa.Changed -= OnChanged;
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

    private async Task RunModuleSafeAsync(string slug, CancellationToken ct, IProgress<string>? progress = null)
    {
        var restore = UseQaMode(slug);
        try
        {
            await diag.RunAsync(slug, progress, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            log.Warn($"[bench-qa] {slug} failed: {ex.Message}");
        }
        finally
        {
            restore?.Invoke();
        }
    }

    /// <summary>
    /// The QA check runs the short form of the tests that have one: the short drive self-test on every drive, the Quick graphics memory
    /// test, and the quick cooling test without switching thermal modes. Returns what puts the person's own choice back afterwards.
    /// </summary>
    private Action? UseQaMode(string slug)
    {
        if (slug == ModuleSlugs.DriveSelfTest && diag.Catalog.ModuleFor(ModuleIds.DriveSelfTest) is DriveSelfTestModule selfTest)
        {
            var (mode, disks) = (selfTest.Mode, selfTest.Disks);
            selfTest.Mode = SelfTestKind.Short;
            selfTest.Disks = null;
            return () => { selfTest.Mode = mode; selfTest.Disks = disks; };
        }
        if (slug == ModuleSlugs.GpuMemory && diag.Catalog.ModuleFor(ModuleIds.GpuMemory) is GpuMemoryModule vram)
        {
            var mode = vram.Mode;
            vram.Mode = GpuMemoryMode.Quick;
            return () => vram.Mode = mode;
        }
        if (slug == ModuleSlugs.Cooling && diag.Catalog.ModuleFor(ModuleIds.Cooling) is CoolingTestModule cooling)
        {
            var (mode, switchModes) = (cooling.Mode, cooling.SwitchModes);
            cooling.Mode = CoolingTestMode.Quick;
            cooling.SwitchModes = false;
            return () => { cooling.Mode = mode; cooling.SwitchModes = switchModes; };
        }
        return null;
    }

    /// <summary>Whether a selected item has a check this PC can run now (keyboard and display are checked by the person, so always).</summary>
    private bool ItemCanRun(string itemId, List<string> suiteStressSlugs, List<string> plainStressSlugs)
    {
        if (itemId is "keyboard" or "display") return true;
        if (GuidedItemIds.Contains(itemId)) return GuidedCanRun(itemId);
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
        return AddedCheckItems.FirstOrDefault(a => string.Equals(a.Slug, slug, StringComparison.OrdinalIgnoreCase)).ItemId;
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
