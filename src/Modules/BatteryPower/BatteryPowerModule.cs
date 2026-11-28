using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Battery health (wear level, cycle count, charge state) and the active Windows power plan, read from <paramref name="source"/>: WMI through
/// the Agent in the app, and in the Store edition the legacy osquery + powercfg reader when no Agent is connected.
/// </summary>
public sealed class BatteryPowerModule(IBatteryPowerSource source, ILogger? log = null, Func<TimeSpan, CancellationToken, Task>? delay = null,
    History.IHistoryStore? history = null) : AreaModuleBase(log)
{
    public const string ModuleName = ModuleSlugs.BatteryPower;
    public const int LowBatteryHealthPercent = BatteryStatus.LowHealthPercent;
    public const int PerformanceLimitWarningThreshold = 90;
    public static readonly TimeSpan ConfirmationDelay = TimeSpan.FromSeconds(5);

    private readonly Func<TimeSpan, CancellationToken, Task> _delay = delay ?? Task.Delay;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.BatteryPower;
    public override string DisplayName => "Battery & power plan";
    protected override string FailedMessage => "Couldn't read battery and power settings on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 3, "Checking battery health…");
        var batteries = await source.ReadBatteriesAsync(ct).ConfigureAwait(false);
        var perf = await source.ReadProcessorPerformanceAsync(ct).ConfigureAwait(false);
        IReadOnlyList<Battery.HpBatterySetting> hp = [];
        if (batteries is { Count: > 0 })
        {
            try { hp = await source.ReadHpChargeSettingsAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { LogWarn($"{Name}: HP battery settings unreadable: {ex.Message}"); }
        }

        var onAc1 = IsOnAcPower(batteries);
        var discharging1 = batteries is { Count: > 0 } && batteries.Any(b => b.IsDischargingOnAc);
        var heldBack1 = onAc1 && perf?.PerformanceLimitPercent is > 0 and < PerformanceLimitWarningThreshold;
        // A fault in one reading can be a moment's glitch (plugging in, a driver update): it counts only if the next reading has it too.
        var faulty1 = batteries is { Count: > 0 } && batteries.Any(b => BatteryCondition.Faults(b).Any(f => f.Level == AreaLevel.Error));

        var confirmedDischargingOnAc = false;
        var confirmedHeldBackOnAc = false;

        // Fast path: only wait 5 s for a second confirmation sample when the first sample looks suspicious.
        if (discharging1 || heldBack1 || faulty1)
        {
            progress.ReportStep(1, 3, "Confirming power and processor limit…");
            await _delay(ConfirmationDelay, ct).ConfigureAwait(false);

            if (discharging1 || faulty1)
            {
                var batteries2 = await source.ReadBatteriesAsync(ct).ConfigureAwait(false);
                if (batteries2 is not null) batteries = batteries2;
                confirmedDischargingOnAc = discharging1 && batteries2 is { Count: > 0 } && batteries2.Any(b => b.IsDischargingOnAc);
            }

            if (heldBack1)
            {
                var perf2 = await source.ReadProcessorPerformanceAsync(ct).ConfigureAwait(false);
                var onAc2 = IsOnAcPower(batteries);
                confirmedHeldBackOnAc = onAc2 && perf2?.PerformanceLimitPercent is > 0 and < PerformanceLimitWarningThreshold;
                if (perf2 is not null) perf = perf2;
            }
        }

        BatteryConditionInput? condition = null;
        if (batteries is { Count: > 0 })
        {
            var (input, latest) = await CheckConditionAsync(batteries, hp, progress, ct).ConfigureAwait(false);
            condition = input;
            if (latest is not null) batteries = latest;
        }

        progress.ReportStep(3, 3, "Checking active power plan…");
        var plan = await source.ReadActivePlanAsync(ct).ConfigureAwait(false);
        var policy = await source.ReadPowerPolicyAsync(ct).ConfigureAwait(false);
        if (batteries is null && plan is null) return AreaReport.Failed(FailedMessage);
        ChargerReading? charger = null;
        if (batteries is not { Count: 0 })
        {
            try { charger = await source.ReadChargerAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { LogWarn($"{Name}: charger readings unreadable: {ex.Message}"); }
        }
        return Build(batteries, plan, confirmedDischargingOnAc, confirmedHeldBackOnAc, perf, policy, hp, condition, charger);
    }

    /// <summary>
    /// The charging check and the History comparison. When one reading can't tell whether a battery on AC charges, reads every
    /// <see cref="BatteryCondition.ChargeSampleEvery"/> for up to <see cref="BatteryCondition.ChargeWatch"/>, stopping as soon as it charges.
    /// Read-only, so safe in Run all; cancelling stops the wait.
    /// </summary>
    private async Task<(BatteryConditionInput Input, IReadOnlyList<BatteryStatus>? Latest)> CheckConditionAsync(
        IReadOnlyList<BatteryStatus> first, IReadOnlyList<Battery.HpBatterySetting> hp, IProgress<string>? progress, CancellationToken ct)
    {
        var limit = BatteryCondition.ChargeLimitPercent(hp);
        var last = first;
        var watched = TimeSpan.Zero;
        var watchedBatteries = first.Select((b, i) => (b, i)).Where(x => BatteryCondition.NeedsChargeWatch(x.b, limit)).ToList();
        if (watchedBatteries.Count > 0)
        {
            while (watched < BatteryCondition.ChargeWatch)
            {
                progress.ReportStep(2, 3, $"Checking that the battery charges ({(int)watched.TotalSeconds} of {(int)BatteryCondition.ChargeWatch.TotalSeconds} s)…");
                await _delay(BatteryCondition.ChargeSampleEvery, ct).ConfigureAwait(false);
                watched += BatteryCondition.ChargeSampleEvery;
                if (await source.ReadBatteriesAsync(ct).ConfigureAwait(false) is not { Count: > 0 } next) break;
                last = next;
                // Unplugged meanwhile, or every watched battery now shows charge going in: nothing more to wait for.
                var w = watched;
                if (!next.Any(b => b.IsOnAc) || watchedBatteries.Select(x => BatteryCondition.JudgeCharging(x.b, Same(next, x.b, x.i) ?? x.b, w, limit))
                        .All(c => c.Outcome is not (ChargeOutcome.NotCharging or ChargeOutcome.HeldBelowFull)))
                    break;
            }
        }
        var charging = first.Select((b, i) => Same(last, b, i) is { } now
            ? BatteryCondition.JudgeCharging(b, now, BatteryCondition.NeedsChargeWatch(b, limit) ? watched : TimeSpan.Zero, limit)
            : null).ToList();

        IReadOnlyList<PreviousCapacity?>? previous = null;
        if (history is not null)
        {
            try
            {
                var read = await Task.Run(() => history.Read(HistoryWindow), ct).ConfigureAwait(false);
                previous = BatteryCondition.PreviousCapacities(read.Entries, last.Count, DateTimeOffset.UtcNow.AddMinutes(-1));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { LogWarn($"{Name}: History unreadable: {ex.Message}"); }
        }
        return (new BatteryConditionInput(charging, previous), ReferenceEquals(last, first) ? null : last);
    }

    /// <summary>How far back History is searched for the last full charge capacity.</summary>
    public static readonly TimeSpan HistoryWindow = TimeSpan.FromDays(180);

    private static BatteryStatus? Same(IReadOnlyList<BatteryStatus> list, BatteryStatus b, int index) =>
        list.FirstOrDefault(x => x.InstanceName.Length > 0 && x.InstanceName == b.InstanceName) ?? (index < list.Count ? list[index] : null);

    /// <summary>
    /// HP's charge limit: a neutral card (it never changes the check's result) saying whether charging stops at about 80%, with the fix when
    /// it doesn't. Null on PCs without HP's setting.
    /// </summary>
    public static AreaCard? ChargeLimitCard(IReadOnlyList<Battery.HpBatterySetting>? settings)
    {
        // Battery Health Manager is HP's newer setting; on a PC with both it's the one that counts.
        var s = settings?.FirstOrDefault(x => x.Name == Battery.HpBatteryCharge.HealthManager && x.LimitValue is not null)
            ?? settings?.FirstOrDefault(x => x.LimitValue is not null);
        if (s is null) return null;
        var limited = s.IsLimited;
        return new("charge-limit", "Battery charge limit", limited ? AreaLevel.Ok : AreaLevel.Neutral,
            limited ? "Charging stops at about 80%" : "Charges to 100%",
            limited ? "Set in HP's BIOS" : "A PC that stays plugged in wears its battery out faster at 100%",
            ["Detail", "Value"],
            [new(AreaLevel.Neutral, [s.Name, s.CurrentValue]), new(AreaLevel.Neutral, ["Values it can take", string.Join(", ", s.PossibleValues)])],
            Note: limited ? null : "HP's BIOS can stop charging at about 80%, which keeps a battery that's usually plugged in healthy for longer. It takes effect after a restart.",
            Actions: limited ? null : [new(RemediationKind.SetHpBatteryChargeLimit, "Limit charging to 80%", Battery.HpBatteryCharge.Target(s.Name, s.LimitValue!), "Battery charge limit")]);
    }

    private static bool IsOnAcPower(IReadOnlyList<BatteryStatus>? batteries) =>
        batteries is { Count: > 0 } ? batteries.Any(b => b.IsOnAc) : batteries is not null;

    public static AreaReport Build(
        IReadOnlyList<BatteryStatus>? batteries,
        string? powerPlan,
        bool dischargingOnAc = false,
        bool heldBackOnAc = false,
        ProcessorPerformanceSample? processorPerf = null,
        PowerPolicySnapshot? policy = null,
        IReadOnlyList<Battery.HpBatterySetting>? hpCharge = null,
        BatteryConditionInput? condition = null,
        ChargerReading? charger = null)
    {
        if (batteries is null && powerPlan is null) return AreaReport.Failed("Couldn't read battery and power settings on this PC.");
        var cards = new List<AreaCard>();
        var parts = new List<string>();
        var metrics = new List<KeyMetric>();

        if (batteries is null)
            cards.Add(AreaCard.Failed("battery", "Battery health", "Couldn't read battery details."));
        else if (batteries.Count == 0)
        {
            cards.Add(new("battery", "Battery health", AreaLevel.Neutral, "No battery (desktop / AC only)",
                "This PC runs directly on wall power", ["Detail", "Value"],
                [new(AreaLevel.Neutral, ["Power source", "AC power (no battery installed)"])]));
            parts.Add("No battery (AC power)");
        }
        else
        {
            for (var i = 0; i < batteries.Count; i++)
            {
                var b = batteries[i];
                // The confirmed drain is the PC's; with several batteries it belongs to the ones that drain.
                var draining = dischargingOnAc && (batteries.Count == 1 || b.IsDischargingOnAc);
                var charging = condition?.Charging is { } c && i < c.Count ? c[i] : null;
                var previous = condition?.Previous is { } pv && i < pv.Count ? pv[i] : null;
                cards.Add(BatteryCondition.Card(b, i, batteries.Count, draining, charging, previous));
                // Tracked over time: health falling (or capacity dropping) faster than normal is the early sign of a battery to replace.
                metrics.AddRange(CheckKeyMetrics.Battery(b, i));
            }
            var b0 = batteries[0];
            var errorCard = cards.TakeLast(batteries.Count).FirstOrDefault(c => c.Level == AreaLevel.Error);
            parts.Add(errorCard is not null ? errorCard.Headline
                : dischargingOnAc ? "Plugged in, discharging"
                : b0.HealthPercent is { } h2 ? $"Battery health {h2}%" + (b0.PercentRemaining is { } pr ? $" · {pr}% charged" : "") : "Battery present");
            if (batteries.Count > 1) parts.Add($"{batteries.Count} batteries");
        }

        var planName = string.IsNullOrWhiteSpace(powerPlan) ? "Not reported" : powerPlan.Trim();
        var isSaver = planName.Contains("Power saver", StringComparison.OrdinalIgnoreCase) || planName.Contains("Energy Saver", StringComparison.OrdinalIgnoreCase);
        var acCap = policy?.AcMaxProcessorStatePercent is >= 0 and <= 100 and var capVal ? capVal : (int?)null;
        var hasAcCapWarning = acCap is < 100;
        var planRows = new List<AreaRow>
        {
            new(isSaver ? AreaLevel.Warning : AreaLevel.Ok, ["Active power plan", planName]),
        };
        if (policy?.PowerMode is { Length: > 0 } powerMode)
            planRows.Add(new(AreaLevel.Neutral, ["Power mode", powerMode]));
        if (acCap is { } configuredCap)
        {
            var capText = configuredCap < 100
                ? $"Configured maximum processor state on AC is {configuredCap}%"
                : "100%";
            planRows.Add(new(hasAcCapWarning ? AreaLevel.Warning : AreaLevel.Ok, ["Configured maximum processor state (AC)", capText]));
        }
        if (heldBackOnAc && processorPerf?.PerformanceLimitPercent is { } perfLimit)
        {
            planRows.Add(new(AreaLevel.Warning, ["Processor performance limit (AC)", $"{perfLimit}% — The processor is being held back while plugged in (weak charger, dock or heat)."]));
        }
        planRows.Add(new(AreaLevel.Neutral, ["Impact", isSaver ? "Power saver caps processor clock speeds and can make the PC feel slow." : "Normal processor speed scaling enabled."]));

        var planLevel = (isSaver || hasAcCapWarning || heldBackOnAc) ? AreaLevel.Warning : AreaLevel.Ok;
        var planNotes = new List<string>();
        if (heldBackOnAc)
            planNotes.Add("The processor is being held back while plugged in (weak charger, dock or heat).");
        if (hasAcCapWarning)
            planNotes.Add($"Configured maximum processor state on AC is {acCap}%. This is a configured power-plan limit; effective behavior can also depend on Windows Power mode, Energy Saver, or OEM controls.");

        var planActions = new List<AreaAction>();
        if (isSaver)
            planActions.Add(new(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced plan", RemediationService.BalancedPlanGuid, "Balanced power plan"));
        if (hasAcCapWarning && policy?.AcMaxProcessorStateEditable != false)
            planActions.Add(new(RemediationKind.ResetMaxProcessorState, "Set max processor state to 100%", "", "Maximum processor state (AC)"));
        if (hasAcCapWarning && policy?.AcMaxProcessorStateEditable == false)
            planNotes.Add("This setting is controlled by Group Policy and cannot be edited here.");

        cards.Add(new("plan", "Windows power plan", planLevel, planName,
            isSaver ? "Power saver reduces CPU speed to save battery"
                : heldBackOnAc ? "Processor held back while plugged in"
                : hasAcCapWarning ? $"Configured maximum processor state on AC is {acCap}%"
                : "Active power scheme",
            ["Detail", "Value"],
            planRows,
            Note: planNotes.Count > 0 ? string.Join(" ", planNotes) : null,
            Actions: planActions.Count > 0 ? planActions : null));
        if (ChargeLimitCard(hpCharge) is { } chargeCard) cards.Add(chargeCard);
        var chargerCard = ChargerCheck.Card(batteries, charger, dischargingOnAc, heldBackOnAc, processorPerf);
        cards.Add(chargerCard);
        if (chargerCard.Level >= AreaLevel.Warning) parts.Add("charger " + chargerCard.Headline.ToLowerInvariant());
        if (!string.IsNullOrWhiteSpace(powerPlan)) parts.Add($"{planName} plan");
        if (heldBackOnAc) parts.Add("processor held back on AC");

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, string.Join(" · ", parts), status) { KeyMetrics = metrics.Count > 0 ? metrics : null };
    }
}
