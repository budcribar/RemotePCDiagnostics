using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Modules.Sound;

/// <summary>One audio driver from WMI <c>Win32_PnPSignedDriver</c> (DeviceClass MEDIA).</summary>
public sealed record AudioDriver(string DeviceName, string DeviceId, string HardwareId, string InfName, string Provider, string Version);

/// <summary>What the Sound check reads besides Core Audio. Null members couldn't be read; their rows are left out.</summary>
public sealed record SoundFacts(
    IReadOnlyList<ServiceInfo>? Services = null,
    IReadOnlyList<ServiceInfo>? ServicesAgain = null,
    IReadOnlyList<ProblemDevice>? Problems = null,
    IReadOnlyList<AudioDriver>? Drivers = null,
    bool? HasBattery = null,
    CapturePrivacy.Switches? MicPrivacy = null,
    bool? MonoAudio = null);

/// <summary>
/// Sound: the checks HP's Audio Check runs for the speaker and the microphone (service, disabled, muted, low volume, default device,
/// unplugged, device problem, enhancements, format, generic driver), plus mic privacy, a device held in exclusive mode, an app muted in the
/// Volume mixer, a Bluetooth headset in call mode, sound to a monitor and mono audio. The fixes run in the app (Core Audio and IPolicyConfig
/// in the user's session); the ones that need a choice open a dialog: the device picker, microphone access (with consent) and device busy.
/// Core Audio is read by the app in the user's session (<see cref="IAudioStateSource"/>); services, devices and drivers come from WMI
/// (through the Agent); privacy and mono audio from the registry.
/// </summary>
public sealed class SoundModule(IAudioStateSource audio, IServiceSource services, IDeviceDriverSource devices, IWmiSource wmi, IRegistrySource registry,
    ILogger? log = null, TimeSpan? pendingRecheck = null) : AreaModuleBase(log)
{
    public const string ModuleName = ModuleSlugs.Sound;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.Sound;
    public override string DisplayName => "Sound";
    protected override string FailedMessage => "Couldn't check sound on this PC.";

    public const string AudioSrv = "Audiosrv", EndpointBuilder = "AudioEndpointBuilder";

    /// <summary>Output volume below this (0 to 1) is a warning.</summary>
    public const double LowOutputVolume = 0.10;
    /// <summary>Microphone level below this (0 to 1) is a warning.</summary>
    public const double LowInputVolume = 0.25;

    public const string DriversSql =
        "SELECT DeviceName, DeviceID, HardWareID, InfName, DriverProviderName, DriverVersion FROM Win32_PnPSignedDriver WHERE DeviceClass = 'MEDIA'";
    public const string MonoKey = @"Software\Microsoft\Multimedia\Audio";

    /// <summary>HD Audio codec makers that ship their own drivers (the <c>VEN_</c> in <c>HDAUDIO\FUNC_01&amp;VEN_10EC&amp;DEV_0257</c>):
    /// Realtek, Conexant/Synaptics, Cirrus Logic, IDT/Tempo, VIA. Windows' generic hdaudio.inf on one of these is worth a warning.</summary>
    public static readonly IReadOnlyDictionary<string, string> OemCodecVendors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["10EC"] = "Realtek", ["14F1"] = "Conexant", ["1013"] = "Cirrus Logic", ["111D"] = "IDT", ["1106"] = "VIA",
    };

    private readonly TimeSpan _pendingRecheck = pendingRecheck ?? TimeSpan.FromSeconds(3);

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 3, "Reading sound devices…");
        var state = await audio.ReadAsync(ct).ConfigureAwait(false);
        progress.ReportStep(2, 3, "Checking the Windows Audio services…");
        IReadOnlyList<ServiceInfo>? svc = null, again = null;
        try
        {
            svc = await services.ReadServicesAsync(ct).ConfigureAwait(false);
            // A service stuck starting or stopping: look again shortly, so a service that was just starting isn't flagged.
            if (svc is not null && AudioServices(svc).Any(s => IsPending(s)))
            {
                await Task.Delay(_pendingRecheck, ct).ConfigureAwait(false);
                again = await services.ReadServicesAsync(ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { LogWarn($"{Name}: services unreadable: {ex.Message}"); }
        progress.ReportStep(3, 3, "Checking sound drivers and settings…");
        var problems = await Try(() => devices.ReadProblemDevicesAsync(ct), "problem devices").ConfigureAwait(false);
        var drivers = await ReadDriversAsync(ct).ConfigureAwait(false);
        var battery = await HasBatteryAsync(ct).ConfigureAwait(false);
        CapturePrivacy.Switches? mic = null;
        try { mic = await CapturePrivacy.ReadAsync(registry, CapturePrivacy.Microphone, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"{Name}: microphone privacy unreadable: {ex.Message}"); }
        var mono = await ReadMonoAsync(ct).ConfigureAwait(false);
        if (state.Error is { } err) LogWarn($"{Name}: audio devices unreadable: {err}");
        return Build(state, new SoundFacts(svc, again, problems, drivers, battery, mic?.Read == true ? mic : null, mono));
    }

    private async Task<T?> Try<T>(Func<Task<T?>> read, string what) where T : class
    {
        try { return await read().ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"{Name}: {what} unreadable: {ex.Message}"); return null; }
    }

    private async Task<IReadOnlyList<AudioDriver>?> ReadDriversAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, DriversSql, ct).ConfigureAwait(false);
        return q.Success
            ? q.Rows!.Select(r => new AudioDriver(r.Str("DeviceName"), r.Str("DeviceID"), r.Str("HardWareID"), r.Str("InfName"),
                r.Str("DriverProviderName"), r.Str("DriverVersion"))).Where(d => d.DeviceName.Trim().Length > 0).ToList()
            : null;
    }

    private async Task<bool?> HasBatteryAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(BatteryReader.WmiNamespace, BatteryReader.StaticSql, ct).ConfigureAwait(false);
        return q.Success ? q.Rows!.Count > 0 : BatteryReader.IsNoBattery(q.Error) ? false : null;
    }

    private async Task<bool?> ReadMonoAsync(CancellationToken ct)
    {
        var r = await registry.ReadAsync(new RegistryRead(RegistryRoot.CurrentUser, MonoKey, ["AccessibilityMonoMixState"]), ct).ConfigureAwait(false);
        if (!r.Success) return null;
        return r.Rows?.FirstOrDefault()?.Long("AccessibilityMonoMixState") == 1;
    }

    // ---------------------------------------------------------------- building the report (no I/O, for tests)

    private static IEnumerable<ServiceInfo> AudioServices(IEnumerable<ServiceInfo> all) =>
        all.Where(s => s.Name.Equals(AudioSrv, StringComparison.OrdinalIgnoreCase) || s.Name.Equals(EndpointBuilder, StringComparison.OrdinalIgnoreCase));

    private static bool IsPending(ServiceInfo s) => s.Status.EndsWith("_PENDING", StringComparison.OrdinalIgnoreCase);

    private static readonly string[] Columns = ["Check", "Result", "Details"];
    private const string NoIssues = "No issues found";

    public static AreaReport Build(AudioState state, SoundFacts facts)
    {
        var serviceHung = state.Endpoints.Any(e => e.IsDefault && e.Probe is AudioProbeOutcome.TimedOut or AudioProbeOutcome.ServiceNotRunning);
        var cards = new List<AreaCard>();
        var generic = GenericDrivers(facts.Drivers);
        if (state.Available)
        {
            cards.Add(FlowCard(state, facts, AudioFlow.Output, generic));
            cards.Add(FlowCard(state, facts, AudioFlow.Input, generic));
        }
        else
        {
            cards.Add(AreaCard.Failed("audio-output", "Speakers & headphones", "Couldn't read the sound devices on this PC."));
            cards.Add(AreaCard.Failed("audio-input", "Microphones", "Couldn't read the microphones on this PC."));
        }
        cards.Add(ServicesCard(facts, serviceHung, state.Available));
        if (cards.All(c => c.Level == AreaLevel.Error)) return AreaReport.Failed("Couldn't check sound on this PC.");

        var problems = cards.SelectMany(c => c.Rows).Where(r => r.Level >= AreaLevel.Warning).ToList();
        var status = AreaReport.Worst(cards.Where(c => c.ErrorText is null).Select(c => c.Level));
        var summary = problems.Count == 0 ? "No sound problems found"
            : $"{AreaModuleBase.Plural(problems.Count, "sound problem")}: {problems[0].Values[0].ToLowerInvariant()}";
        return new AreaReport(cards, summary, status);
    }

    private static AreaRow Row(AreaLevel level, string check, string result, string details = "", string? key = null, IReadOnlyList<AreaAction>? actions = null) =>
        new(level, [check, result, details], Key: key, Actions: actions);

    private static string Percent(double v) => $"{Math.Round(v * 100):0}%";

    private static AreaCard FlowCard(AudioState state, SoundFacts facts, AudioFlow flow, IReadOnlyList<(AudioDriver Driver, string Vendor)> generic)
    {
        var output = flow == AudioFlow.Output;
        var id = output ? "audio-output" : "audio-input";
        var title = output ? "Speakers & headphones" : "Microphones";
        var thing = output ? "speaker" : "microphone";
        var mine = state.Endpoints.Where(e => e.Flow == flow).ToList();
        var active = mine.Where(e => e.IsActive).ToList();
        var def = active.FirstOrDefault(e => e.DefaultFor.Contains(AudioEndpointInfo.Multimedia)) ?? active.FirstOrDefault(e => e.IsDefault);
        var rows = new List<AreaRow>();

        var policy = state.CanChangeSettings != false; // unknown: offered, and the fix fails closed
        AreaAction picker = Picker(state, flow);
        IReadOnlyList<AreaAction>? Pick() => policy && active.Count > 0 ? [picker] : null;

        // Default device
        if (active.Count == 0)
        {
            var missingLevel = output ? facts.HasBattery == true ? AreaLevel.Warning : AreaLevel.Neutral : AreaLevel.Neutral;
            rows.Add(Row(missingLevel, "Default device", output ? "No speakers or headphones found" : "No microphone found",
                output && facts.HasBattery == true ? "A laptop has built-in speakers: they may be disabled or their driver may be missing." : ""));
        }
        else if (def is null)
            rows.Add(Row(AreaLevel.Warning, "Default device", "No default device", $"Windows has no default {thing}, so apps may have nowhere to send sound.", "default", Pick()));
        else
        {
            var calls = active.FirstOrDefault(e => e.IsDefaultForCalls);
            var detail = calls is not null && calls.Id != def.Id ? $"Calls use {calls.Name}." : "";
            rows.Add(Row(AreaLevel.Ok, "Default device", def.Name, detail));
        }

        // Disabled or unplugged
        var off = mine.Where(e => e.State is AudioEndpointState.Disabled or AudioEndpointState.Unplugged).ToList();
        IReadOnlyList<AreaAction>? enable = policy && off.Any(e => e.State == AudioEndpointState.Disabled)
            ? off.Where(e => e.State == AudioEndpointState.Disabled).Select(e => new AreaAction(RemediationKind.EnableAudioEndpoint, $"Turn on {e.Name}", e.Id, e.Name)).ToList()
            : null;
        if (active.Count == 0 && off.Count > 0)
            rows.Add(Row(AreaLevel.Warning, "Disabled or unplugged", string.Join(", ", off.Select(e => $"{e.Name}: {e.FriendlyState.ToLowerInvariant()}")),
                off.Any(e => e.State == AudioEndpointState.Disabled) ? "Turn the device back on." : "Plug the device in, or check the jack.", "off", enable));
        else if (off.Count > 0)
            rows.Add(Row(AreaLevel.Neutral, "Disabled or unplugged", AreaModuleBase.Plural(off.Count, "other device"),
                string.Join(", ", off.Select(e => $"{e.Name} ({e.FriendlyState.ToLowerInvariant()})")), "off", enable));
        else rows.Add(Row(AreaLevel.Ok, "Disabled or unplugged", NoIssues));

        // Muted and volume (the default device)
        if (def is not null)
        {
            if (def.Muted == true) rows.Add(Row(AreaLevel.Warning, "Muted", $"{def.Name} is muted", "", "mute",
                [new AreaAction(RemediationKind.UnmuteAudioEndpoint, "Unmute", def.Id, def.Name)]));
            else if (def.Muted == false) rows.Add(Row(AreaLevel.Ok, "Muted", NoIssues));
            var low = output ? LowOutputVolume : LowInputVolume;
            if (def.Volume is { } v)
                rows.Add(v < low
                    ? Row(AreaLevel.Warning, output ? "Low volume" : "Low microphone level", $"{Percent(v)}",
                        output ? "Very quiet or silent at this volume." : "Others may not hear you at this level.", "volume",
                        [new AreaAction(RemediationKind.RaiseAudioVolume, output ? "Raise volume to 50%" : "Raise level to 80%", def.Id, def.Name)])
                    : Row(AreaLevel.Ok, output ? "Low volume" : "Low microphone level", NoIssues, Percent(v)));
        }

        // Busy or not answering (the shared-mode open of the default device)
        if (def is not null && def.Probe != AudioProbeOutcome.NotRun)
            rows.Add(def.Probe switch
            {
                AudioProbeOutcome.Ok => Row(AreaLevel.Ok, "Device responds", NoIssues),
                AudioProbeOutcome.DeviceInUse => Row(AreaLevel.Warning, "Device responds", "Another app has exclusive control of this device",
                    "Close music, recording or game apps that may have taken it over.", "busy", [Busy(state, def)]),
                AudioProbeOutcome.TimedOut or AudioProbeOutcome.ServiceNotRunning => Row(AreaLevel.Warning, "Device responds", "Windows Audio isn't answering",
                    "See Windows Audio services below."),
                _ => Row(AreaLevel.Warning, "Device responds", "Windows couldn't open this device", "The driver may have a problem: restart the device or update its driver."),
            });

        // Format and enhancements
        if (def is not null && def.DeviceFormat is { } fmt)
        {
            var changed = def.OemFormat is { } oem && !string.Equals(fmt, oem, StringComparison.OrdinalIgnoreCase);
            var probeFailed = def.Probe is AudioProbeOutcome.Failed or AudioProbeOutcome.EndpointCreateFailed;
            rows.Add(!changed ? Row(AreaLevel.Ok, "Sound format", NoIssues, fmt)
                : Row(probeFailed ? AreaLevel.Warning : AreaLevel.Neutral, "Sound format", "Changed from the driver's default",
                    $"{fmt} (default {def.OemFormat})", "format",
                    policy ? [new AreaAction(RemediationKind.ResetAudioFormat, "Reset to the default format", def.Id, def.Name)] : null));
        }
        if (def?.EnhancementsDisabled is { } fxOff)
        {
            // Turning them off is the usual fix when a device won't open; turning them back on is offered too (undoing a sound maker's advice).
            var probeFailed = def.Probe is AudioProbeOutcome.Failed or AudioProbeOutcome.EndpointCreateFailed;
            IReadOnlyList<AreaAction>? fx = !policy ? null
                : fxOff ? [new AreaAction(RemediationKind.ToggleAudioEnhancements, "Turn enhancements on", $"{def.Id}|{AudioTargets.On}", def.Name)]
                : probeFailed ? [new AreaAction(RemediationKind.ToggleAudioEnhancements, "Turn enhancements off", $"{def.Id}|{AudioTargets.Off}", def.Name)]
                : null;
            rows.Add(Row(!fxOff && probeFailed ? AreaLevel.Warning : AreaLevel.Neutral, "Audio enhancements", fxOff ? "Off" : "On",
                !fxOff && probeFailed ? "Sound makers' enhancements can stop a device from opening: try turning them off." : "", "sysfx", fx));
        }

        // Device Manager problems on sound hardware
        var bad = (facts.Problems ?? []).Where(p => IsSoundDevice(p, flow)).ToList();
        if (facts.Problems is not null)
        {
            if (bad.Count == 0) rows.Add(Row(AreaLevel.Ok, "Sound hardware", NoIssues));
            foreach (var p in bad)
                rows.Add(Row(AreaLevel.Warning, "Sound hardware", p.Name, p.FriendlyError, p.DeviceId,
                    p.DeviceId.Length > 0
                        ? [new AreaAction(p.IsDisabledOnly ? RemediationKind.EnableDevice : RemediationKind.RestartDevice,
                            p.IsDisabledOnly ? "Enable device" : "Restart device", p.DeviceId, p.Name)]
                        : null));
        }

        // Generic driver on an OEM codec
        if (facts.Drivers is not null)
        {
            if (generic.Count == 0) rows.Add(Row(AreaLevel.Ok, "Generic audio driver", NoIssues));
            foreach (var (d, vendor) in generic)
                rows.Add(Row(AreaLevel.Warning, "Generic audio driver", d.DeviceName,
                    $"Windows' generic driver is in use for this {vendor} audio chip. The PC maker's driver usually fixes missing microphones, jack detection and enhancements.",
                    d.DeviceId, [new AreaAction(RemediationKind.CheckAndInstallDriverUpdates, "Check & install driver updates")]));
        }

        if (output)
        {
            // Sessions on an output (recordings made before sessions carried their device only have the default output's).
            var outputs = state.Sessions.Where(x => x.EndpointId.Length == 0 || mine.Any(e => e.Id == x.EndpointId)).ToList();
            var muted = outputs.Where(x => x.Muted).GroupBy(x => x.ProcessName, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
            rows.Add(muted.Count > 0
                ? Row(AreaLevel.Neutral, "App muted in Volume mixer", string.Join(", ", muted.Select(x => x.ProcessName)),
                    "These apps won't make sound until they're unmuted in the Volume mixer.", "apps-muted",
                    muted.Where(x => x.EndpointId.Length > 0 && Core.Session.AgentScripts.IsProcessName(x.ProcessName))
                        .Select(x => new AreaAction(RemediationKind.UnmuteAudioSession, $"Unmute {x.ProcessName}", $"{x.EndpointId}|{x.ProcessName}", x.ProcessName)).ToList() is { Count: > 0 } un ? un : null)
                : Row(AreaLevel.Ok, "App muted in Volume mixer", NoIssues));
            if (def is not null && def.IsBluetoothHandsFree)
                rows.Add(Row(AreaLevel.Neutral, "Bluetooth call mode", "Sound is going to the headset's call mode",
                    "Call mode is mono and sounds worse. Pick the headset's Stereo output for music and video.", "bluetooth-call", Pick()));
            if (def is not null && def.IsDisplayAudio && active.Any(e => !e.IsDisplayAudio))
                rows.Add(Row(AreaLevel.Neutral, "Sound goes to a monitor", def.Name,
                    "Sound only plays if the monitor or TV has speakers. Pick another output if you hear nothing.", "display-audio", Pick()));
            if (facts.MonoAudio == true)
                rows.Add(Row(AreaLevel.Neutral, "Mono audio", "On", "Left and right are mixed together (accessibility setting).", "mono",
                    [new AreaAction(RemediationKind.OpenSettings, "Open Audio accessibility", "ms-settings:easeofaccess-audio", "Settings (Audio)")]));
        }
        else if (facts.MicPrivacy is { } priv)
        {
            rows.Add(priv.Blocked
                ? Row(AreaLevel.Warning, "Microphone privacy", "Microphone access is turned off",
                    string.Join(", ", CapturePrivacy.OffNames(priv, "Microphone")) + " is off in Windows privacy settings.", "privacy",
                    [PrivacyAction(CapturePrivacy.Microphone, priv),
                     new AreaAction(RemediationKind.OpenSettings, "Open Microphone privacy", "ms-settings:privacy-microphone", "Settings (Microphone)")])
                : Row(AreaLevel.Ok, "Microphone privacy", NoIssues));
        }

        // The devices themselves (HP's "Audio Device Information"), after the checks.
        foreach (var e in mine.Where(e => e.State != AudioEndpointState.NotPresent).OrderByDescending(e => e.IsDefault).ThenBy(e => e.Name, StringComparer.CurrentCultureIgnoreCase))
            rows.Add(Row(AreaLevel.Neutral, "Device", e.Name, DeviceDetail(e), e.Id));

        var level = rows.Select(r => r.Level).DefaultIfEmpty(AreaLevel.Ok).Max();
        var warnings = rows.Count(r => r.Level >= AreaLevel.Warning);
        var headline = warnings == 0 ? NoIssues : AreaModuleBase.Plural(warnings, "problem");
        var meta = def is not null ? def.Name : active.Count == 0 ? $"No {thing} found" : "No default device";
        var card = new AreaCard(id, title, level == AreaLevel.Neutral ? AreaLevel.Ok : level, headline, meta, Columns, rows, PreserveRowOrder: true,
            Actions: policy && active.Count > 1 ? [picker] : null);
        return generic.Count > 0 ? card with { RunCheck = new AreaCheckLink(ModuleSlugs.DeviceDrivers, "Check Device Manager & drivers") } : card;
    }

    // ---------------------------------------------------------------- the fix dialogs

    /// <summary>
    /// The device picker: every output (or microphone) Windows knows, the connected ones first, a Bluetooth headset's Stereo output above
    /// its Hands-free one; unplugged and turned-off devices are listed greyed out with the reason. "Also use for calls" is ticked to start.
    /// Nothing is picked to start with, so Go waits for a choice.
    /// </summary>
    public static AreaAction Picker(AudioState state, AudioFlow flow)
    {
        var output = flow == AudioFlow.Output;
        var list = state.Endpoints.Where(e => e.Flow == flow && e.State != AudioEndpointState.NotPresent)
            .OrderBy(e => e.IsActive ? 0 : 1).ThenBy(e => e.IsBluetoothHandsFree ? 1 : 0).ThenByDescending(e => e.IsDefault)
            .ThenBy(e => e.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(e => new AreaChoice(e.Id, e.Name, ChoiceDetail(e), e.State switch
            {
                AudioEndpointState.Disabled => "Turned off: turn it on first.",
                AudioEndpointState.Unplugged => "Unplugged: plug it in first.",
                _ => null,
            })).ToList();
        return new AreaAction(RemediationKind.SetDefaultAudioEndpoint, output ? "Change output device" : "Change microphone",
            output ? AudioTargets.Output : AudioTargets.Input, output ? "Speakers & headphones" : "Microphones")
        {
            Choices = list,
            Option = new AreaChoiceOption("Also use for calls", AudioTargets.CallsSuffix),
            EmptyChoicesText = output ? "Windows doesn't list any speakers or headphones." : "Windows doesn't list any microphones.",
        };
    }

    private static string ChoiceDetail(AudioEndpointInfo e)
    {
        var parts = new List<string>();
        if (e.Bus == AudioBus.Bluetooth && e.Flow == AudioFlow.Output) parts.Add(e.IsBluetoothHandsFree ? "Hands-free (calls): mono, call quality" : "Stereo (music and video)");
        else if (FormFactorWords(e.FormFactor) is { Length: > 0 } kind) parts.Add(char.ToUpperInvariant(kind[0]) + kind[1..]);
        parts.Add(e.Bus switch { AudioBus.Bluetooth => "Bluetooth", AudioBus.Usb => "USB", AudioBus.Internal => "built-in", _ => "" });
        if (e.DefaultFor.Contains(AudioEndpointInfo.Multimedia) || e.DefaultFor.Contains(AudioEndpointInfo.Console)) parts.Add("default now");
        else if (e.IsDefaultForCalls) parts.Add("default for calls now");
        var text = string.Join(" · ", parts.Where(p => p.Length > 0));
        return e.IsDisplayAudio ? text + ". Only plays sound if the monitor has speakers." : text;
    }

    /// <summary>
    /// Device busy: the apps with a session on the device (protected Windows processes left out). When none can be identified, the
    /// Volume mixer instead (an exclusive-mode stream may not show up as a session).
    /// </summary>
    public static AreaAction Busy(AudioState state, AudioEndpointInfo device)
    {
        var apps = state.Sessions.Where(x => x.EndpointId == device.Id && Core.Session.AgentScripts.IsProcessName(x.ProcessName) && !ProcessProtection.IsProtected(x.ProcessName))
            .GroupBy(x => x.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Active).First())
            .OrderByDescending(x => x.Active).ThenBy(x => x.ProcessName, StringComparer.CurrentCultureIgnoreCase)
            .Select(x => new AreaChoice($"{device.Id}|{x.ProcessName}", x.WindowTitle is { Length: > 0 } t ? $"{x.ProcessName} ({t})" : x.ProcessName,
                x.Active ? "Using the device now" : "Has the device open"))
            .ToList();
        if (apps.Count == 0)
            return new AreaAction(RemediationKind.OpenSettings, "Open Volume mixer", "ms-settings:apps-volume", "Settings (Volume mixer)");
        return new AreaAction(RemediationKind.CloseAudioHolder, "Close the app", device.Id, device.Name)
        {
            Choices = apps,
            EmptyChoicesText = "No app could be identified. The app holding the device may not show up here: close music, recording or game apps.",
        };
    }

    /// <summary>Microphone (or camera) access, with the person's consent.</summary>
    public static AreaAction PrivacyAction(string capability, CapturePrivacy.Switches off)
    {
        var thing = CapturePrivacy.Thing(capability).ToLowerInvariant();
        return new AreaAction(RemediationKind.AllowCapturePrivacy, $"Turn on {thing} access", capability, $"{CapturePrivacy.Thing(capability)} access",
            string.Join(", ", CapturePrivacy.OffNames(off, CapturePrivacy.Thing(capability))))
        {
            Consent = $"I'm the person using this PC (or they agreed) and I want {thing} access turned on.",
        };
    }

    private static string DeviceDetail(AudioEndpointInfo e)
    {
        var parts = new List<string> { e.FriendlyState };
        if (e.DefaultFor.Count > 0) parts.Add("default for " + string.Join(", ", e.DefaultFor.Select(r => r.ToLowerInvariant())));
        parts.Add(e.Bus switch { AudioBus.Bluetooth => "Bluetooth", AudioBus.Usb => "USB", AudioBus.Internal => "built-in", _ => "" });
        parts.Add(FormFactorWords(e.FormFactor));
        return string.Join(" · ", parts.Where(p => p.Length > 0));
    }

    private static string FormFactorWords(string f) => f switch
    {
        "Speakers" => "speakers", "Headphones" => "headphones", "Headset" => "headset", "Microphone" => "microphone", "LineLevel" => "line level",
        "DigitalAudioDisplayDevice" => "monitor or TV", "Spdif" => "digital (S/PDIF)", "Handset" => "handset", _ => "",
    };

    /// <summary>A Device Manager problem on sound hardware: an endpoint of this flow (<c>SWD\MMDEVAPI\{0.0.0...</c> outputs, <c>{0.0.1...</c>
    /// inputs) or an audio device (MEDIA), which affects both.</summary>
    public static bool IsSoundDevice(ProblemDevice p, AudioFlow flow)
    {
        if (p.Class.Equals("MEDIA", StringComparison.OrdinalIgnoreCase)) return true;
        if (!p.Class.Equals("AudioEndpoint", StringComparison.OrdinalIgnoreCase)) return false;
        var marker = flow == AudioFlow.Output ? "{0.0.0." : "{0.0.1.";
        return p.DeviceId.Contains(marker, StringComparison.OrdinalIgnoreCase) || !p.DeviceId.Contains("{0.0.", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Internal HD Audio codecs from a maker that ships its own driver, running on Windows' generic <c>hdaudio.inf</c>.</summary>
    public static IReadOnlyList<(AudioDriver Driver, string Vendor)> GenericDrivers(IReadOnlyList<AudioDriver>? drivers)
    {
        var list = new List<(AudioDriver, string)>();
        foreach (var d in drivers ?? [])
        {
            if (!d.InfName.Equals("hdaudio.inf", StringComparison.OrdinalIgnoreCase)) continue;
            var hw = d.HardwareId.Length > 0 ? d.HardwareId : d.DeviceId;
            if (!hw.StartsWith(@"HDAUDIO\FUNC_01", StringComparison.OrdinalIgnoreCase)) continue; // FUNC_01 = audio; HDMI audio and modems aren't flagged
            var vendor = CodecVendor(hw);
            if (vendor is not null && OemCodecVendors.TryGetValue(vendor, out var name)) list.Add((d, name));
        }
        return list;
    }

    /// <summary>The 4 hex digits after <c>VEN_</c> in an HD Audio hardware id, split by hand (no regex).</summary>
    public static string? CodecVendor(string hardwareId)
    {
        var tail = hardwareId.Contains('\\') ? hardwareId[(hardwareId.IndexOf('\\') + 1)..] : hardwareId;
        foreach (var part in tail.Split('&', '\\'))
            if (part.StartsWith("VEN_", StringComparison.OrdinalIgnoreCase) && part.Length >= 8) return part.Substring(4, 4).ToUpperInvariant();
        return null;
    }

    private static AreaCard ServicesCard(SoundFacts facts, bool serviceHung, bool audioRead)
    {
        string[] cols = ["Service", "Status", "Details"];
        if (facts.Services is null)
            return AreaCard.Failed("audio-services", "Windows Audio services", "Couldn't read the Windows services.");
        var rows = new List<AreaRow>();
        // A disabled service can't start, so while either is disabled only "Turn Windows Audio back on" is offered.
        var anyDisabled = new[] { AudioSrv, EndpointBuilder }.Any(name =>
            (facts.ServicesAgain?.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
             ?? facts.Services.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))?.IsDisabled == true);
        AreaAction[] Fix(RemediationKind kind, string button) => [new(kind, button, "", "Windows Audio")];
        foreach (var name in new[] { AudioSrv, EndpointBuilder })
        {
            var s = facts.Services.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            var label = name == AudioSrv ? "Windows Audio" : "Windows Audio Endpoint Builder";
            if (s is null) { rows.Add(new(AreaLevel.Warning, [label, "Missing", "This Windows service isn't installed."], Key: name)); continue; }
            var later = facts.ServicesAgain?.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            var stuck = IsPending(s) && later is not null && IsPending(later);
            var now = later ?? s;
            AreaRow row;
            if (now.IsDisabled)
                row = new(AreaLevel.Warning, [label, "Disabled", "It's turned off, so no sound can play."], Key: name,
                    Actions: Fix(RemediationKind.SetAudioServicesAutomatic, "Turn Windows Audio back on"));
            else if (stuck)
                row = new(AreaLevel.Warning, [label, "Not responding", $"Stuck {now.FriendlyStatus.ToLowerInvariant()}."], Key: name,
                    Actions: anyDisabled ? null : Fix(RemediationKind.RestartAudioServices, "Restart Windows Audio"));
            else if (!now.IsRunning && !IsPending(now))
                row = new(AreaLevel.Warning, [label, "Not running", name == AudioSrv ? "No sound can play until it's started." : "Windows Audio needs it to run."], Key: name,
                    Actions: anyDisabled ? null : Fix(RemediationKind.StartAudioServices, "Start Windows Audio"));
            else if (serviceHung && now.IsRunning)
                row = new(AreaLevel.Warning, [label, "Not responding", "It's running but didn't answer when a sound device was opened."], Key: name,
                    // One restart button: Windows Audio's row (the restart goes on to the Endpoint Builder only if that doesn't help).
                    Actions: anyDisabled || name != AudioSrv ? null : Fix(RemediationKind.RestartAudioServices, "Restart Windows Audio"));
            else
                row = new(AreaLevel.Ok, [label, now.FriendlyStatus, now.FriendlyStartType], Key: name);
            rows.Add(row);
        }
        // Sound makers' own helper services (Realtek, Dolby, Waves...): shown so a stopped one is visible, never flagged.
        foreach (var s in facts.Services.Where(x => !x.Name.Equals(AudioSrv, StringComparison.OrdinalIgnoreCase) && !x.Name.Equals(EndpointBuilder, StringComparison.OrdinalIgnoreCase)
                     && (x.Name.Contains("Audio", StringComparison.OrdinalIgnoreCase) || x.DisplayName.Contains("Audio", StringComparison.OrdinalIgnoreCase))
                     && !x.Name.StartsWith("AudioEndpoint", StringComparison.OrdinalIgnoreCase))
                     .OrderBy(x => x.Label, StringComparer.CurrentCultureIgnoreCase))
            rows.Add(new(AreaLevel.Neutral, [s.Label, s.FriendlyStatus, s.FriendlyStartType], Key: s.Name));
        foreach (var d in (facts.Drivers ?? []).OrderBy(d => d.DeviceName, StringComparer.CurrentCultureIgnoreCase))
            rows.Add(new(AreaLevel.Neutral, [$"Driver: {d.DeviceName.Trim()}", d.Version, $"{d.Provider} · {d.InfName}"], Key: d.DeviceId));
        var warnings = rows.Count(r => r.Level >= AreaLevel.Warning);
        var level = warnings > 0 ? AreaLevel.Warning : AreaLevel.Ok;
        return new AreaCard("audio-services", "Windows Audio services", level, warnings == 0 ? "Running" : AreaModuleBase.Plural(warnings, "problem"),
            audioRead ? "Windows Audio, Endpoint Builder and sound drivers" : "Sound devices couldn't be read", cols, rows, PreserveRowOrder: true);
    }
}
