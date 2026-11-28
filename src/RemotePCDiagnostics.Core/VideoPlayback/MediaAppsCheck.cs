using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.VideoPlayback;

/// <summary>
/// The media apps check (no stress): for a few seconds, watches what is playing and the graphics chip's video decode engine per process. An
/// app that plays video while its processes use the decode engine decodes on the graphics chip. A video app that plays with a lot of CPU and
/// no decode engine load is decoding on the processor, which costs battery and makes the fan run: the advice names the app and where its
/// hardware acceleration setting is. Apps are added up over their processes (a browser decodes in its GPU process, not its tabs).
/// </summary>
public sealed class MediaAppsCheck(IVideoPlaybackSource source, IStressClock? clock = null, ILogger? log = null)
{
    /// <summary>Decode engine load at or above this counts as decoding on the graphics chip.</summary>
    public const double DecodeActivePercent = 0.5;
    /// <summary>A video app playing with no decode engine load and at least this much CPU (percent of one core, over its processes) is
    /// decoding on the processor. Software decoding of 1080p H.264 takes about 30 to 60% of one core; a page or an audio app stays far below.</summary>
    public const double CpuDecodePercentOfCore = 25;

    public async Task<MediaAppsResult> RunAsync(TimeSpan window, CancellationToken ct)
    {
        var clk = clock ?? new StopwatchStressClock();
        IGpuEngineMeter? meter = null;
        var enginesOk = true;
        try { meter = source.OpenEngineMeter(); meter.Sample(); }
        catch (Exception ex) { log.Info($"Media apps: engine counters unavailable: {ex.Message}"); enginesOk = false; }
        try
        {
            var before = SafeProcesses();
            var t0 = clk.Elapsed;
            await clk.DelayAsync(window, ct).ConfigureAwait(false);
            var after = SafeProcesses();
            var seconds = Math.Max(0.001, (clk.Elapsed - t0).TotalSeconds);
            IReadOnlyList<GpuEngineLoad> loads = [];
            if (meter is not null)
            {
                try { loads = meter.Sample(); }
                catch (Exception ex) { log.Info($"Media apps: engine sample failed: {ex.Message}"); enginesOk = false; }
            }
            if (enginesOk && loads.Count == 0) enginesOk = false; // no GPU Engine counters at all (a basic display driver, a VM)
            IReadOnlyList<MediaSessionInfo> sessions;
            try { sessions = source.ReadMediaSessions(); }
            catch (Exception ex) { log.Info($"Media apps: media sessions unavailable: {ex.Message}"); sessions = []; }
            IReadOnlyList<string>? formats;
            try { formats = source.ReadHardwareDecodeFormats(); }
            catch (Exception ex) { log.Info($"Media apps: decode formats unavailable: {ex.Message}"); formats = null; }
            var result = Evaluate(before, after, seconds, loads, sessions, source.SelfProcessId, enginesOk, formats);
            log.Info($"Media apps: {result.Apps.Count} apps, sessions={sessions.Count}, engines={enginesOk}, formats={(formats is null ? "unknown" : string.Join(",", formats))}: "
                + string.Join("; ", result.Apps.Select(a => $"{a.Name} playing={a.Playing} cpu={a.CpuPercentOfCore:0}% decode={a.DecodePercent:0.0}% {a.Verdict}")));
            return result;
        }
        finally { meter?.Dispose(); }
    }

    private IReadOnlyList<MediaProcess> SafeProcesses()
    {
        try { return source.ReadProcesses(); }
        catch (Exception ex) { log.Info($"Media apps: process list failed: {ex.Message}"); return []; }
    }

    /// <summary>The verdict per app from two process snapshots <paramref name="seconds"/> apart, the decode engine load over that time and the
    /// media sessions. Lists every app that plays or decodes, plus video apps that are open but idle (as Not playing).</summary>
    public static MediaAppsResult Evaluate(IReadOnlyList<MediaProcess> before, IReadOnlyList<MediaProcess> after, double seconds,
        IReadOnlyList<GpuEngineLoad> loads, IReadOnlyList<MediaSessionInfo> sessions, int selfPid, bool enginesAvailable,
        IReadOnlyList<string>? hardwareDecodeFormats = null)
    {
        var noAv1 = hardwareDecodeFormats is { Count: > 0 } && !hardwareDecodeFormats.Contains(VideoFormats.Av1);
        var earlier = before.GroupBy(p => p.ProcessId).ToDictionary(g => g.Key, g => g.First().CpuTime);
        var decodeByPid = loads.Where(l => l.IsVideoDecode).GroupBy(l => l.ProcessId).ToDictionary(g => g.Key, g => g.Max(l => l.Percent));
        var apps = new List<MediaAppUsage>();
        double other = 0;
        foreach (var g in after.Where(p => p.ProcessId != selfPid).GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase))
        {
            var known = MediaAppCatalog.Find(g.Key);
            var decode = g.Sum(p => decodeByPid.GetValueOrDefault(p.ProcessId));
            var playing = sessions.Any(s => s.Playing && MediaAppCatalog.SessionMatches(s.AppId, g.Key, known));
            if (known is null && decode < DecodeActivePercent && !playing) continue;
            // Only a process seen both times counts (a new one has no "before"); CPU time can't go down, so clamp jitter at 0.
            var cpu = g.Sum(p => earlier.TryGetValue(p.ProcessId, out var t0) ? Math.Max(0, (p.CpuTime - t0).TotalSeconds) : 0) / seconds * 100;
            var videoApp = known?.Video ?? decode >= DecodeActivePercent;
            var verdict = Verdict(playing || decode >= DecodeActivePercent, videoApp, cpu, decode, enginesAvailable);
            if (known is null && verdict == MediaAppVerdict.NotPlaying) continue;
            if (known is null && g.Key.Equals("dwm", StringComparison.OrdinalIgnoreCase)) { other += decode; continue; }
            apps.Add(new MediaAppUsage(g.Key, known?.DisplayName ?? g.Key, g.Count(), playing, videoApp, Math.Round(cpu, 1), Math.Round(decode, 1), verdict,
                verdict == MediaAppVerdict.ProcessorDecode ? Advice(known, noAv1, hardwareDecodeFormats) : null));
        }
        var ordered = apps.OrderBy(a => a.Verdict switch { MediaAppVerdict.ProcessorDecode => 0, MediaAppVerdict.GraphicsChip => 1, MediaAppVerdict.LightLoad => 2, _ => 3 })
            .ThenByDescending(a => a.CpuPercentOfCore).ToList();
        return new MediaAppsResult(TimeSpan.FromSeconds(seconds), ordered, sessions.Count > 0, enginesAvailable, Math.Round(other, 1), hardwareDecodeFormats);
    }

    /// <summary>What to do about an app decoding on the processor. A browser on a chip with no AV1 decoder is most likely playing AV1 (YouTube's
    /// usual format), which no browser setting moves to the chip: say so first, then the app's own setting in case acceleration is also off.</summary>
    public static string Advice(MediaApp? known, bool noAv1Decoder, IReadOnlyList<string>? hardwareDecodeFormats)
    {
        var own = known?.Advice ?? MediaAppCatalog.GenericAdvice;
        if (!noAv1Decoder || known?.Browser != true) return own;
        var decodes = hardwareDecodeFormats is { Count: > 0 } f ? $" (it decodes {MediaAppCatalog.JoinAnd(f)})" : "";
        return $"This graphics chip can't decode AV1{decodes}, and YouTube and many other sites send AV1, so the browser decodes it on the processor "
            + "even with graphics acceleration on. To move it to the chip, block AV1 with a browser extension such as enhanced-h264ify and reload "
            + $"the video. If that doesn't help: {own}";
    }

    public static MediaAppVerdict Verdict(bool playing, bool videoApp, double cpuPercentOfCore, double decodePercent, bool enginesAvailable) =>
        !playing ? MediaAppVerdict.NotPlaying
        : decodePercent >= DecodeActivePercent ? MediaAppVerdict.GraphicsChip
        : enginesAvailable && videoApp && cpuPercentOfCore >= CpuDecodePercentOfCore ? MediaAppVerdict.ProcessorDecode
        : MediaAppVerdict.LightLoad;
}

/// <summary>A media app the check knows: its exe name, what to call it, whether it plays video, and where its hardware acceleration setting is.</summary>
public sealed record MediaApp(string ExeName, string DisplayName, bool Video, string Advice, params string[] SessionIds)
{
    /// <summary>A web browser: it plays whatever format the site sends, so a chip with no AV1 decoder explains processor decoding.</summary>
    public bool Browser => MediaAppCatalog.Browsers.Contains(ExeName);
}

/// <summary>Apps people play video in, with the setting that moves decoding to the graphics chip. Matched on the exe name (no extension).</summary>
public static class MediaAppCatalog
{
    public const string GenericAdvice = "Turn on hardware acceleration (or hardware decoding) in this app's settings, update the graphics driver, and restart the app.";
    private const string Chromium = "Turn on \"Use graphics acceleration when available\" in Settings > System, restart the browser, and update the graphics driver.";

    public static readonly IReadOnlyList<MediaApp> Apps =
    [
        new("chrome", "Google Chrome", true, Chromium, "chrome"),
        new("msedge", "Microsoft Edge", true, "Turn on \"Use graphics acceleration when available\" in Settings > System and performance, restart Edge, and update the graphics driver.", "msedge"),
        new("firefox", "Firefox", true, "In Settings > General > Performance, untick \"Use recommended performance settings\" and tick \"Use hardware acceleration when available\", then restart Firefox.", "firefox", "308046B0AF4A39CB"),
        new("brave", "Brave", true, Chromium, "brave"),
        new("opera", "Opera", true, "Turn on \"Use hardware acceleration when available\" in Settings > System, then restart Opera.", "opera"),
        new("vivaldi", "Vivaldi", true, Chromium, "vivaldi"),
        new("vlc", "VLC media player", true, "In Tools > Preferences > Input / Codecs, set Hardware-accelerated decoding to Automatic (or Direct3D11), then restart VLC.", "vlc"),
        new("Microsoft.Media.Player", "Media Player", true, "Media Player decodes on the graphics chip when the driver allows it: update the graphics driver, and install the HEVC or AV1 extension from the Store if the video uses it.", "Microsoft.ZuneMusic", "Microsoft.Media.Player"),
        new("Video.UI", "Movies & TV", true, "Update the graphics driver; Movies & TV decodes on the graphics chip when the driver supports the video's format.", "Microsoft.ZuneVideo"),
        new("wmplayer", "Windows Media Player (legacy)", true, "Update the graphics driver, or play the video in Media Player instead.", "wmplayer"),
        new("mpc-hc64", "MPC-HC", true, "In View > Options > Internal Filters > Video Decoder, choose a hardware decoder (D3D11 or DXVA2 native).", "mpc-hc64"),
        new("mpc-hc", "MPC-HC", true, "In View > Options > Internal Filters > Video Decoder, choose a hardware decoder (D3D11 or DXVA2 native).", "mpc-hc"),
        new("mpc-be64", "MPC-BE", true, "In View > Options > Internal Filters > Video Decoder, turn on hardware acceleration (D3D11).", "mpc-be64"),
        new("PotPlayerMini64", "PotPlayer", true, "In Preferences > Video > Video Codec/Filter, choose the built-in DXVA (or D3D11) video codec.", "PotPlayerMini64"),
        new("mpv", "mpv", true, "Add hwdec=auto-safe to mpv.conf.", "mpv"),
        new("kodi", "Kodi", true, "In Settings > Player > Videos, turn on \"Allow hardware acceleration - DXVA2\".", "kodi"),
        new("Plex", "Plex", true, "In Settings > Advanced (Player), turn on hardware decoding, then restart Plex.", "Plex"),
        new("Spotify", "Spotify", true, "In Settings > Compatibility, turn on \"Enable hardware acceleration\", then restart Spotify.", "Spotify"),
        new("ms-teams", "Microsoft Teams", true, "In Settings > General, make sure \"Disable GPU hardware acceleration\" is off (if shown), then restart Teams.", "MSTeams", "ms-teams"),
        new("Teams", "Microsoft Teams (classic)", true, "In Settings > General, untick \"Disable GPU hardware acceleration\", then restart Teams.", "Teams"),
        new("Zoom", "Zoom", true, "In Settings > Video > Advanced, turn on hardware acceleration for receiving video.", "Zoom"),
        new("Discord", "Discord", true, "In Settings > Advanced, turn on Hardware Acceleration, and in Voice & Video turn on hardware acceleration (H.264).", "Discord"),
        new("WWAHost", "Store web app (Netflix and similar)", true, "Update the graphics driver; this app decodes on the graphics chip when the driver allows it."),
    ];

    private static readonly Dictionary<string, MediaApp> ByExe = Apps.GroupBy(a => a.ExeName, StringComparer.OrdinalIgnoreCase)
        .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

    public static MediaApp? Find(string exeName) => ByExe.GetValueOrDefault(exeName);

    public static readonly IReadOnlySet<string> Browsers = new HashSet<string>(["chrome", "msedge", "firefox", "brave", "opera", "vivaldi"], StringComparer.OrdinalIgnoreCase);

    /// <summary>"A, B and C".</summary>
    public static string JoinAnd(IReadOnlyList<string> items) =>
        items.Count <= 1 ? string.Join("", items) : string.Join(", ", items.Take(items.Count - 1)) + " and " + items[^1];

    /// <summary>Whether a media session's app id belongs to the exe: a Win32 app's id is its name ("Chrome", "Spotify.exe", "vlc"), a Store app's
    /// is its package family ("Microsoft.ZuneMusic_8wekyb3d8bbwe!Microsoft.ZuneMusic").</summary>
    public static bool SessionMatches(string appId, string exeName, MediaApp? known)
    {
        if (string.IsNullOrWhiteSpace(appId)) return false;
        var id = appId.Trim();
        var bare = id.Split('!')[0].Split('_')[0];
        if (bare.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) bare = bare[..^4];
        if (bare.Equals(exeName, StringComparison.OrdinalIgnoreCase)) return true;
        return known?.SessionIds.Any(s => id.StartsWith(s, StringComparison.OrdinalIgnoreCase) || bare.Equals(s, StringComparison.OrdinalIgnoreCase)) == true;
    }
}
