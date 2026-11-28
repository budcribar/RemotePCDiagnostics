using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Display;

/// <summary>The kind of video connector, from Windows' output technology for the target (<c>DISPLAYCONFIG_VIDEO_OUTPUT_TECHNOLOGY</c>).</summary>
public enum DisplayConnector { Unknown, Internal, Hdmi, DisplayPort, UsbC, Vga, Dvi, Wireless, UsbAdapter, Virtual, Other }

/// <summary>
/// One video output (a "target" in Windows' display configuration: a connector on a graphics adapter, or a wireless or virtual one) and
/// the monitor on it, when there is one. Read in the app with <c>QueryDisplayConfig</c> and <c>DisplayConfigGetDeviceInfo</c> (no
/// administrator rights). <see cref="Available"/>: a monitor is attached; <see cref="Active"/>: Windows shows part of the desktop on it.
/// Sizes are in physical pixels; <see cref="Width"/>/<see cref="Height"/> are the desktop's, so a rotated monitor has them swapped.
/// </summary>
public sealed record DisplayOutput(
    string AdapterId,
    uint TargetId,
    int OutputTechnology,
    bool Available,
    bool Active,
    string? AdapterName = null,
    int ConnectorInstance = 0,
    string? MonitorName = null,
    // The monitor's device instance (DISPLAY\DELA0B1\5&...): no serial in it; the serial is in the EDID.
    string? MonitorInstanceId = null,
    /// <summary>The maker code and product code Windows took from the EDID (also there when the EDID itself couldn't be read).</summary>
    string? EdidManufacturer = null,
    int? EdidProductCode = null,
    /// <summary>Null when the monitor's EDID wasn't found (Windows keeps it under the monitor's device key).</summary>
    EdidInfo? Edid = null,
    int? Width = null,
    int? Height = null,
    double? RefreshHz = null,
    /// <summary>The monitor's preferred mode as the graphics driver reports it.</summary>
    int? PreferredWidth = null,
    int? PreferredHeight = null,
    double? PreferredRefreshHz = null,
    /// <summary>The largest mode the driver offers for this monitor, and the fastest refresh at the current resolution.</summary>
    int? MaxWidth = null,
    int? MaxHeight = null,
    double? MaxRefreshHz = null,
    int Rotation = 0,
    bool Primary = false,
    int? X = null,
    int? Y = null,
    int? ScalePercent = null,
    bool? HdrSupported = null,
    bool? HdrEnabled = null,
    int? BitsPerColor = null,
    string? GdiName = null)
{
    /// <summary>Identifies this output across reads: the adapter and its target.</summary>
    [JsonIgnore] public string Key => AdapterId + "/" + TargetId.ToString(System.Globalization.CultureInfo.InvariantCulture);

    [JsonIgnore] public DisplayConnector Connector => Displays.ConnectorOf(OutputTechnology);
}

/// <summary>The display configuration as read once. <see cref="Error"/> says why it couldn't be read (then <see cref="Outputs"/> is empty).</summary>
public sealed record DisplaySnapshot(IReadOnlyList<DisplayOutput> Outputs, string? Error = null)
{
    public static DisplaySnapshot Unavailable(string reason) => new([], reason);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static DisplaySnapshot FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Unavailable("No display answer.");
        try { return JsonSerializer.Deserialize<DisplaySnapshot>(json, Json) is { } s ? s with { Outputs = s.Outputs ?? [] } : Unavailable("No display answer."); }
        catch (JsonException ex) { return Unavailable("The display answer couldn't be read: " + ex.Message); }
    }

    /// <summary>The outputs with a monitor attached.</summary>
    [JsonIgnore] public IReadOnlyList<DisplayOutput> Monitors => [.. Outputs.Where(o => o.Available)];
}

/// <summary>Reads the display configuration (the app: no administrator rights needed).</summary>
public interface IDisplaySource
{
    Task<DisplaySnapshot> ReadAsync(CancellationToken ct = default);
}

/// <summary>No displays here (CI, non-Windows).</summary>
public sealed class NullDisplaySource : IDisplaySource
{
    public Task<DisplaySnapshot> ReadAsync(CancellationToken ct = default) => Task.FromResult(DisplaySnapshot.Unavailable("Displays can't be read here."));
}

/// <summary>This PC's displays, read in this process (<see cref="Platform.WindowsDisplayReader"/>).</summary>
public sealed class WindowsDisplaySource(ILogger? log = null) : IDisplaySource
{
    public Task<DisplaySnapshot> ReadAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            if (!OperatingSystem.IsWindows()) return DisplaySnapshot.Unavailable("Displays can only be read on Windows.");
            try { return Platform.WindowsDisplayReader.Read(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                log.Warn($"Display configuration unreadable: {ex.GetType().Name}: {ex.Message}");
                return DisplaySnapshot.Unavailable("The displays couldn't be read: " + ex.Message);
            }
        }, ct);
    }
}

/// <summary>
/// For a module in user mode (the module host): asks the app (<c>display.state</c>), which reads the display configuration in the signed-in
/// user's session, so the read is recorded with the app's other answers.
/// </summary>
public sealed class HostDisplaySource(Plugins.IHostQueries host, ILogger? log = null) : IDisplaySource
{
    public async Task<DisplaySnapshot> ReadAsync(CancellationToken ct = default)
    {
        try { return await host.ReadDisplayStateAsync(ct).ConfigureAwait(false); }
        catch (Plugins.HostQueryException ex)
        {
            log.Warn($"display.state refused ({ex.Error}): {ex.Message}");
            return DisplaySnapshot.Unavailable(ex.Message);
        }
    }
}
