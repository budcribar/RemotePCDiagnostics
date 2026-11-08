using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Scripts;

namespace RemotePCDiagnostics.Core.Areas;

public sealed record SupportEndpoint(string Host, Uri? Web);
public sealed record SupportObservation(string Name, string Result);
public sealed record DockDevice(string Id, string Kind, string Name, string? Status, string? Container, bool? Active, string? Connection = null);

/// <summary>On-demand observations for support calls. Outputs are held for the current view only.</summary>
public sealed class SupportDiagnostics(IProcessLauncher launcher)
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(5);
    private static readonly HttpClient Http = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseDefaultCredentials = false
    });

    public static bool TryEndpoint(string input, out SupportEndpoint endpoint)
    {
        endpoint = null!;
        var target = input.Trim();
        if (target.Length is 0 or > 2048 || target.Any(char.IsControl)) return false;
        if (target.StartsWith(@"\\", StringComparison.Ordinal))
        {
            var parts = target[2..].Split('\\');
            if (parts.Length < 2 || parts[1].Length == 0 || Uri.CheckHostName(parts[0]) == UriHostNameType.Unknown) return false;
            endpoint = new(parts[0], null);
            return true;
        }
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") ||
            uri.HostNameType == UriHostNameType.Unknown || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0)
            return false;
        endpoint = new(uri.IdnHost, uri);
        return true;
    }

    public static async Task<IReadOnlyList<SupportObservation>> ProbeAsync(SupportEndpoint endpoint, bool includeClock, CancellationToken ct)
    {
        var observations = new List<SupportObservation>();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ProbeTimeout);
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(endpoint.Host, timeout.Token).ConfigureAwait(false);
            if (addresses.Length == 0) return [new("System DNS", "No address returned")];
            observations.Add(new("System DNS", "Address resolved"));
        }
        catch (SocketException) { return [new("System DNS", "Could not resolve the host")]; }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return [new("System DNS", "Timed out")]; }

        timeout.CancelAfter(ProbeTimeout);
        var probe = endpoint.Web is null ? "SMB port 445" : "Web endpoint";
        try
        {
            if (endpoint.Web is { } uri)
            {
                using var request = new HttpRequestMessage(HttpMethod.Head, uri);
                using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
                observations.Add(new(probe, DescribeHttp(response.StatusCode)));
                if (includeClock)
                {
                    var clock = uri.Scheme == "https" && response.Headers.Date is { } serverTime
                        ? $"This PC differs from the HTTPS response time by about {Math.Abs((DateTimeOffset.UtcNow - serverTime).TotalSeconds):0} seconds"
                        : "No HTTPS response time available";
                    observations.Add(new("Clock comparison", clock));
                }
            }
            else
            {
                using var client = new TcpClient();
                await client.ConnectAsync(endpoint.Host, 445, timeout.Token).ConfigureAwait(false);
                observations.Add(new(probe, "Server port reachable. Share access and credentials were not tested."));
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { observations.Add(new(probe, "Timed out")); }
        catch (HttpRequestException ex)
        {
            observations.Add(new(probe, ex.HttpRequestError == HttpRequestError.SecureConnectionError
                ? "TLS connection failed. Check the clock, certificate, or network inspection." : "No HTTP response was received."));
        }
        catch (SocketException) { observations.Add(new(probe, "Could not connect to the server port")); }
        return observations;
    }

    public static string DescribeHttp(HttpStatusCode status) => (int)status switch
    {
        401 => "HTTP 401. Authentication required or rejected for this anonymous request.",
        403 => "HTTP 403. The server denied this anonymous request.",
        405 or 501 => $"HTTP {(int)status}. The server responded but does not support this probe.",
        >= 200 and < 300 => $"HTTP {(int)status}. The endpoint responded to an anonymous request.",
        >= 300 and < 400 => $"HTTP {(int)status}. The endpoint redirected the request.",
        _ => $"HTTP {(int)status}. The server responded with an error."
    };

    public async Task<IReadOnlyList<SupportObservation>> ReadWindowsSignInAsync(CancellationToken ct)
    {
        var join = ReadAsync(SystemCommandRunner.SystemTool("dsregcmd.exe"), ["/status"], ct);
        var clock = ReadAsync(SystemCommandRunner.SystemTool("w32tm.exe"), ["/query", "/status", "/verbose"], ct);
        var events = ReadAsync(WindowsEventLog.Wevtutil, WindowsEventLog.Arguments("Security",
            "*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 86400000]]]", 20), ct);
        await Task.WhenAll(join, clock, events).ConfigureAwait(false);
        var observations = ParseJoin(await join.ConfigureAwait(false)).ToList();
        observations.Add(new("Windows time service", DescribeClock(await clock.ConfigureAwait(false))));
        var raw = await events.ConfigureAwait(false);
        try
        {
            var rows = raw is null ? null : WindowsEventLog.Parse(raw, "Security");
            if (rows is not { Count: > 0 })
                observations.Add(new("Recent Windows logon failures", rows is null ? "Security log unavailable" : "None recorded in the last 24 hours"));
            else
                observations.AddRange(rows.Select(e => new SupportObservation("Windows logon failure",
                    $"{WindowsEventLog.FormatTime(e.Time)} · status {Code(e, "Status")} · substatus {Code(e, "SubStatus")}")));
        }
        catch (System.Xml.XmlException) { observations.Add(new("Recent Windows logon failures", "Security log unreadable")); }
        return observations;
    }

    private static string Code(WinEvent e, string name) => e.NamedData.TryGetValue(name, out var code) &&
        code.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && uint.TryParse(code.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out _)
        ? code : "Unavailable";

    public static IEnumerable<SupportObservation> ParseJoin(string? output)
    {
        foreach (var (key, label) in new[] { ("AzureAdJoined", "Microsoft Entra join"), ("DomainJoined", "Windows domain join") })
        {
            var value = Field(output, key);
            yield return new(label, value switch { "YES" => "Joined", "NO" => "Not joined", _ => "Unavailable" });
        }
    }

    public static string DescribeClock(string? output)
    {
        if (Field(output, "Leap Indicator") is not { } indicator) return "Synchronization status unavailable";
        if (indicator.StartsWith("3", StringComparison.Ordinal)) return "Windows reports that the clock is not synchronized";
        var offset = Field(output, "Phase Offset");
        return offset is not null && double.TryParse(offset.TrimEnd('s', ' '), NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) && double.IsFinite(seconds)
            ? $"Last reported phase offset: {seconds:+0.000;-0.000;0.000} seconds"
            : "No clock offset reported";
    }

    private static string? Field(string? output, string key) => (output ?? "").Split('\n', StringSplitOptions.TrimEntries)
        .Select(line => line.Split(':', 2, StringSplitOptions.TrimEntries))
        .FirstOrDefault(pair => pair.Length == 2 && pair[0] == key)?[1];

    public async Task<IReadOnlyList<DockDevice>?> ReadDockAsync(CancellationToken ct)
    {
        var raw = await ReadAsync(SystemCommandRunner.PowerShell,
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", PowerShellScripts.Get("DockDevices")], ct).ConfigureAwait(false);
        try { return raw is null ? null : JsonSerializer.Deserialize<DockDevice[]>(raw); }
        catch (JsonException) { return null; }
    }

    public static IEnumerable<DockDevice> MissingDevices(IEnumerable<DockDevice> before, IEnumerable<DockDevice> after)
    {
        var present = after.Select(d => d.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return before.Where(d => !present.Contains(d.Id));
    }

    private async Task<string?> ReadAsync(string file, IReadOnlyList<string> args, CancellationToken ct)
    {
        // Do not send unfiltered dsregcmd, Security log or PnP output to the diagnostic logger.
        try
        {
            var result = await launcher.RunAsync(file, args, TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
            return result is { ExitCode: 0, TimedOut: false } ? result.StdOut : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return null; }
    }
}
