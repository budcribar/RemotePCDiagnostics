using Windows.Networking.Connectivity;
using RemotePCDiagnostics.Core.NetworkUsage;

namespace NetworkUsagePrototype;

internal static class WindowsUsage
{
    public static async Task<NetworkUsageReport> ReadAsync(DateTimeOffset start, DateTimeOffset end)
    {
        var rows = new List<NetworkUsageEntry>();
        var warnings = new List<string> { "Application identities may represent shared system buckets. User attribution is unavailable through this API. Aggregated records do not expose actual history coverage." };
        var states = new NetworkUsageStates { Roaming = TriStates.DoNotCare, Shared = TriStates.DoNotCare };
        var profiles = NetworkInformation.GetConnectionProfiles();
        foreach (var profile in profiles)
        {
            var name = profile.ProfileName;
            try
            {
                var usage = await profile.GetAttributedNetworkUsageAsync(start, end, states).AsTask().WaitAsync(TimeSpan.FromSeconds(30));
                foreach (var entry in usage)
                    rows.Add(new(entry.AttributionId, string.IsNullOrWhiteSpace(entry.AttributionName) ? entry.AttributionId : entry.AttributionName,
                        "Unavailable (API)", name, null, entry.BytesSent, entry.BytesReceived));
                if (usage.Count == 0) warnings.Add($"{name}: no attributed records returned; usage may be absent or inaccessible.");
            }
            catch (Exception ex) { warnings.Add($"{name}: attributed usage unavailable: {ex.GetType().Name}: {ex.Message}"); }
        }
        if (profiles.Count == 0) warnings.Add("Windows returned no connection profiles.");
        return new("Windows attributed network usage API", start, end, rows, warnings);
    }
}
