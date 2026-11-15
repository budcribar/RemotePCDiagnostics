using System.Text.Json;

namespace RemotePCDiagnostics.Agent.Core;

public sealed record ActiveSessionInfo(
    int ProcessId,
    bool Running,
    string? SessionId,
    string? Group,
    string? Mode,
    DateTimeOffset StartedUtc)
{
    public static ActiveSessionInfo? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            return JsonSerializer.Deserialize(json, AgentJsonContext.Default.ActiveSessionInfo);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public string ToJson() => JsonSerializer.Serialize(this, AgentJsonContext.Default.ActiveSessionInfo);

    public static bool TryWrite(ActiveSessionInfo info, string? path = null)
    {
        try
        {
            var target = path ?? AgentLayout.ActiveSessionPath();
            var dir = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(target, info.ToJson());
            return true;
        }
        catch
        {
            if (path is null)
            {
                try
                {
                    var fallback = AgentLayout.LegacyActiveSessionPath();
                    File.WriteAllText(fallback, info.ToJson());
                    return true;
                }
                catch { }
            }
            return false;
        }
    }

    public static bool TryDelete(string? path = null, int? expectedProcessId = null)
    {
        if (path is not null)
        {
            return TryDeleteSingle(path, expectedProcessId);
        }

        var deletedPrimary = TryDeleteSingle(AgentLayout.ActiveSessionPath(), expectedProcessId);
        var deletedLegacy = TryDeleteSingle(AgentLayout.LegacyActiveSessionPath(), expectedProcessId);
        return deletedPrimary || deletedLegacy;
    }

    private static bool TryDeleteSingle(string target, int? expectedProcessId)
    {
        try
        {
            if (!File.Exists(target)) return false;

            if (expectedProcessId.HasValue)
            {
                var json = File.ReadAllText(target);
                var info = Parse(json);
                if (info is not null && info.ProcessId != expectedProcessId.Value)
                {
                    return false;
                }
            }

            File.Delete(target);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
