using System.Text.Json;

namespace RemotePCDiagnostics.Agent.Core;

public sealed record ActiveSessionInfo(
    int ProcessId,
    bool Running,
    string? SessionId,
    string? Group,
    string? Mode,
    DateTimeOffset StartedUtc,
    bool Unattended = false,
    bool Voice = false,
    bool? Admin = null,
    bool RemoteControl = false,
    DateTimeOffset? RemoteLeftInControlUtc = null)
{
    // RemoteControl: the remote user has control now. RemoteLeftInControlUtc: when their page last left while it had control.
    // The Agent reads both when it starts an update, so the app it relaunches hands control back to the technician.
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
            return false;
        }
    }

    public static bool TryDelete(string? path = null, int? expectedProcessId = null) =>
        TryDeleteSingle(path ?? AgentLayout.ActiveSessionPath(), expectedProcessId);

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
