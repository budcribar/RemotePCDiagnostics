using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Agent.Core;

/// <summary><c>%ProgramData%\RemotePCDiagnostics\agent.json</c>, written by <c>install</c> (only Administrators and SYSTEM can change it).</summary>
public sealed class AgentConfig
{
    [JsonPropertyName("machineId")] public string MachineId { get; set; } = "";
    [JsonPropertyName("server")] public string Server { get; set; } = AgentCommandLine.DefaultServer;
    [JsonPropertyName("key")] public string Key { get; set; } = "";
    /// <summary><c>ask</c> or <c>unattended</c>.</summary>
    [JsonPropertyName("consent")] public string Consent { get; set; } = "ask";
    /// <summary><c>persistent</c> or <c>session</c>.</summary>
    [JsonPropertyName("lifetime")] public string Lifetime { get; set; } = "persistent";

    /// <summary>Anything other than an explicit "unattended" means ask (the safe reading of a damaged file).</summary>
    [JsonIgnore] public ConsentCeiling ConsentCeiling => string.Equals(Consent, "unattended", StringComparison.OrdinalIgnoreCase) ? ConsentCeiling.Unattended : ConsentCeiling.Ask;
    [JsonIgnore] public AgentLifetime AgentLifetime => string.Equals(Lifetime, "session", StringComparison.OrdinalIgnoreCase) ? AgentLifetime.Session : AgentLifetime.Persistent;

    public static string ConsentText(ConsentCeiling c) => c == ConsentCeiling.Unattended ? "unattended" : "ask";
    public static string LifetimeText(AgentLifetime l) => l == AgentLifetime.Session ? "session" : "persistent";

    /// <summary>Parses agent.json; null when it's missing, not JSON, or has no valid machine id.</summary>
    public static AgentConfig? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            var c = JsonSerializer.Deserialize(json, AgentJsonContext.Default.AgentConfig);
            if (c is null || !Guid.TryParse(c.MachineId, out var id) || id == Guid.Empty) return null;
            c.MachineId = id.ToString("D");
            if (!AgentCommandLine.TryNormalizeServer(c.Server, out var server)) server = AgentCommandLine.DefaultServer;
            c.Server = server;
            c.Key ??= "";
            c.Consent = ConsentText(c.ConsentCeiling);
            c.Lifetime = LifetimeText(c.AgentLifetime);
            return c;
        }
        catch (JsonException) { return null; }
    }

    public string ToJson() => JsonSerializer.Serialize(this, AgentJsonContext.Default.AgentConfig);

    /// <summary>
    /// The configuration <c>install</c> writes: the machine id is kept from an existing file (so a reinstall is the same computer on
    /// the admin site), options given on the command line win, then the existing values, then the defaults (consent ask, persistent).
    /// </summary>
    public static AgentConfig ForInstall(AgentConfig? existing, AgentArgs args, Guid newMachineId) => new()
    {
        MachineId = existing?.MachineId ?? newMachineId.ToString("D"),
        Server = args.Server ?? existing?.Server ?? AgentCommandLine.DefaultServer,
        Key = args.Key ?? existing?.Key ?? "",
        Consent = ConsentText(args.Consent ?? existing?.ConsentCeiling ?? ConsentCeiling.Ask),
        Lifetime = LifetimeText(args.Lifetime ?? existing?.AgentLifetime ?? AgentLifetime.Persistent),
    };
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(AgentConfig))]
[JsonSerializable(typeof(ReleaseManifest))]
public partial class AgentJsonContext : JsonSerializerContext;
