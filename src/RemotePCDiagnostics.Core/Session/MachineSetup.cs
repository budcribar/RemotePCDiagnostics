using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// What the Agent's machine setup did (<see cref="AdminPipeFraming.OpPrepareMachine"/>): the admin-only state folder and the app's
/// Windows Event Log source. The app never runs as administrator, so these happen in the Agent.
/// </summary>
public sealed record MachineSetupResult(
    [property: JsonPropertyName("stateFolderSecured")] bool StateFolderSecured,
    [property: JsonPropertyName("eventSourceReady")] bool EventSourceReady)
{
    /// <summary>Nothing more for the app to ask for on this start: the folder and the source are ready.</summary>
    [JsonIgnore]
    public bool Done => StateFolderSecured && EventSourceReady;
}

/// <summary>The Agent side of <see cref="AdminPipeFraming.OpPrepareMachine"/> (Windows implementation in the Agent; fakes in tests).</summary>
public interface IMachineSetup
{
    /// <summary>Safe to call again: each part is a no-op once done. Never throws.</summary>
    MachineSetupResult Prepare();
}
