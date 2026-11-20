using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// What the Agent's one-time machine setup did (<see cref="AdminPipeFraming.OpPrepareMachine"/>): the admin-only state folder,
/// the app's Windows Event Log source and the history updates. The app never runs as administrator, so these happen in the Agent.
/// </summary>
public sealed record MachineSetupResult(
    [property: JsonPropertyName("stateFolderSecured")] bool StateFolderSecured,
    [property: JsonPropertyName("eventSourceReady")] bool EventSourceReady,
    [property: JsonPropertyName("historyUpdate")] string HistoryUpdate,
    [property: JsonPropertyName("logMove")] string LogMove)
{
    /// <summary>Nothing more for the app to ask for on this start: the folder and the source are ready and neither update failed.</summary>
    [JsonIgnore]
    public bool Done => StateFolderSecured && EventSourceReady
        && HistoryUpdate != nameof(Migrations.MigrationOutcome.Failed) && LogMove != nameof(Migrations.MigrationOutcome.Failed);
}

/// <summary>The Agent side of <see cref="AdminPipeFraming.OpPrepareMachine"/> (Windows implementation in the Agent; fakes in tests).</summary>
public interface IMachineSetup
{
    /// <summary>Safe to call again: each part is a no-op once done. Never throws.</summary>
    MachineSetupResult Prepare();
}
