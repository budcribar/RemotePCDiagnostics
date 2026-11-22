using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Checks;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// One state file (<see cref="ProtectedStateFiles.AgentManaged"/>) in the state folder only administrators can open, read and saved by
/// the Agent for the app, which isn't elevated. While the Agent isn't connected, it reads and saves the file itself only when this
/// process can open it (an app the restart-resume task started with administrator rights); otherwise nothing is read or saved.
/// </summary>
public sealed class AgentStateFile(IElevatedCommandBridge agent, string name, string? fallbackPath = null, ILogger? log = null)
{
    public string Name => name;

    private static readonly TimeSpan PipeTimeout = TimeSpan.FromSeconds(5);

    /// <summary>The file's JSON, or null when there is none or it couldn't be read.</summary>
    public string? Read()
    {
        if (agent.IsConnected)
        {
            try
            {
                using var cts = new CancellationTokenSource(PipeTimeout);
                var r = Task.Run(() => agent.ReadStateFileAsync(name, cts.Token)).GetAwaiter().GetResult();
                if (r.Ok) return r.Json;
            }
            catch (Exception ex) { log.Warn($"[state] The Agent couldn't read {name}: {ex.Message}"); }
        }
        if (string.IsNullOrEmpty(fallbackPath)) return null;
        try { return File.Exists(fallbackPath) ? File.ReadAllText(fallbackPath) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Saves the JSON (null deletes the file). False when it couldn't be saved.</summary>
    public bool Write(string? json)
    {
        if (agent.IsConnected)
        {
            try
            {
                using var cts = new CancellationTokenSource(PipeTimeout);
                if (Task.Run(() => agent.WriteStateFileAsync(name, json, cts.Token)).GetAwaiter().GetResult()) return true;
            }
            catch (Exception ex) { log.Warn($"[state] The Agent couldn't save {name}: {ex.Message}"); }
        }
        if (!string.IsNullOrEmpty(fallbackPath))
        {
            try
            {
                // Never creates the folder: only the secured one (administrators only) may hold these files.
                if (Directory.Exists(Path.GetDirectoryName(fallbackPath)))
                {
                    if (json is null) { if (File.Exists(fallbackPath)) File.Delete(fallbackPath); return true; }
                    var tmp = fallbackPath + ".tmp";
                    File.WriteAllText(tmp, json);
                    File.Move(tmp, fallbackPath, overwrite: true);
                    return true;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        log.Warn($"[state] {name} wasn't saved: {ElevationService.AdminRepairHint}");
        return false;
    }
}

/// <summary>The service workflow's state, kept by the Agent (see <see cref="AgentStateFile"/>).</summary>
public sealed class AgentWorkflowStore(AgentStateFile file) : IWorkflowStore
{
    public AgentWorkflowStore(IElevatedCommandBridge agent, ILogger? log = null)
        : this(new AgentStateFile(agent, ProtectedState.WorkflowFile, FileWorkflowStore.DefaultPath(), log)) { }

    public WorkflowState? Load() => WorkflowState.FromJson(file.Read());
    public void Save(WorkflowState state) => file.Write(state.ToJson());
}

/// <summary>The benchmarks' state, kept by the Agent (see <see cref="AgentStateFile"/>).</summary>
public sealed class AgentBenchmarkStore(AgentStateFile file) : IBenchmarkStore
{
    public AgentBenchmarkStore(IElevatedCommandBridge agent, ILogger? log = null)
        : this(new AgentStateFile(agent, ProtectedState.BenchmarksFile, FileBenchmarkStore.DefaultPath(), log)) { }

    public BenchmarkState? Load() => BenchmarkState.FromJson(file.Read());
    public void Save(BenchmarkState state) => file.Write(state.ToJson());
}

/// <summary>Which diagnostic checks are turned on, kept by the Agent (see <see cref="AgentStateFile"/>).</summary>
public sealed class AgentCheckSettingsStore(AgentStateFile file) : ICheckSettingsStore
{
    public AgentCheckSettingsStore(IElevatedCommandBridge agent, ILogger? log = null)
        : this(new AgentStateFile(agent, ProtectedState.CheckSettingsFile, FileCheckSettingsStore.DefaultPath(), log)) { }

    public CheckSettings? Load() => CheckSettings.FromJson(file.Read());
    public void Save(CheckSettings settings) => file.Write(settings.ToJson());
}
