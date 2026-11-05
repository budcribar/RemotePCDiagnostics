using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Migrations;

namespace RemotePCDiagnostics.Tests;

/// <summary>The one-time move of the journal, workflow, resume and benchmark files out of %LOCALAPPDATA%.</summary>
public sealed class ProtectedStateMigrationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpd-state-" + Guid.NewGuid().ToString("N"));
    private string Legacy => Path.Combine(_dir, "local");
    private string State => Path.Combine(_dir, "programdata", "state");
    private MigrationMarkers Markers => new(Path.Combine(_dir, "programdata", "migrations.json"));

    public void Dispose() { try { Directory.Delete(_dir, recursive: true); } catch { } }

    private ProtectedStateMigration Migration(List<string>? logs = null) => new(Legacy, State, Markers, l => logs?.Add(l));

    private void WriteLegacy(string name, string text)
    {
        Directory.CreateDirectory(Legacy);
        File.WriteAllText(Path.Combine(Legacy, name), text);
    }

    [Fact]
    public void Moves_every_state_file_and_marks_done()
    {
        foreach (var name in ProtectedState.FileNames) WriteLegacy(name, "{\"from\":\"" + name + "\"}");
        WriteLegacy("preferences.json", "{}");

        Assert.Equal(MigrationOutcome.Completed, Migration().Run());

        foreach (var name in ProtectedState.FileNames)
        {
            Assert.Equal("{\"from\":\"" + name + "\"}", File.ReadAllText(Path.Combine(State, name)));
            Assert.False(File.Exists(Path.Combine(Legacy, name)));
        }
        Assert.True(File.Exists(Path.Combine(Legacy, "preferences.json"))); // per-user files stay
        Assert.Empty(Directory.GetFiles(State, "*.tmp"));
        Assert.True(Markers.IsDone(ProtectedStateMigration.MarkerKey));
    }

    [Fact]
    public void Runs_once_so_a_file_dropped_in_the_old_folder_later_is_never_read()
    {
        Assert.Equal(MigrationOutcome.NothingToMigrate, Migration().Run());
        WriteLegacy(ProtectedState.ChangesFile, "[{\"forged\":true}]");

        Assert.Equal(MigrationOutcome.AlreadyDone, Migration().Run());
        Assert.False(File.Exists(Path.Combine(State, ProtectedState.ChangesFile)));
    }

    [Fact]
    public void A_file_already_in_the_state_folder_wins()
    {
        Directory.CreateDirectory(State);
        File.WriteAllText(Path.Combine(State, ProtectedState.WorkflowFile), "new");
        WriteLegacy(ProtectedState.WorkflowFile, "old");

        Assert.Equal(MigrationOutcome.NothingToMigrate, Migration().Run());
        Assert.Equal("new", File.ReadAllText(Path.Combine(State, ProtectedState.WorkflowFile)));
        Assert.False(File.Exists(Path.Combine(Legacy, ProtectedState.WorkflowFile)));
    }

    [Fact]
    public void Default_paths_point_at_the_protected_folder()
    {
        Assert.Equal(ProtectedState.PathFor("changes.json"), RemotePCDiagnostics.Core.Changes.FileChangeJournal.DefaultPath());
        Assert.Equal(ProtectedState.PathFor("workflow.json"), RemotePCDiagnostics.Core.Workflow.FileWorkflowStore.DefaultPath());
        Assert.Equal(ProtectedState.PathFor("benchmarks.json"), RemotePCDiagnostics.Core.Benchmarks.FileBenchmarkStore.DefaultPath());
        Assert.Equal(ProtectedState.PathFor("pending-reboot.json"), RemotePCDiagnostics.Core.Areas.RebootResumeCoordinator.DefaultStateFilePath());
        Assert.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), ProtectedState.Folder());
    }
}
