using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.Tests;

/// <summary>The journal, workflow, resume and benchmark files live in the admin-only %ProgramData% state folder.</summary>
public sealed class ProtectedStatePathTests
{
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
