using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class WorkflowExportTests
{
    private static readonly WorkflowFix Temp = new("rem:CleanTempFiles:", "Clean temporary files", "2.1 GB of temp files", "Storage", SuggestionRisk.Low, FixSource.Remediation, 1);
    private static readonly WorkflowFix Startup = new("mem:startup:OneDrive", "Stop OneDrive starting with Windows", "Slows start-up", "Start-up apps", SuggestionRisk.Medium, FixSource.Memory, 2, DefaultOn: false);

    [Fact]
    public void Review_lists_fixes_with_ids_approval_and_sign_in_readiness_without_credentials()
    {
        var state = new WorkflowState { Stage = WorkflowStage.Review, Fixes = [Temp, Startup], Approved = [Temp.Id], Findings = ["Low disk space"] };

        var json = WorkflowExport.ToJson(state, busy: false, waitingForRestart: false, status: null, message: null, [], ["Storage"],
            new WorkflowExport.SignIn(Automatic: false, RestartSignOn: false, CanStart: true));
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("Review", root.GetProperty("stage").GetString());
        Assert.Equal(1, root.GetProperty("approvedCount").GetInt32());
        var fixes = root.GetProperty("fixes");
        Assert.Equal("rem:CleanTempFiles:", fixes[0].GetProperty("id").GetString());
        Assert.True(fixes[0].GetProperty("approved").GetBoolean());
        Assert.True(fixes[0].GetProperty("areaOpen").GetBoolean());
        Assert.False(fixes[1].GetProperty("approved").GetBoolean());
        Assert.False(fixes[1].GetProperty("defaultOn").GetBoolean());
        Assert.Equal("medium", fixes[1].GetProperty("risk").GetString());
        Assert.True(root.GetProperty("signIn").GetProperty("canStart").GetBoolean());
        Assert.False(root.GetProperty("signIn").GetProperty("automatic").GetBoolean());
        Assert.False(root.GetProperty("signIn").GetProperty("restartSignOn").GetBoolean());
        Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Running_stages_report_outcomes_and_no_sign_in()
    {
        var state = new WorkflowState
        {
            Stage = WorkflowStage.Applying,
            Fixes = [Temp, Startup],
            Approved = [Temp.Id, Startup.Id],
            Outcomes = [new FixOutcome(Temp.Id, Temp.Title, true, "Freed 2.1 GB"), new FixOutcome(Startup.Id, Startup.Title, false, "Skipped", Skipped: true)],
        };

        using var doc = JsonDocument.Parse(WorkflowExport.ToJson(state, true, false, "Applying fixes (1 of 2)", null, [], [],
            new WorkflowExport.SignIn(false, false, false)));
        var root = doc.RootElement;

        Assert.True(root.GetProperty("running").GetBoolean());
        Assert.Equal("Applying fixes (1 of 2)", root.GetProperty("status").GetString());
        Assert.Equal("succeeded", root.GetProperty("outcomes")[0].GetProperty("outcome").GetString());
        Assert.Equal("skipped", root.GetProperty("outcomes")[1].GetProperty("outcome").GetString());
        Assert.False(root.TryGetProperty("signIn", out _));
        Assert.False(root.TryGetProperty("checks", out _));
    }

    [Fact]
    public void Checking_stage_reports_each_check()
    {
        var state = new WorkflowState { Stage = WorkflowStage.Checking };
        var checks = new List<WorkflowCheckItem> { new("DriveHealth", "Drive health", DiagnosticStatus.Running, "Checking", 1, 2) };

        using var doc = JsonDocument.Parse(WorkflowExport.ToJson(state, true, false, null, null, checks, [], new WorkflowExport.SignIn(false, false, false)));
        var check = doc.RootElement.GetProperty("checks")[0];

        Assert.Equal("running", check.GetProperty("status").GetString());
        Assert.Equal(2, check.GetProperty("total").GetInt32());
    }
}
