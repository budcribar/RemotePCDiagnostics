namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>The long runs that must not overlap: each one's Start is greyed out while another runs.</summary>
public enum RunKind { Checks, Stress, Qa, Workflow }

/// <summary>
/// One shared "something is running" answer for the Checks, Stress tests, QA and Service workflow Start buttons (and the Dashboard's
/// Refresh), so two runs never start at the same time. Read from the runners' own state, so nothing has to be registered or released.
/// </summary>
public static class RunGate
{
    /// <summary>Why <paramref name="self"/> can't start now ("Checks need to stop or finish first."), or null when nothing else runs.</summary>
    public static string? BusyReason(RunKind self, ChecksScreenState? screen, DiagnosticsService diag, BenchQaRunner? qa, WorkflowService? flow)
    {
        if (self != RunKind.Checks && screen?.RunningGroup == CheckGroup.Checks) return ChecksBusy;
        if (self != RunKind.Stress && (screen?.RunningGroup == CheckGroup.Stress || diag.IsAnyStressRunning)) return StressBusy;
        if (self != RunKind.Qa && qa?.IsRunning == true) return QaBusy;
        if (self != RunKind.Workflow && flow is not null && (flow.Busy || flow.State.IsRunning)) return WorkflowBusy;
        return null;
    }

    public const string ChecksBusy = "Checks need to stop or finish first.";
    public const string StressBusy = "Stress tests need to stop or finish first.";
    public const string QaBusy = "The QA check needs to stop or finish first.";
    public const string WorkflowBusy = "The service workflow needs to stop or finish first.";
}
