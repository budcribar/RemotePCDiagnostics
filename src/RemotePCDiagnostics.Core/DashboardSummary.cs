namespace RemotePCDiagnostics.Core;

/// <summary>One module as seen by the Dashboard banner.</summary>
public sealed record BannerModule(string Name, string DisplayName, bool OnDemand, bool IsStress, DiagnosticStatus Status, string? Message = null);

/// <summary>A module that needs a look, in the banner title.</summary>
public sealed record BannerProblem(string Name, string DisplayName, bool IsError);

/// <summary>What the Dashboard banner shows: the problem list and the "on-demand tests not run" note.</summary>
public sealed class DashboardSummary
{
    public IReadOnlyList<BannerProblem> Problems { get; }
    public IReadOnlyList<BannerModule> NotRun { get; }
    public bool HasError => Problems.Any(p => p.IsError);

    private DashboardSummary(IReadOnlyList<BannerProblem> problems, IReadOnlyList<BannerModule> notRun) { Problems = problems; NotRun = notRun; }

    /// <summary>"1 thing to look at" / "3 things to look at".</summary>
    public string TitleLead => $"{Problems.Count} {(Problems.Count == 1 ? "thing" : "things")} to look at";

    /// <summary>"On-demand tests not run: 3 (stress tests and security audit)", or null when everything ran.</summary>
    public string? NotRunNote
    {
        get
        {
            if (NotRun.Count == 0) return null;
            var parts = new List<string>();
            var stress = NotRun.Where(m => m.IsStress).ToList();
            if (stress.Count > 1 && stress.Count == stressTotal) parts.Add("stress tests");
            else parts.AddRange(stress.Select(m => Lower(m.DisplayName)));
            parts.AddRange(NotRun.Where(m => !m.IsStress).Select(m => Lower(m.DisplayName)));
            return $"On-demand tests not run: {NotRun.Count} ({JoinList(parts)})";
        }
    }

    /// <summary>Hint shown after the note when the stress suite would run the missing tests.</summary>
    public string? NotRunHint => NotRun.Any(m => m.IsStress) ? "for stress tests, use Run all + stress tests" : null;

    private int stressTotal;

    /// <summary>Messages that mean the user cancelled the module, not that something is wrong.</summary>
    public static bool IsCancelled(BannerModule m) =>
        m.Status == DiagnosticStatus.Warning && m.Message is { } msg
        && (msg.Trim().Equals("Cancelled", StringComparison.OrdinalIgnoreCase)
            || msg.Trim().Equals("Stopped", StringComparison.OrdinalIgnoreCase)
            || msg.Trim().Equals("Stopped by you", StringComparison.OrdinalIgnoreCase)
            || msg == Security.SecurityAuditModule.CancelledMessage);

    /// <param name="modules">Modules in Dashboard order.</param>
    /// <param name="suite">Last stress suite progress; finished steps marked Skipped (not available on this PC) are not counted as not run.</param>
    public static DashboardSummary Build(IEnumerable<BannerModule> modules, StressSuiteProgress? suite)
    {
        var list = modules.ToList();
        var problems = list
            .Select((m, i) => (m, i))
            .Where(x => x.m.Status is DiagnosticStatus.Warning or DiagnosticStatus.Error && !IsCancelled(x.m))
            .OrderBy(x => x.m.Status == DiagnosticStatus.Error ? 0 : 1).ThenBy(x => x.i)
            .Select(x => new BannerProblem(x.m.Name, x.m.DisplayName, x.m.Status == DiagnosticStatus.Error))
            .ToList();
        var skipped = suite is { Finished: true }
            ? suite.Steps.Where(s => s.State == StressSuiteStepState.Skipped).Select(s => s.ModuleName).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>();
        var candidates = list.Where(m => m.OnDemand && !(m.IsStress && skipped.Contains(m.Name))).ToList();
        var notRun = candidates.Where(m => m.Status == DiagnosticStatus.NotRun).ToList();
        return new DashboardSummary(problems, notRun) { stressTotal = candidates.Count(m => m.IsStress) };
    }

    private static string Lower(string s) => s.Length > 1 && char.IsUpper(s[0]) && char.IsLower(s[1]) ? char.ToLowerInvariant(s[0]) + s[1..] : s;
    private static string JoinList(IEnumerable<string> items)
    {
        var a = items.ToList();
        return a.Count switch { 0 => "", 1 => a[0], 2 => $"{a[0]} and {a[1]}", _ => string.Join(", ", a.Take(a.Count - 1)) + " and " + a[^1] };
    }
}
