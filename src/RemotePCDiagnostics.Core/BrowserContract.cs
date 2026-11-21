namespace RemotePCDiagnostics.Core;

/// <summary>
/// Version of each page's agent metadata (docs/agent-guides/browser-contract.md). Pages render it next to their marker as
/// <c>data-rpcd-contract</c>, so a browser agent can tell which data-testid, data-* attributes and hidden data copies to expect.
/// Bump a page's version whenever its agent metadata is added, renamed or removed, and add a row to the changelog in the doc.
/// </summary>
public static class BrowserContract
{
    public const int Dashboard = 1;
    public const int Workflow = 1;
    public const int Checks = 4;
    public const int Stress = 1;
    public const int Interactive = 1;
    public const int SecurityAudit = 1;
    public const int Benchmark = 3;
    public const int Certificates = 1;
    public const int History = 2;
    public const int About = 1;
    public const int Module = 3;

    /// <summary>Every page marker value and its version.</summary>
    public static IReadOnlyDictionary<string, int> Pages { get; } = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["dashboard"] = Dashboard,
        ["workflow"] = Workflow,
        ["checks"] = Checks,
        ["stress"] = Stress,
        ["interactive"] = Interactive,
        ["security-audit"] = SecurityAudit,
        ["benchmark"] = Benchmark,
        ["certificates"] = Certificates,
        ["history"] = History,
        ["about"] = About,
        ["module"] = Module,
    };
}
