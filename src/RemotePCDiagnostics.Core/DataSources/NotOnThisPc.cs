using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.DataSources;

/// <summary>
/// A check that asks WMI for a class or namespace this PC doesn't have (an older Windows, another maker's driver, a desktop with no
/// battery driver) says "Not available on this PC" instead of "Couldn't read", and the missing classes travel with the report so the
/// shop's connector can log them. <see cref="DiagnosticsService"/> opens a <see cref="WmiAnswers"/> around each run; the app's WMI source
/// (<see cref="NotingWmiSource"/>) notes every failed answer in it; <see cref="Apply"/> rewrites the result afterwards.
/// </summary>
public static class NotOnThisPc
{
    public const string Text = "Not available on this PC";

    /// <summary>The most missing answers kept per run.</summary>
    public const int MaxNoted = 20;

    /// <summary>
    /// WMI's answer for a class (0x80041010 InvalidClass), namespace (0x8004100E InvalidNamespace) or operation (0x8004100C NotSupported)
    /// this PC doesn't have. Access denied, timeouts and provider failures are not: they may work another time.
    /// </summary>
    public static bool IsMissing(string? error) =>
        error is not null && (error.Contains("0x80041010", StringComparison.OrdinalIgnoreCase)
            || error.Contains("0x8004100E", StringComparison.OrdinalIgnoreCase)
            || error.Contains("0x8004100C", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The result as the person should see it. With no missing answers it is unchanged. With missing answers only (no other failures),
    /// error cards say "Not available on this PC" without an error level, and a check left with nothing else says so as a whole (History:
    /// Skipped). Either way the report lists what was missing.
    /// </summary>
    public static DiagnosticResult Apply(DiagnosticResult r, WmiAnswers answers)
    {
        var missing = answers.Missing;
        if (missing.Count == 0 || r.Cancelled) return r;
        if (r.Payload is AreaReport report)
        {
            if (answers.OtherFailures > 0 || report.CouldNotRunReason is not null)
                return r with { Payload = report with { NotAvailable = missing } };
            var cards = report.Cards.Select(c => c.ErrorText is null ? c : c with { ErrorText = Text, Level = AreaLevel.Neutral }).ToList();
            if (report.Cards.All(c => c.ErrorText is not null))
            {
                var none = report with { Cards = cards, Summary = Text, Status = DiagnosticStatus.Warning, NotAvailable = missing, NotOnThisPc = true };
                return r with { Status = DiagnosticStatus.Warning, Message = Text, Payload = none };
            }
            // Some cards were read: the check keeps its own verdict, without the error the missing class caused.
            var status = report.Status == DiagnosticStatus.Error && !cards.Any(c => c.Level == AreaLevel.Error)
                ? AreaReport.Worst(cards.Select(c => c.Level)) : report.Status;
            return r with
            {
                Status = r.Status == DiagnosticStatus.Error ? status : r.Status,
                Payload = report with { Cards = cards, Status = status, NotAvailable = missing },
            };
        }
        if (answers.OtherFailures > 0 || r.Status != DiagnosticStatus.Error) return r;
        // A check with a payload of its own (hardware inventory) keeps it for its page; only the verdict and the line change.
        return r.Payload is null or Exception
            ? r with
            {
                Status = DiagnosticStatus.Warning, Message = Text,
                Payload = new AreaReport([], Text, DiagnosticStatus.Warning) { NotAvailable = missing, NotOnThisPc = true },
            }
            : r with { Status = DiagnosticStatus.Warning, Message = Text };
    }
}

/// <summary>
/// The WMI answers that failed during one check's run, collected by <see cref="NotingWmiSource"/>. Runs on other threads of the same
/// check (its awaits, Task.Run) see the same collection; other checks running at the same time have their own.
/// </summary>
public sealed class WmiAnswers : IDisposable
{
    private static readonly AsyncLocal<WmiAnswers?> Current = new();
    private readonly WmiAnswers? _outer;
    private readonly object _gate = new();
    private readonly List<MissingOnPc> _missing = [];
    private int _other;

    private WmiAnswers(WmiAnswers? outer) => _outer = outer;

    /// <summary>Starts collecting for the code that runs from here on (until disposed).</summary>
    public static WmiAnswers Begin()
    {
        var scope = new WmiAnswers(Current.Value);
        Current.Value = scope;
        return scope;
    }

    public IReadOnlyList<MissingOnPc> Missing { get { lock (_gate) return [.. _missing]; } }

    /// <summary>Failed answers that were not "this PC doesn't have it" (access denied, timeout, provider failure).</summary>
    public int OtherFailures { get { lock (_gate) return _other; } }

    /// <summary>Notes a WMI answer in the current run's collection, if there is one.</summary>
    public static void Note(WmiQueryResult result)
    {
        if (result.Success || Current.Value is not { } scope) return;
        lock (scope._gate)
        {
            if (!NotOnThisPc.IsMissing(result.Error)) { scope._other++; return; }
            var item = new MissingOnPc(result.Namespace, result.Query, result.Error!);
            if (scope._missing.Count < NotOnThisPc.MaxNoted && !scope._missing.Contains(item)) scope._missing.Add(item);
        }
    }

    public void Dispose()
    {
        if (Current.Value == this) Current.Value = _outer;
    }
}

/// <summary>The app's WMI source, noting each failed answer for <see cref="NotOnThisPc"/>.</summary>
public sealed class NotingWmiSource(IWmiSource inner) : IWmiSource
{
    public async Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default)
    {
        var result = await inner.QueryAsync(wmiNamespace, wql, ct).ConfigureAwait(false);
        WmiAnswers.Note(result);
        return result;
    }
}
