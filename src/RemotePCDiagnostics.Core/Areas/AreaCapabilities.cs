namespace RemotePCDiagnostics.Core.Areas;

// What a module offers on its page beyond its report. Pages ask for these instead of checking for a concrete module type,
// so a new module (or a plugin) gets the same panel or action by implementing the interface, without editing the page.

/// <summary>Panels a module's page shows under its report.</summary>
[Flags]
public enum AreaPanels
{
    None = 0,
    /// <summary>"Ways to use less memory" (the memory suggestions panel and its link on the memory card).</summary>
    MemorySuggestions = 1,
    /// <summary>Storage clean-up suggestions.</summary>
    StorageCleanup = 2,
}

/// <summary>A module whose page shows extra panels (<see cref="AreaPanels"/>).</summary>
public interface IHasAreaPanels
{
    AreaPanels Panels { get; }
}

/// <summary>A module whose report rows are Windows services, so the page can offer Start, Stop and Restart on each row.</summary>
public interface IServiceRows
{
    /// <summary>The services found by the latest run, by name. A new dictionary each run.</summary>
    IReadOnlyDictionary<string, ServiceInfo> Latest { get; }
}

/// <summary>A module that can look up Windows log evidence around app freezes (rows with <see cref="AreaRow.HangOccurrences"/>).</summary>
public interface IHangEvidenceSource
{
    /// <summary>The id of the card whose rows can be collected together into one shared timeline.</summary>
    string HangCardId { get; }
    Task<string> FindHangEvidenceAsync(IReadOnlyList<HangOccurrence> occurrences, CancellationToken ct);
}

/// <summary>A long scan (DISM, SFC) the user can cancel from the Checks screen while it runs; progress comes as a <c>double</c> percent payload.</summary>
public interface ICancellableScan
{
    void Cancel();
}
