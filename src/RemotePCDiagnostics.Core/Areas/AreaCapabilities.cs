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

/// <summary>
/// A module that offers some of the interfaces above through another object: the app's stand-in for a module that runs out of process
/// (UserModeModuleProxy), which can't implement them itself because what it offers depends on the module and its last run.
/// </summary>
public interface IModuleFeatures
{
    /// <summary>The module's <typeparamref name="T"/>, or null when it offers none (now).</summary>
    T? Feature<T>() where T : class;
}

public static class ModuleFeatureExtensions
{
    /// <summary>What a page asks instead of <c>module as T</c>: the module itself, or what its stand-in offers (<see cref="IModuleFeatures"/>),
    /// so a page works the same in and out of process.</summary>
    public static T? Feature<T>(this IDiagnosticModule? module) where T : class =>
        module as T ?? (module as IModuleFeatures)?.Feature<T>();
}
