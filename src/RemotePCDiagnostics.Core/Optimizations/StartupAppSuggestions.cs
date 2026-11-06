using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>Running apps and what starts with Windows: close an app, shut down idle build servers, keep an app from starting with Windows.</summary>
internal sealed class StartupAppSuggestions(SuggestionContext c)
{
    internal async Task<ActionOutcome> CloseAppAsync(MemoryAction a, CancellationToken ct)
    {
        if (ProtectedProcesses.IsProtected(a.Target)) return new(false, $"{MemoryText.FriendlyAppName(a.Target)} is part of Windows or this app and can't be closed from here.");
        if (c.Snapshot?.App(a.Target) is { IsService: true }) return new(false, "That's a background service, not an app.");
        return a.Type == MemoryActionType.CloseApp ? await c.Sys.CloseAppAsync(a.Target, ct).ConfigureAwait(false) : await c.Sys.ForceCloseAppAsync(a.Target, ct).ConfigureAwait(false);
    }

    internal async Task<ActionOutcome> ShutdownBuildServersAsync(CancellationToken ct)
    {
        var cmd = MemoryCommandAllowlist.BuildServerShutdown;
        if (!MemoryCommandAllowlist.IsAllowed(cmd.FileName, cmd.Arguments)) return new(false, "Not allowed.");
        return await c.Sys.RunCommandAsync(cmd.FileName, cmd.Arguments, ct).ConfigureAwait(false);
    }

    internal ActionOutcome DisableStartup(MemorySuggestion s, MemoryAction a)
    {
        if (c.Snapshot?.Startup?.FirstOrDefault(e => e.Name == a.Target) is not { } entry) return new(false, "That startup app is no longer listed.");
        var prev = c.Sys.GetStartupApproved(entry.Name);
        c.Sys.SetStartupApproved(entry.Name, StartupParsing.DisabledValue(c.Now()));
        c.AddUndo(new(s.Id, MemoryText.FriendlyAppName(entry.ExeName), a.Type, entry.Name, null, prev));
        c.Journal(ChangeKind.StartupApp, entry.Name, prev is null ? null : Convert.ToBase64String(prev), $"{MemoryText.FriendlyAppName(entry.ExeName)} won't start with Windows");
        return new(true, $"{MemoryText.FriendlyAppName(entry.ExeName)} won't start with Windows (your account only).");
    }

    internal ActionOutcome UndoStartup(UndoEntry u)
    {
        c.Sys.SetStartupApproved(u.Target, u.PreviousBytes);
        return new(true, $"{u.Label} will start with Windows again.");
    }
}
