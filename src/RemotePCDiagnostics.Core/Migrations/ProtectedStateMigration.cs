namespace RemotePCDiagnostics.Core.Migrations;

/// <summary>
/// One-time move of the undo journal, workflow, reboot resume and benchmark files from %LOCALAPPDATA%\RemotePCDiagnostics to the
/// protected state folder (<see cref="ProtectedState"/>). Each file is copied as bytes and the old one deleted, so the new file takes the
/// state folder's permissions (a move would keep the old file's, which let the user change it). A file already in the state folder wins.
/// The marker makes this run once: afterwards a file someone drops in the old folder is never read.
/// </summary>
public sealed class ProtectedStateMigration(string legacyFolder, string stateFolder, MigrationMarkers markers, Action<string>? log = null,
    Func<DateTimeOffset>? now = null)
{
    public const string MarkerKey = "protected-state";

    public MigrationOutcome Run()
    {
        if (markers.IsDone(MarkerKey)) return MigrationOutcome.AlreadyDone;
        var moved = 0;
        foreach (var name in ProtectedState.FileNames)
        {
            var from = Path.Combine(legacyFolder, name);
            var to = Path.Combine(stateFolder, name);
            try
            {
                if (!File.Exists(from)) continue;
                if (File.Exists(to))
                {
                    File.Delete(from);
                    log?.Invoke($"State move: kept {to} and removed the older copy in {legacyFolder}");
                    continue;
                }
                Directory.CreateDirectory(stateFolder);
                var tmp = to + ".tmp";
                File.WriteAllBytes(tmp, File.ReadAllBytes(from));
                File.Move(tmp, to, overwrite: false);
                File.Delete(from);
                moved++;
                log?.Invoke($"State move: {name} moved to {stateFolder}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                log?.Invoke($"State move: {name} failed, will retry next start: {ex.Message}");
                return MigrationOutcome.Failed;
            }
        }
        markers.MarkDone(MarkerKey, now?.Invoke() ?? DateTimeOffset.Now);
        return moved == 0 ? MigrationOutcome.NothingToMigrate : MigrationOutcome.Completed;
    }
}
