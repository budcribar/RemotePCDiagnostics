using System.Security.AccessControl;
using System.Security.Principal;
using RemotePCDiagnostics.Logging;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Keeps links and other people's files out of %ProgramData%\RemotePCDiagnostics. Windows lets any user create that folder
/// before RPCD is installed and put junctions, links or files in it, which the agent (SYSTEM) would otherwise follow when it
/// writes or re-permissions things there. Links are removed (the link, never what it points to). Outside the sessions folder,
/// anything not owned by Administrators, SYSTEM or TrustedInstaller is deleted. In the sessions folder each user owns their own
/// files, so files are kept there, but folders and links are not (users can't create folders there).
/// </summary>
public static class DataFolderGuard
{
    private const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private static readonly EnumerationOptions OneLevel = new()
    {
        RecurseSubdirectories = false,
        AttributesToSkip = 0,
        IgnoreInaccessible = true,
    };

    /// <summary>True when <paramref name="path"/> itself is a junction, symbolic link or other reparse point. Doesn't follow it.</summary>
    public static bool IsLink(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return false;
        }
    }

    /// <summary>Removes a link at <paramref name="path"/> (the link only). Returns true when there was one.</summary>
    public static bool RemoveLink(string path, ILogger? log = null)
    {
        if (!IsLink(path)) return false;
        log.Warn($"Data folder: removing link {path}");
        try
        {
            File.Delete(path); // a file link; on Unix any symbolic link
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            Directory.Delete(path, recursive: false); // a directory junction or symbolic link: removes the link, not its target
        }
        return true;
    }

    /// <summary>
    /// Deletes whatever is at <paramref name="path"/> without following links, so the next write creates a fresh file.
    /// Used for temp files the agent writes and then moves into place.
    /// </summary>
    public static void ClearForNewFile(string path)
    {
        if (RemoveLink(path)) return;
        if (Directory.Exists(path))
            Directory.Delete(path, recursive: true); // .NET removes links inside without following them
        else if (File.Exists(path))
            File.Delete(path);
    }

    /// <summary>Walks <paramref name="root"/> without following links and removes what isn't ours (see the class summary).</summary>
    public static void Scrub(string root, string sessionsFolder, ILogger? log)
    {
        if (!Directory.Exists(root) || IsLink(root)) return;
        var inSessions = SamePath(root, sessionsFolder);
        foreach (var entry in new DirectoryInfo(root).EnumerateFileSystemInfos("*", OneLevel))
        {
            try
            {
                if (RemoveLink(entry.FullName, log)) continue;
                if (entry is DirectoryInfo dir)
                {
                    if (inSessions || !OwnedByUs(dir))
                    {
                        log.Warn($"Data folder: removing {dir.FullName} (" + (inSessions ? "folders aren't allowed in the sessions folder)" : "not created by this app)"));
                        dir.Delete(recursive: true);
                        continue;
                    }
                    Scrub(dir.FullName, sessionsFolder, log);
                }
                else if (!inSessions && !OwnedByUs(entry))
                {
                    log.Warn($"Data folder: removing {entry.FullName} (not created by this app)");
                    entry.Delete();
                }
            }
            catch (Exception ex)
            {
                log.Warn($"Data folder: couldn't check {entry.FullName}: {ex.Message}");
            }
        }
    }

    private static bool OwnedByUs(FileSystemInfo entry)
    {
        if (!OperatingSystem.IsWindows()) return true; // ownership is a Windows rule; tests on other systems check links only
        var acl = entry is DirectoryInfo d
            ? (FileSystemSecurity)d.GetAccessControl(AccessControlSections.Owner)
            : ((FileInfo)entry).GetAccessControl(AccessControlSections.Owner);
        return acl.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner
            && (owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
                || owner.Value == TrustedInstallerSid);
    }

    private static bool SamePath(string a, string b) =>
        string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(a)), Path.TrimEndingDirectorySeparator(Path.GetFullPath(b)),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
}
