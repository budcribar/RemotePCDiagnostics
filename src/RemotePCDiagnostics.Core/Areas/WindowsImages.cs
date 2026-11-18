namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Windows installation images on this PC's drives (a mounted ISO or USB install media): repair sources for DISM.</summary>
public static class WindowsImages
{
    /// <summary>Every <c>X:\sources\install.wim</c> or <c>install.esd</c> on a ready drive. Empty when none, or when drives can't be listed.</summary>
    public static IReadOnlyList<string> FindOnDrives()
    {
        var found = new List<string>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (!drive.IsReady) continue;
                    foreach (var name in new[] { "install.wim", "install.esd" })
                    {
                        var path = Path.Combine(drive.RootDirectory.FullName, "sources", name);
                        if (File.Exists(path)) found.Add(path);
                    }
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return found;
    }
}
