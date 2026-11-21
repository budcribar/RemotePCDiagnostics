using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Inno Setup's documented process exit codes. <see cref="Describe"/> is the sentence shown with the number.
/// Code 1 is "failed to initialize", which this app hits when a silent install finds
/// <c>Global\RemotePCDiagnostics.Host</c> still held: that prompt is answered with Cancel before CloseApplications runs.
/// Code 3 is the one that names running out of memory. Code 8 is a restart that <c>/NORESTART</c> refused.
/// </summary>
public static class InnoSetupExitCodes
{
    public static string Describe(int exitCode) => exitCode switch
    {
        0 => "Setup finished.",
        1 => "Setup failed to initialize. A silent install does this when the application is still running, the command line is invalid, or the /LOG file cannot be created.",
        2 => "Setup was cancelled before installation started.",
        3 => "Setup hit a fatal error while preparing the next step, which includes running out of memory.",
        4 => "Setup hit a fatal error while copying files.",
        5 => "Setup was cancelled during installation, or an error dialog was answered with Abort.",
        6 => "Setup was terminated by a debugger.",
        7 => "Setup stopped on Preparing to Install and did not change this PC.",
        8 => "Setup needs a restart before it can continue, and it was started with /NORESTART.",
        -1 => "Setup did not start.",
        _ => "Setup returned an unexpected exit code.",
    };
}

/// <summary>
/// The Setup log a remote update always asks for, and the tail that leaves the PC.
/// User profile paths, email addresses, and key or password arguments are masked before the tail is stored or logged.
/// </summary>
public static partial class RpcdSetupLog
{
    public const string FileName = "rpcd-setup.log";
    public const int TailLines = 200;
    public const int MaxChars = 16_000;

    /// <summary>The <c>/LOG="path"</c> switch, or null when the path could not be passed without breaking the command line.</summary>
    public static string? LogSwitch(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.IndexOfAny(['"', '\r', '\n']) >= 0)
            return null;
        return $"/LOG=\"{path}\"";
    }

    /// <summary>
    /// The agent service runs in session 0 and can end the Host without ending itself.
    /// The elevated helper runs in the user's session, inside the Host's kill-on-close job, so it must not.
    /// Setup's script closes the Host after Setup has left that job.
    /// </summary>
    public static bool CanCloseHostBeforeSetup(int sessionId) => sessionId == 0;

    /// <summary>Last <see cref="TailLines"/> lines of the Setup log, masked. Null when the file is missing or empty.</summary>
    public static string? ReadTail(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        string text;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (stream.Length > 512 * 1024)
                stream.Seek(-512 * 1024, SeekOrigin.End);
            using var reader = new StreamReader(stream);
            text = reader.ReadToEnd();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
        return Tail(text);
    }

    /// <summary>Masks <paramref name="text"/> and keeps the last <see cref="TailLines"/> lines, capped at <see cref="MaxChars"/>.</summary>
    public static string? Tail(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return null;
        var masked = Mask(text).Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        var lines = masked.Split('\n');
        if (lines.Length > TailLines)
            lines = lines[^TailLines..];
        var tail = string.Join('\n', lines).Trim();
        if (tail.Length > MaxChars)
            tail = tail[^MaxChars..];
        return tail.Length == 0 ? null : tail;
    }

    /// <summary>Hides profile paths, email addresses, and credential arguments. The rest of the log is kept.</summary>
    public static string Mask(string text)
    {
        if (string.IsNullOrEmpty(text))
            return text;
        text = UserProfile().Replace(text, "$1<user>");
        text = Email().Replace(text, "<email>");
        text = SecretArgument().Replace(text, "$1<redacted>");
        return text;
    }

    [GeneratedRegex(@"(?i)([A-Za-z]:[\\/]+(?:\?\\)?Users[\\/]+)[^\\/\r\n]+", RegexOptions.CultureInvariant)]
    private static partial Regex UserProfile();

    [GeneratedRegex(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", RegexOptions.CultureInvariant)]
    private static partial Regex Email();

    [GeneratedRegex(@"(?i)((?:--|/)(?:key|password|pwd|token|secret|apikey|api_key)=)(?:""[^""]*""|'[^']*'|\S+)", RegexOptions.CultureInvariant)]
    private static partial Regex SecretArgument();
}
