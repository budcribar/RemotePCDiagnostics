using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>The one winget command undo runs for a removed Store app. Built only by <see cref="StoreReinstall.CommandFor"/>.</summary>
public sealed record WingetCommand(string StoreId, IReadOnlyList<string> Arguments)
{
    public string Display => "winget " + string.Join(' ', Arguments);
}

/// <summary>What the Host saw when it ran winget as the signed-in user.</summary>
/// <param name="Started">winget.exe was found and started.</param>
/// <param name="ExitCode">Its exit code; null when it didn't start or didn't finish in <see cref="StoreReinstall.Timeout"/>.</param>
/// <param name="Problem">Why it didn't start or finish (for the outcome and the log).</param>
public sealed record WingetResult(bool Started, int? ExitCode, string? Problem = null)
{
    public static WingetResult NotStarted(string why) => new(false, null, why);
    public static WingetResult TimedOut() => new(true, null, "it didn't finish in 10 minutes");
    public static WingetResult Exited(int code) => new(true, code);
}

/// <summary>
/// Undo for removed Microsoft Store apps: reinstall from the Microsoft Store with winget, for the signed-in account (msstore installs are
/// per-user; the Host never runs it elevated or as SYSTEM), then check with Get-AppxPackage that the package is back.
/// Only apps on <see cref="AppRemoval.Packages"/> with a verified <see cref="RemovableAppx.StoreId"/>; the id always comes from the allowlist
/// (looked up by package family name), never from the journal alone. The only command is
/// <c>winget install --id &lt;StoreId&gt; --source msstore --accept-package-agreements --accept-source-agreements --silent --disable-interactivity</c>.
/// </summary>
public static class StoreReinstall
{
    /// <summary>How long winget may take (download + install) before the Host stops waiting and ends it.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromMinutes(10);

    // $ alone would also accept a trailing newline, hence the length check below and \z for SIDs.
    private static readonly Regex IdPattern = new("^[0-9A-Z]{12}$", RegexOptions.CultureInvariant);
    /// <summary>Local, domain and Microsoft account SIDs (S-1-5-21-…) and Microsoft Entra ID accounts (S-1-12-1-…).</summary>
    private static readonly Regex SidPattern = new(@"^S-1-(5-21|12-1)(-[0-9]{1,10}){4}\z", RegexOptions.CultureInvariant);

    /// <summary>A Store product id: exactly 12 upper-case letters or digits ("9WZDNCRFJ3Q2").</summary>
    public static bool IsValidId(string? id) => id is { Length: 12 } && IdPattern.IsMatch(id);

    public static bool IsValidSid(string? sid) => sid is not null && SidPattern.IsMatch(sid);

    /// <summary>The app is on the allowlist (exactly, never one on <see cref="AppRemoval.NeverRemove"/>) and has a valid Store id.</summary>
    public static bool CanReinstall(RemovableAppx a) => IsValidId(a.StoreId) && AppRemoval.FindPackage(a.Name, a.PublisherId) == a;

    /// <summary>
    /// Undo may reinstall a removal only when every package it removes can be reinstalled; a mixed removal (some without a Store id)
    /// stays permanent as a whole.
    /// </summary>
    public static bool CanReinstallAll(IEnumerable<RemovableAppx> apps)
    {
        var list = apps.ToList();
        return list.Count > 0 && list.All(CanReinstall);
    }

    /// <summary>"Microsoft.BingWeather_8wekyb3d8bbwe" → the allowlisted app with a Store id, or null.</summary>
    public static RemovableAppx? FindByFamily(string? familyName)
    {
        if (string.IsNullOrEmpty(familyName)) return null;
        var i = familyName.LastIndexOf('_');
        if (i <= 0 || i == familyName.Length - 1) return null;
        return AppRemoval.FindPackage(familyName[..i], familyName[(i + 1)..]) is { } app && CanReinstall(app) ? app : null;
    }

    public static IReadOnlyList<string> Arguments(string storeId) =>
        ["install", "--id", storeId, "--source", "msstore", "--accept-package-agreements", "--accept-source-agreements", "--silent", "--disable-interactivity"];

    /// <summary>
    /// The command for an allowlisted family name, or null. <paramref name="journaledId"/> (the Store id the journal recorded) must match the
    /// allowlist's when given; the command always uses the allowlist's id.
    /// </summary>
    public static WingetCommand? CommandFor(string? familyName, string? journaledId = null)
    {
        if (FindByFamily(familyName) is not { StoreId: { } id }) return null;
        if (journaledId is not null && !string.Equals(journaledId, id, StringComparison.Ordinal)) return null;
        return new(id, Arguments(id));
    }

    /// <summary>A command the Host may run: exactly the fixed form, for a Store id on the allowlist (re-checked on the Host side).</summary>
    public static bool IsAllowedCommand(WingetCommand? c) =>
        c is not null && IsValidId(c.StoreId) && AppRemoval.Packages.Any(p => p.StoreId == c.StoreId && CanReinstall(p))
        && c.Arguments.SequenceEqual(Arguments(c.StoreId), StringComparer.Ordinal);

    /// <summary>A plain local folder ("C:\Users\Ann\AppData\Local"): drive-rooted, no "..", quotes, wildcards or environment variables.</summary>
    public static bool IsSafeLocalAppData(string? path) =>
        path is { Length: >= 4 } p && char.IsAsciiLetter(p[0]) && p[1] == ':' && p[2] == '\\'
        && !p.Contains("..", StringComparison.Ordinal) && p.IndexOfAny(['"', '%', '*', '?', '<', '>', '|', '/', '\0']) < 0 && !p.Any(char.IsControl);

    /// <summary>The signed-in account's winget: <c>%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe</c> (App Installer's alias). Null for an unsafe folder.</summary>
    public static string? WingetPath(string? localAppData) =>
        IsSafeLocalAppData(localAppData) ? localAppData!.TrimEnd('\\') + @"\Microsoft\WindowsApps\winget.exe" : null;

    /// <summary>
    /// The Windows command line for <paramref name="exe"/> and <paramref name="args"/> (the same quoting as ProcessStartInfo.ArgumentList), for
    /// starting it with the signed-in user's token. Only called with a validated command; never goes through a shell.
    /// </summary>
    public static string CommandLine(string exe, IEnumerable<string> args)
    {
        var sb = new StringBuilder();
        Append(sb, exe);
        foreach (var a in args) { sb.Append(' '); Append(sb, a); }
        return sb.ToString();
    }

    private static void Append(StringBuilder sb, string arg)
    {
        if (arg.Length > 0 && arg.IndexOfAny([' ', '\t', '\n', '\v', '"']) < 0) { sb.Append(arg); return; }
        sb.Append('"');
        for (var i = 0; i < arg.Length; i++)
        {
            var slashes = 0;
            while (i < arg.Length && arg[i] == '\\') { slashes++; i++; }
            if (i == arg.Length) { sb.Append('\\', slashes * 2); break; }
            if (arg[i] == '"') sb.Append('\\', slashes * 2 + 1).Append('"');
            else sb.Append('\\', slashes).Append(arg[i]);
        }
        sb.Append('"');
    }

    /// <summary>
    /// Prints "INSTALLED:&lt;count&gt;": how many packages with this exact name and publisher id are installed for the account
    /// (<paramref name="userSid"/>; null = the account the script runs as). Only allowlisted apps and well-formed SIDs.
    /// </summary>
    public static string VerifyScript(RemovableAppx app, string? userSid)
    {
        if (!CanReinstall(app)) throw new InvalidOperationException($"{app.Label} isn't an app this app reinstalls.");
        if (userSid is not null && !IsValidSid(userSid)) throw new InvalidOperationException("That isn't an account SID.");
        var user = userSid is null ? "" : $"-User '{userSid}' ";
        return "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" +
            $"$p=@(Get-AppxPackage {user}-Name '{app.Name}' | Where-Object {{ $_.PublisherId -eq '{app.PublisherId}' }});" +
            "'INSTALLED:'+$p.Count";
    }

    /// <summary>True / false from <see cref="VerifyScript"/>'s output; null when the line is missing (the script failed).</summary>
    public static bool? ParseInstalled(string? output)
    {
        var line = (output ?? "").Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("INSTALLED:", StringComparison.Ordinal));
        return line is not null && int.TryParse(line["INSTALLED:".Length..], NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n > 0 : null;
    }

    public static string FailedMessage(string label) => $"Couldn't reinstall {label} automatically — reinstall it from the Microsoft Store.";

    /// <summary>Why winget didn't do it, in plain words ("winget ended with code 0x8A15005E").</summary>
    public static string Reason(WingetResult r) =>
        !r.Started || r.ExitCode is null ? r.Problem ?? "winget didn't run"
        : $"winget ended with code {(r.ExitCode < 0 || r.ExitCode > 0xFFFF ? "0x" + unchecked((uint)r.ExitCode.Value).ToString("X8", CultureInfo.InvariantCulture) : r.ExitCode.Value.ToString(CultureInfo.InvariantCulture))}";

    /// <summary>The journal record for a removed app undo can reinstall: family name, Store id, label.</summary>
    public static ChangeRecord Record(RemovableAppx app, long? bytes, string actor)
    {
        if (!CanReinstall(app)) throw new InvalidOperationException($"{app.Label} isn't an app this app reinstalls.");
        return ChangeRecord.New(ChangeKind.StoreReinstall, app.FamilyName, app.StoreId, AppRemoval.RemovedLabel(app, bytes, reinstall: true), actor);
    }

    /// <summary>
    /// Reinstalls one removed app for the signed-in account: already back → done; otherwise winget (fixed command) and a check with
    /// Get-AppxPackage that it's installed again. Success only when that check finds it. The caller keeps the journal entry on failure.
    /// </summary>
    public static async Task<ActionOutcome> ReinstallAsync(IAppManagementSystem sys, string? familyName, string? journaledId, CancellationToken ct, Action<string>? log = null)
    {
        var app = FindByFamily(familyName);
        var cmd = CommandFor(familyName, journaledId);
        if (app is null || cmd is null || !IsAllowedCommand(cmd))
        {
            log?.Invoke($"Refused reinstall of '{familyName}' (Store id '{journaledId}'): not on the allowlist");
            return new(false, "That app isn't one this app reinstalls, so it was left as is. Reinstall it from the Microsoft Store if needed.");
        }
        if (await sys.IsStorePackageInstalledAsync(app, ct).ConfigureAwait(false) == true)
            return new(true, $"{app.Label} is already installed for the signed-in account.");

        var r = await sys.RunWingetAsync(cmd, ct).ConfigureAwait(false);
        log?.Invoke($"Reinstall {app.FamilyName}: {cmd.Display} → {(r.Started ? r.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? "no exit code" : "not started")} {r.Problem}");
        if (!r.Started || r.ExitCode != 0) return new(false, $"{FailedMessage(app.Label)} ({Reason(r)}.)");

        var back = await sys.IsStorePackageInstalledAsync(app, ct).ConfigureAwait(false);
        if (back != true)
            return new(false, $"{FailedMessage(app.Label)} ({(back is null ? "Windows couldn't confirm it's installed" : "Windows doesn't show it installed afterwards")}.)");
        return new(true, $"{app.Label} reinstalled from the Microsoft Store for the signed-in account. Its old settings and data weren't restored.");
    }
}
