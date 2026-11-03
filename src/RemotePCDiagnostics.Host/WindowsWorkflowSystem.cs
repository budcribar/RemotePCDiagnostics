using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows side of the service workflow: an elevated "continue after sign-in" task, temporary automatic sign-in (password kept
/// as an LSA secret, like Sysinternals Autologon; never in a file or plain registry value), restarts, and the saved report.
/// </summary>
public sealed class WindowsWorkflowSystem(SystemCommandRunner commands, ISessionContext session, Action<string>? log = null) : IWorkflowSystem
{
    public const string TaskName = WorkflowService.ResumeTaskName;
    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string PasswordLessKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device";
    private void Log(string m) { try { log?.Invoke("[workflow] " + m); } catch { } }

    private static string Q(string s) => s.Replace("'", "''");

    private async Task<bool> PsAsync(string script, CancellationToken ct)
    {
        var r = await commands.RunAsync(SystemCommandRunner.PowerShell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], ct).ConfigureAwait(false);
        Log($"powershell exit={r?.ExitCode} err={r?.StdErr.Trim()}");
        return r is { ExitCode: 0 };
    }

    // ---- continue after sign-in (Task Scheduler: starts elevated without a UAC prompt, unlike RunOnce) ----
    public Task<bool> RegisterResumeAsync(CancellationToken ct)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("No process path");
        var full = SessionLaunchOptions.BuildResumeCommandLine(exe, session.Mode, session.ServerUri, session.SessionId, session.Mirror);
        var args = full[$"\"{exe.Trim('"')}\"".Length..].Trim() + " --workflow";
        var user = $"{Environment.UserDomainName}\\{Environment.UserName}";
        var script =
            "$ErrorActionPreference='Stop';" +
            $"$a=New-ScheduledTaskAction -Execute '{Q(exe)}' -Argument '{Q(args)}' -WorkingDirectory '{Q(Path.GetDirectoryName(exe)!)}';" +
            $"$t=New-ScheduledTaskTrigger -AtLogOn -User '{Q(user)}';" +
            $"$p=New-ScheduledTaskPrincipal -UserId '{Q(user)}' -LogonType Interactive -RunLevel Highest;" +
            "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero);" +
            $"Register-ScheduledTask -TaskName '{Q(TaskName)}' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null";
        Log($"register resume task: {exe} {args}");
        return PsAsync(script, ct);
    }

    /// <summary>Removes the task (a missing task is fine) and fails only when it's still registered afterwards.</summary>
    public Task<bool> RemoveResumeAsync(CancellationToken ct) =>
        PsAsync($"Unregister-ScheduledTask -TaskName '{Q(TaskName)}' -Confirm:$false -ErrorAction SilentlyContinue; " +
                $"if (Get-ScheduledTask -TaskName '{Q(TaskName)}' -ErrorAction SilentlyContinue) {{ exit 1 }}", ct);

    // ---- restart ----
    public async Task<bool> RestartAsync(TimeSpan delay, string message, CancellationToken ct)
    {
        var r = await commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/r", "/t", ((int)delay.TotalSeconds).ToString(), "/c", message], ct).ConfigureAwait(false);
        return r is { ExitCode: 0 };
    }

    public async Task AbortRestartAsync(CancellationToken ct) =>
        await commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/a"], ct).ConfigureAwait(false);

    public TimeSpan Uptime => TimeSpan.FromMilliseconds(Environment.TickCount64);

    // ---- automatic sign-in ----
    public AutoLogonStatus GetAutoLogonStatus()
    {
        var user = Environment.UserName; var domain = Environment.UserDomainName;
        using var wl = Registry.LocalMachine.OpenSubKey(WinlogonKey);
        var already = (wl?.GetValue("AutoAdminLogon") as string) == "1";
        using var pl = Registry.LocalMachine.OpenSubKey(PasswordLessKey);
        var helloOnly = pl?.GetValue("DevicePasswordLessBuildVersion") is int v && v == 2;
        return new(user, domain, already, helloOnly, helloOnly
            ? "This PC has \"Only allow Windows Hello sign-in\" turned on. Automatic sign-in will temporarily turn that off for the two restarts and turn it back on during cleanup (or tick Skip so the client signs in after each restart)."
            : already ? "This PC already signs in automatically." : null, FindMicrosoftAccountEmail());
    }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetUserNameEx(int nameFormat, System.Text.StringBuilder name, ref uint size);

    /// <summary>
    /// The signed-in user's Microsoft account email, or null for a local/domain account. Read-only; never throws.
    /// Sources in order: IdentityStore cache (HKLM, keyed by the user's SID), IdentityCRL UserExtendedProperties (HKCU, subkeys named by email),
    /// then the user principal name (only if it looks like an email and the IdentityStore says nothing else).
    /// </summary>
    private string? FindMicrosoftAccountEmail()
    {
        static string? Email(object? v) => v is string s && s.Contains('@') && !s.Contains(' ') ? s.Trim() : null;
        try
        {
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
            if (sid is not null)
            {
                using var ic = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\IdentityStore\Cache\{sid}\IdentityCache\{sid}");
                if (Email(ic?.GetValue("UserName")) is { } e1) return e1;
            }
        }
        catch (Exception ex) { Log("identity store lookup: " + ex.Message); }
        try
        {
            using var ux = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\IdentityCRL\UserExtendedProperties");
            if (ux?.GetSubKeyNames().Select(Email).FirstOrDefault(e => e is not null) is { } e2) return e2;
        }
        catch (Exception ex) { Log("IdentityCRL lookup: " + ex.Message); }
        try
        {
            uint size = 256; var sb = new System.Text.StringBuilder((int)size);
            if (GetUserNameEx(8 /* NameUserPrincipal */, sb, ref size) && Email(sb.ToString()) is { } e3
                && string.Equals(Environment.UserDomainName, Environment.MachineName, StringComparison.OrdinalIgnoreCase)) return e3;
        }
        catch (Exception ex) { Log("UPN lookup: " + ex.Message); }
        return null;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(string user, string domain, string password, int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);

    public bool ValidateCredentials(string user, string domain, string password)
    {
        int? restorePasswordLess = null;
        try
        {
            using var pl = Registry.LocalMachine.OpenSubKey(PasswordLessKey, writable: true);
            if (pl?.GetValue("DevicePasswordLessBuildVersion") is int v && v != 0)
            {
                restorePasswordLess = v;
                pl.SetValue("DevicePasswordLessBuildVersion", 0, RegistryValueKind.DWord);
            }
        }
        catch (Exception ex) { Log("passwordless check before validate: " + ex.Message); }
        try
        {
            if (!LogonUser(user, domain, password, 2 /* interactive */, 0, out var token))
            {
                var err = Marshal.GetLastWin32Error();
                Log($"credential check failed for {domain}\\{user}: Win32 error {err}{err switch { 1326 => " (wrong user name or password)", 1327 => " (account restriction)", 1385 => " (logon type not granted)", 1311 => " (no logon server)", 1909 => " (account locked out)", _ => "" }}");
                return false;
            }
            CloseHandle(token);
            Log($"credential check passed for {domain}\\{user}");
            return true;
        }
        finally
        {
            if (restorePasswordLess is int prev)
            {
                try { using var pl = Registry.LocalMachine.OpenSubKey(PasswordLessKey, writable: true); pl?.SetValue("DevicePasswordLessBuildVersion", prev, RegistryValueKind.DWord); }
                catch (Exception ex) { Log("passwordless restore after validate: " + ex.Message); }
            }
        }
    }

    public AutoLogonBackup EnableAutoLogon(string user, string domain, string password, int logons)
    {
        using var wl = Registry.LocalMachine.OpenSubKey(WinlogonKey, writable: true) ?? throw new InvalidOperationException("Winlogon key missing");
        int? passwordLess = null;
        using (var pl = Registry.LocalMachine.OpenSubKey(PasswordLessKey, writable: true))
        {
            if (pl?.GetValue("DevicePasswordLessBuildVersion") is int v)
            {
                passwordLess = v;
                if (v != 0) pl.SetValue("DevicePasswordLessBuildVersion", 0, RegistryValueKind.DWord);
            }
        }
        var backup = new AutoLogonBackup(wl.GetValue("AutoAdminLogon") as string, wl.GetValue("DefaultUserName") as string,
            wl.GetValue("DefaultDomainName") as string, wl.GetValue("AutoLogonCount")?.ToString(), passwordLess);
        StoreSecret("DefaultPassword", password);
        wl.DeleteValue("DefaultPassword", throwOnMissingValue: false); // never a plain-text copy
        wl.SetValue("DefaultUserName", user, RegistryValueKind.String);
        wl.SetValue("DefaultDomainName", domain, RegistryValueKind.String);
        wl.SetValue("AutoLogonCount", logons, RegistryValueKind.DWord); // Windows turns it off by itself after this many sign-ins
        wl.SetValue("AutoAdminLogon", "1", RegistryValueKind.String);
        Log($"automatic sign-in on for {domain}\\{user} ({logons} sign-ins, passwordless was {passwordLess?.ToString() ?? "unset"})");
        return backup;
    }

    public void DisableAutoLogon(AutoLogonBackup? backup)
    {
        StoreSecret("DefaultPassword", null);
        using var wl = Registry.LocalMachine.OpenSubKey(WinlogonKey, writable: true);
        if (wl is not null)
        {
            void Restore(string name, string? value) { if (value is null) wl.DeleteValue(name, false); else wl.SetValue(name, value, RegistryValueKind.String); }
            wl.SetValue("AutoAdminLogon", backup?.AutoAdminLogon ?? "0", RegistryValueKind.String);
            Restore("DefaultUserName", backup?.DefaultUserName);
            Restore("DefaultDomainName", backup?.DefaultDomainName);
            if (backup?.AutoLogonCount is { } c && int.TryParse(c, out var n)) wl.SetValue("AutoLogonCount", n, RegistryValueKind.DWord); else wl.DeleteValue("AutoLogonCount", false);
        }
        if (backup?.PasswordLessBuildVersion is int pv)
        {
            using var pl = Registry.LocalMachine.OpenSubKey(PasswordLessKey, writable: true);
            pl?.SetValue("DevicePasswordLessBuildVersion", pv, RegistryValueKind.DWord);
        }
        Log("automatic sign-in off; stored password removed and previous sign-in settings restored");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_UNICODE_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
    [DllImport("advapi32.dll")] private static extern uint LsaOpenPolicy(IntPtr system, ref LSA_OBJECT_ATTRIBUTES attrs, uint access, out IntPtr policy);
    [DllImport("advapi32.dll")] private static extern uint LsaStorePrivateData(IntPtr policy, ref LSA_UNICODE_STRING key, IntPtr data);
    [DllImport("advapi32.dll")] private static extern uint LsaClose(IntPtr policy);
    [DllImport("advapi32.dll")] private static extern uint LsaNtStatusToWinError(uint status);
    private const uint POLICY_CREATE_SECRET = 0x20;

    /// <summary>Stores (or with null, deletes) an LSA private data secret — where Windows reads the automatic sign-in password.</summary>
    private static void StoreSecret(string name, string? value)
    {
        var attrs = new LSA_OBJECT_ATTRIBUTES { Length = Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
        var st = LsaOpenPolicy(IntPtr.Zero, ref attrs, POLICY_CREATE_SECRET, out var policy);
        if (st != 0) throw new System.ComponentModel.Win32Exception((int)LsaNtStatusToWinError(st));
        var keyBuf = Marshal.StringToHGlobalUni(name);
        IntPtr valBuf = IntPtr.Zero, valStruct = IntPtr.Zero;
        try
        {
            var key = new LSA_UNICODE_STRING { Buffer = keyBuf, Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2 + 2) };
            if (value is not null)
            {
                valBuf = Marshal.StringToHGlobalUni(value);
                valStruct = Marshal.AllocHGlobal(Marshal.SizeOf<LSA_UNICODE_STRING>());
                Marshal.StructureToPtr(new LSA_UNICODE_STRING { Buffer = valBuf, Length = (ushort)(value.Length * 2), MaximumLength = (ushort)(value.Length * 2 + 2) }, valStruct, false);
            }
            st = LsaStorePrivateData(policy, ref key, valStruct);
            // Deleting a secret that doesn't exist is fine (STATUS_OBJECT_NAME_NOT_FOUND).
            if (st != 0 && !(value is null && st == 0xC0000034)) throw new System.ComponentModel.Win32Exception((int)LsaNtStatusToWinError(st));
        }
        finally
        {
            Marshal.FreeHGlobal(keyBuf);
            if (valBuf != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(valBuf);
            if (valStruct != IntPtr.Zero) Marshal.FreeHGlobal(valStruct);
            LsaClose(policy);
        }
    }

    // ---- report ----
    public string ReportFile(DateTimeOffset when) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), "Remote PC Diagnostics", $"Service report {when.LocalDateTime:yyyy-MM-dd HHmm}.html");

    public void SaveReport(string path, string html)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, html);
    }
}
