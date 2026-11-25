using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// The system settings the fixes and undo change that need administrator rights: machine-wide startup apps, service start types and
/// start/stop, hibernation and Fast Startup, and adapter DNS. The app never runs as administrator, so it has the Agent make these
/// (<see cref="AgentAdminSettings"/>, over the admin pipe); the Agent does them with <see cref="WindowsAdminSettings"/>.
/// Each throws with the reason when it can't.
/// </summary>
public interface IAdminSettingsBackend
{
    /// <summary>A machine-wide (HKLM) StartupApproved value: <c>hklm:&lt;name&gt;</c> or <c>hklm32:&lt;name&gt;</c>; null deletes it.</summary>
    void SetStartupApproved(string name, byte[]? value);
    /// <summary>"Automatic", "AutomaticDelayed", "Manual" or "Disabled".</summary>
    void SetServiceStartType(string service, string startType);
    /// <summary>Only <see cref="ServiceDelayedStart.ValueName"/>; null deletes it.</summary>
    void RestoreServiceValue(string service, string name, int? value);
    void StartService(string service);
    /// <summary>Stops the service; Windows stops its running dependents first.</summary>
    void StopService(string service);
    /// <summary>Runs powercfg /h /type reduced (or full).</summary>
    void SetHibernateType(bool reduced);
    /// <summary>Deletes one of <see cref="Hibernation.TrackedValues"/>.</summary>
    void DeleteHibernateValue(string name);
    /// <summary>HiberbootEnabled: 1 = Fast Startup on, 0 = off.</summary>
    void SetFastStartup(int value);
    /// <summary>The adapter's IPv4 DNS servers; an empty list goes back to automatic (DHCP).</summary>
    void SetAdapterDns(string alias, IReadOnlyList<string> servers);
    /// <summary>True when Windows lists <paramref name="service"/> as a driver (the Agent never starts or stops those).</summary>
    bool IsDriver(string service) => false;
}

/// <summary>Something needed administrator rights and the Agent wasn't there to do it. The message says what to do.</summary>
public sealed class AdminRequiredException(string message) : InvalidOperationException(message)
{
    /// <summary>The exception's own message when it's this one (it tells the person what to do), else <paramref name="fallback"/>.</summary>
    public static string MessageOr(Exception ex, string fallback) => ex is AdminRequiredException a ? a.Message : fallback;
}

/// <summary>One <see cref="AdminPipeFraming.OpSystemSetting"/> request: which change (<see cref="Action"/>) and its arguments.</summary>
public sealed record AdminPipeSetting(
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("target")] string? Target = null,
    [property: JsonPropertyName("name")] string? Name = null,
    [property: JsonPropertyName("text")] string? Text = null,
    [property: JsonPropertyName("number")] int? Number = null,
    [property: JsonPropertyName("bytes")] byte[]? Bytes = null,
    [property: JsonPropertyName("servers")] IReadOnlyList<string>? Servers = null)
{
    public const string StartupApproved = "startup_approved";
    public const string ServiceStartType = "service_start_type";
    public const string ServiceValue = "service_value";
    public const string ServiceStart = "service_start";
    public const string ServiceStop = "service_stop";
    public const string HibernateType = "hibernate_type";
    public const string HibernateValueDelete = "hibernate_value_delete";
    public const string FastStartup = "fast_startup";
    public const string AdapterDns = "adapter_dns";
}

/// <summary>
/// What the Agent agrees to change for the app, checked before <see cref="IAdminSettingsBackend"/> is called, so a request from the app
/// can only ever make the changes the fixes and undo make.
/// </summary>
public static class AdminSettingsRules
{
    public const int MaxDnsServers = 4;

    /// <summary>A service's key name: no path separators (it's put into an HKLM path), at most 256 characters.</summary>
    public static bool IsServiceName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Length <= 256 && name.IndexOfAny(['\\', '/']) < 0 && !name.Any(char.IsControl);

    /// <summary>A machine-wide startup entry's value name, after its <c>hklm:</c> / <c>hklm32:</c> prefix.</summary>
    public static bool IsStartupName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Length <= 260 && !name.Any(char.IsControl);

    /// <summary>Null (to delete), or a StartupApproved value: Task Manager's are 12 bytes (flags + FILETIME).</summary>
    public static bool IsStartupApprovedValue(byte[]? value) => value is null || value.Length is >= 4 and <= 12;

    /// <summary>The reason the Agent refuses <paramref name="s"/>, or null when it's allowed.</summary>
    public static string? Refusal(AdminPipeSetting s, Func<string, bool>? isDriver = null)
    {
        switch (s.Action)
        {
            case AdminPipeSetting.StartupApproved:
                var raw = MachineStartupName(s.Target);
                if (raw is null) return "Only machine-wide startup apps are changed by the Agent.";
                if (!IsStartupName(raw)) return "That isn't a startup app's name.";
                return IsStartupApprovedValue(s.Bytes) ? null : "That isn't a startup setting.";

            case AdminPipeSetting.ServiceStartType:
                if (!IsServiceName(s.Target)) return "That isn't a service name.";
                if (ServiceProtection.ProtectsStartType(s.Target!)) return "That service is protected and can't be changed.";
                return MemorySuggestionService.StartTypes.Contains(s.Text) ? null : "That isn't a start-up type.";

            case AdminPipeSetting.ServiceValue:
                if (ServiceRefusal(s.Target) is { } sv) return sv;
                if (!string.Equals(s.Name, ServiceDelayedStart.ValueName, StringComparison.OrdinalIgnoreCase)) return $"{s.Name} isn't a service value this app restores.";
                return s.Number is null or 0 or 1 ? null : "That isn't a delayed-start setting.";

            case AdminPipeSetting.ServiceStart:
                if (!IsServiceName(s.Target)) return "That isn't a service name.";
                // Starting a stopped protected service only brings Windows back to normal, so it's allowed (as on the Services page).
                if (ServiceProtection.IsSelfComponent(s.Target!) || isDriver?.Invoke(s.Target!) == true) return "That service is protected and can't be started from here.";
                return null;

            case AdminPipeSetting.ServiceStop:
                if (ServiceRefusal(s.Target) is { } ss) return ss;
                if (MemorySuggestionEngine.IsVisualStudioCollector(s.Target!) || isDriver?.Invoke(s.Target!) == true) return "That service is protected and can't be stopped from here.";
                return null;

            case AdminPipeSetting.HibernateType:
                return s.Number is 0 or 1 ? null : "That isn't a hibernation file type.";

            case AdminPipeSetting.HibernateValueDelete:
                return Hibernation.IsTracked(s.Name) ? null : $"{s.Name} isn't a hibernation value this app removes.";

            case AdminPipeSetting.FastStartup:
                return s.Number is 0 or 1 ? null : "Fast Startup is either on (1) or off (0).";

            case AdminPipeSetting.AdapterDns:
                if (!SystemSettingsRules.IsAdapterName(s.Target)) return "That isn't a network adapter name.";
                var servers = s.Servers ?? [];
                if (servers.Count > MaxDnsServers) return $"At most {MaxDnsServers} DNS servers can be set.";
                return SystemSettingsRules.Ipv4Servers(string.Join(",", servers)).Count == servers.Count ? null : "Only IPv4 DNS server addresses can be set.";

            default:
                return $"Unknown setting '{s.Action}'.";
        }
    }

    /// <summary>The value name of a <c>hklm:</c> or <c>hklm32:</c> startup entry, or null for any other.</summary>
    public static string? MachineStartupName(string? name) =>
        name is null ? null
        : name.StartsWith("hklm32:", StringComparison.OrdinalIgnoreCase) ? name[7..]
        : name.StartsWith("hklm:", StringComparison.OrdinalIgnoreCase) ? name[5..]
        : null;

    private static string? ServiceRefusal(string? service)
    {
        if (!IsServiceName(service)) return "That isn't a service name.";
        return ServiceProtection.IsProtected(service!) || ServiceProtection.IsSelfComponent(service!) ? "That service is protected and can't be changed." : null;
    }

    /// <summary>Calls the <paramref name="backend"/> method <paramref name="s"/> names (after <see cref="Refusal"/> allowed it).</summary>
    public static void Apply(IAdminSettingsBackend backend, AdminPipeSetting s)
    {
        switch (s.Action)
        {
            case AdminPipeSetting.StartupApproved: backend.SetStartupApproved(s.Target!, s.Bytes); break;
            case AdminPipeSetting.ServiceStartType: backend.SetServiceStartType(s.Target!, s.Text!); break;
            case AdminPipeSetting.ServiceValue: backend.RestoreServiceValue(s.Target!, s.Name!, s.Number); break;
            case AdminPipeSetting.ServiceStart: backend.StartService(s.Target!); break;
            case AdminPipeSetting.ServiceStop: backend.StopService(s.Target!); break;
            case AdminPipeSetting.HibernateType: backend.SetHibernateType(s.Number == 1); break;
            case AdminPipeSetting.HibernateValueDelete: backend.DeleteHibernateValue(s.Name!); break;
            case AdminPipeSetting.FastStartup: backend.SetFastStartup(s.Number!.Value); break;
            case AdminPipeSetting.AdapterDns: backend.SetAdapterDns(s.Target!, s.Servers ?? []); break;
            default: throw new InvalidOperationException($"Unknown setting '{s.Action}'.");
        }
    }
}

/// <summary>
/// The app's side: each change is sent to the Agent over the admin pipe (<see cref="IElevatedCommandBridge.ChangeSystemSettingAsync"/>).
/// Without the Agent it throws <see cref="AdminRequiredException"/> and changes nothing.
/// </summary>
public sealed class AgentAdminSettings(IElevatedCommandBridge? bridge) : IAdminSettingsBackend
{
    public void SetStartupApproved(string name, byte[]? value) => Send(new(AdminPipeSetting.StartupApproved, Target: name, Bytes: value));
    public void SetServiceStartType(string service, string startType) => Send(new(AdminPipeSetting.ServiceStartType, Target: service, Text: startType));
    public void RestoreServiceValue(string service, string name, int? value) => Send(new(AdminPipeSetting.ServiceValue, Target: service, Name: name, Number: value));
    public void StartService(string service) => Send(new(AdminPipeSetting.ServiceStart, Target: service));
    public void StopService(string service) => Send(new(AdminPipeSetting.ServiceStop, Target: service));
    public void SetHibernateType(bool reduced) => Send(new(AdminPipeSetting.HibernateType, Number: reduced ? 1 : 0));
    public void DeleteHibernateValue(string name) => Send(new(AdminPipeSetting.HibernateValueDelete, Name: name));
    public void SetFastStartup(int value) => Send(new(AdminPipeSetting.FastStartup, Number: value));
    public void SetAdapterDns(string alias, IReadOnlyList<string> servers) => Send(new(AdminPipeSetting.AdapterDns, Target: alias, Servers: servers));

    private void Send(AdminPipeSetting setting)
    {
        if (bridge is not { IsConnected: true }) throw new AdminRequiredException("The Agent isn't connected. " + ElevationService.AdminRepairHint);
        // The callers are synchronous (registry-style setters); the pipe call runs on the thread pool so no caller's context is captured.
        Task.Run(() => bridge.ChangeSystemSettingAsync(setting)).GetAwaiter().GetResult();
    }
}

/// <summary>The changes themselves, in the Agent (elevated helper or agent service). Callers check <see cref="AdminSettingsRules"/> first.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsAdminSettings(ILogger? log = null) : IAdminSettingsBackend
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string Run32Key = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string ApprovedKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string Approved32Key = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";
    private const string SessionPowerKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Power";
    private void Log(string m) => log.Info("[admin-settings] " + m);

    private static RegistryKey Hklm() => RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
    private static string ServiceKey(string name) => @"SYSTEM\CurrentControlSet\Services\" + name;

    public void SetStartupApproved(string name, byte[]? value)
    {
        var wow = name.StartsWith("hklm32:", StringComparison.OrdinalIgnoreCase);
        var raw = AdminSettingsRules.MachineStartupName(name) ?? throw new InvalidOperationException("Not a machine startup entry");
        using var lm = Hklm();
        using (var run = lm.OpenSubKey(wow ? Run32Key : RunKey))
            if (run?.GetValue(raw) is null) throw new InvalidOperationException(wow ? "Not a 32-bit machine startup entry" : "Not a machine startup entry");
        using var k = lm.CreateSubKey(wow ? Approved32Key : ApprovedKey);
        if (value is null) k.DeleteValue(raw, throwOnMissingValue: false);
        else k.SetValue(raw, value, RegistryValueKind.Binary);
        Log($"Startup app '{name}' {(value is null ? "approval removed" : StartupParsing.IsEnabled(value) ? "enabled" : "disabled")}");
    }

    public void SetServiceStartType(string service, string startType)
    {
        using var lm = Hklm();
        using var k = lm.OpenSubKey(ServiceKey(service), writable: true) ?? throw new InvalidOperationException("Service not found");
        k.SetValue("Start", startType switch { "Automatic" or "AutomaticDelayed" => 2, "Disabled" => 4, _ => 3 }, RegistryValueKind.DWord);
        if (startType == "AutomaticDelayed") k.SetValue(ServiceDelayedStart.ValueName, 1, RegistryValueKind.DWord);
        // Only clear a delayed start that's there: many services have no DelayedAutostart at all, and undo must not leave a 0 behind.
        else if (startType == "Automatic" && k.GetValue(ServiceDelayedStart.ValueName) is int d && d != 0) k.SetValue(ServiceDelayedStart.ValueName, 0, RegistryValueKind.DWord);
        Log($"Service '{service}' start type set to {startType}");
    }

    public void RestoreServiceValue(string service, string name, int? value)
    {
        using var lm = Hklm();
        using var k = lm.OpenSubKey(ServiceKey(service), writable: true) ?? throw new InvalidOperationException("Service not found");
        if (value is { } v) k.SetValue(ServiceDelayedStart.ValueName, v, RegistryValueKind.DWord);
        else k.DeleteValue(ServiceDelayedStart.ValueName, throwOnMissingValue: false);
        Log($"Service '{service}' {ServiceDelayedStart.ValueName} {(value.HasValue ? "set back to " + value.Value : "removed (it wasn't there before)")}");
    }

    public void StartService(string service)
    {
        using var sc = new ServiceController(service);
        if (sc.Status is not (ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)) sc.Start();
        Log($"Service '{service}' start requested");
    }

    public void StopService(string service)
    {
        using var sc = new ServiceController(service);
        if (sc.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)) sc.Stop(stopDependentServices: true);
        Log($"Service '{service}' stop requested");
    }

    /// <summary>True when Windows lists <paramref name="service"/> as a kernel, file-system or adapter driver.</summary>
    public bool IsDriver(string service)
    {
        try
        {
            using var sc = new ServiceController(service);
            return (sc.ServiceType & (ServiceType.KernelDriver | ServiceType.FileSystemDriver | ServiceType.Adapter | ServiceType.RecognizerDriver)) != 0;
        }
        catch (InvalidOperationException) { return false; }
    }

    /// <summary>Only ever runs System32\powercfg.exe /h /type reduced|full.</summary>
    public void SetHibernateType(bool reduced)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "powercfg.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "/h", "/type", reduced ? "reduced" : "full" }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Couldn't run powercfg.");
        var err = p.StandardError.ReadToEndAsync();
        var output = p.StandardOutput.ReadToEndAsync();
        if (!p.WaitForExit(TimeSpan.FromSeconds(60)))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new InvalidOperationException("powercfg didn't finish in time.");
        }
        if (p.ExitCode != 0)
        {
            Log($"powercfg /h /type failed ({p.ExitCode}): {err.Result.Trim()} {output.Result.Trim()}");
            throw new InvalidOperationException("Windows didn't allow changing the hibernation file (a custom size may be set).");
        }
        Log($"Hibernation file set to {(reduced ? "reduced" : "full")}");
    }

    public void DeleteHibernateValue(string name)
    {
        using var lm = Hklm();
        using var k = lm.OpenSubKey(Hibernation.PowerKey, writable: true) ?? throw new InvalidOperationException("Power key missing");
        k.DeleteValue(name, throwOnMissingValue: false);
        Log($@"HKLM\{Hibernation.PowerKey}\{name} removed (it wasn't there before)");
    }

    public void SetFastStartup(int value)
    {
        using var lm = Hklm();
        using var k = lm.OpenSubKey(SessionPowerKey, writable: true) ?? throw new InvalidOperationException("The power settings key is missing.");
        k.SetValue("HiberbootEnabled", value, RegistryValueKind.DWord);
        Log($"Fast Startup set to {value}");
    }

    public void SetAdapterDns(string alias, IReadOnlyList<string> servers)
    {
        using var config = FindAdapterConfiguration(alias) ?? throw new InvalidOperationException($"No network adapter named '{alias}'.");
        // An empty or null list makes the adapter take its DNS servers from DHCP again.
        var result = config.InvokeMethod("SetDNSServerSearchOrder", [servers.Count == 0 ? null : servers.ToArray()]);
        var code = Convert.ToUInt32(result ?? 0u);
        Log($"SetDNSServerSearchOrder '{alias}' [{string.Join(",", servers)}]: {code}");
        if (code is not (0 or 1)) throw new InvalidOperationException($"Windows refused the DNS change (WMI error {code}).");
    }

    /// <summary>The Win32_NetworkAdapterConfiguration of the adapter whose connection name (as in Settings) is <paramref name="alias"/>.</summary>
    public static ManagementObject? FindAdapterConfiguration(string alias)
    {
        var escaped = alias.Replace("\\", "\\\\").Replace("'", "\\'");
        using var adapters = new ManagementObjectSearcher($"SELECT Index FROM Win32_NetworkAdapter WHERE NetConnectionID = '{escaped}'");
        using var adapterResults = adapters.Get();
        foreach (ManagementObject adapter in adapterResults)
        {
            using (adapter)
            {
                if (adapter["Index"] is not uint index) continue;
                using var configs = new ManagementObjectSearcher($"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index = {index}");
                using var configResults = configs.Get();
                ManagementObject? found = null;
                foreach (ManagementObject config in configResults)
                {
                    if (found is null) found = config;
                    else config.Dispose();
                }
                if (found is not null) return found;
            }
        }
        return null;
    }
}
