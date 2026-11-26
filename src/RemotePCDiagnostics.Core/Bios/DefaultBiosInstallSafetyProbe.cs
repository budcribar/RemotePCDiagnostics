using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Default <see cref="IBiosInstallSafetyProbe"/> that reads AC power, battery charge, pending Windows reboot markers,
/// BitLocker protection state on the system drive (pure C# COM/WMI), and elevation status before flashing firmware.
/// </summary>
public sealed partial class DefaultBiosInstallSafetyProbe : IBiosInstallSafetyProbe
{
    private readonly IElevationContext? _elevation;
    private readonly ILogger? _log;
    private readonly Func<CancellationToken, Task<int?>>? _bitLockerProbe;

    [GeneratedRegex("^[A-Za-z]:$", RegexOptions.CultureInvariant)]
    private static partial Regex SystemDrivePattern();

    public DefaultBiosInstallSafetyProbe(
        IElevationContext? elevation = null,
        SystemCommandRunner? commands = null,
        ILogger? log = null,
        Func<CancellationToken, Task<int?>>? bitLockerProbe = null)
    {
        _elevation = elevation;
        _ = commands; // Preserved for DI/constructor backward compatibility; BitLocker probing is pure C# COM/WMI.
        _log = log;
        _bitLockerProbe = bitLockerProbe;
    }

    public async Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default)
    {
        var hasElevation = _elevation?.HasAdminCapabilities ?? ElevationService.DetectProcessElevated();

        if (!OperatingSystem.IsWindows())
        {
            var (injectedActive, injectedSuspended) = _bitLockerProbe is not null
                ? await ReadInjectedBitLockerStateAsync(ct).ConfigureAwait(false)
                : (null, null);

            return new BiosSafetySnapshot(
                OnAcPower: null,
                HasBattery: null,
                BatteryPercent: null,
                BitLockerActive: injectedActive,
                BitLockerSuspended: injectedSuspended,
                HasElevation: hasElevation,
                PendingReboot: null);
        }

        var (onAcPower, hasBattery, batteryPercent) = ReadWindowsPowerStatus();
        var pendingReboot = ReadWindowsPendingReboot();
        var (bitLockerActive, bitLockerSuspended) = _bitLockerProbe is not null
            ? await ReadInjectedBitLockerStateAsync(ct).ConfigureAwait(false)
            : await ReadWindowsBitLockerStateAsync(ct).ConfigureAwait(false);

        return new BiosSafetySnapshot(
            OnAcPower: onAcPower,
            HasBattery: hasBattery,
            BatteryPercent: batteryPercent,
            BitLockerActive: bitLockerActive,
            BitLockerSuspended: bitLockerSuspended,
            HasElevation: hasElevation,
            PendingReboot: pendingReboot);
    }

    /// <summary>
    /// Interprets Windows Shell <c>System.Volume.BitLockerProtection</c> values:
    /// <c>1</c> (on), <c>3</c> (encrypting), <c>6</c> (locked) =&gt; active;
    /// <c>5</c> (suspended) =&gt; active &amp; suspended;
    /// <c>0</c>, <c>2</c>, <c>4</c>, <c>7</c>, <c>8</c> =&gt; not active.
    /// </summary>
    public static (bool? Active, bool? Suspended) ParseBitLockerProtectionCode(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return (null, null);

        var line = raw.Trim().Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim();
        if (!int.TryParse(line, NumberStyles.Integer, CultureInfo.InvariantCulture, out var code))
            return (null, null);

        return ParseBitLockerProtectionCode(code);
    }

    /// <summary>
    /// Interprets numeric Windows Shell <c>System.Volume.BitLockerProtection</c> values.
    /// </summary>
    public static (bool? Active, bool? Suspended) ParseBitLockerProtectionCode(int code) => code switch
    {
        1 or 3 or 6 => (true, false),
        5 => (true, true),
        0 or 2 or 4 or 7 or 8 => (false, false),
        _ => (null, null),
    };

    /// <summary>
    /// Interprets WMI <c>Win32_EncryptableVolume</c> <c>ProtectionStatus</c> and optional <c>ConversionStatus</c>.
    /// Separate from Shell codes so WMI <c>2</c> (UNKNOWN) is never confused with Shell <c>2</c> (Off).
    /// </summary>
    public static (bool? Active, bool? Suspended) ParseWmiBitLockerProtectionStatus(
        int protectionStatus,
        int? conversionStatus = null) => protectionStatus switch
    {
        1 => (true, false),
        0 => conversionStatus is 1 or 2 or 4 ? (true, true) : (false, false),
        _ => (null, null),
    };

    /// <summary>
    /// Validates and normalizes a Windows drive specifier (<c>^[A-Za-z]:$</c>), falling back to <c>"C:"</c>.
    /// </summary>
    public static string ResolveSystemDrive(string? rawSystemDrive)
    {
        var candidate = rawSystemDrive?.Trim();
        return !string.IsNullOrEmpty(candidate) && SystemDrivePattern().IsMatch(candidate)
            ? candidate.ToUpperInvariant()
            : "C:";
    }

    private static int? TryConvertToInt32(object? raw)
    {
        if (raw is null || raw is DBNull)
            return null;

        if (raw is int i)
            return i;

        if (raw is string s)
            return int.TryParse(s.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

        try
        {
            return Convert.ToInt32(raw, CultureInfo.InvariantCulture);
        }
        catch
        {
            return null;
        }
    }

    private async Task<(bool? Active, bool? Suspended)> ReadInjectedBitLockerStateAsync(CancellationToken ct)
    {
        try
        {
            var code = await _bitLockerProbe!(ct).ConfigureAwait(false);
            return code.HasValue ? ParseBitLockerProtectionCode(code.Value) : (null, null);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS safety probe: BitLocker state check failed: {ex.Message}");
            return (null, null);
        }
    }

    [SupportedOSPlatform("windows")]
    private (bool? OnAcPower, bool? HasBattery, int? BatteryPercent) ReadWindowsPowerStatus()
    {
        try
        {
            if (!GetSystemPowerStatus(out var status))
                return (null, null, null);

            bool? onAc = status.ACLineStatus switch
            {
                0 => false,
                1 => true,
                _ => null,
            };

            bool? hasBattery = status.BatteryFlag == 255
                ? null
                : (status.BatteryFlag & 128) == 0;

            int? percent = status.BatteryLifePercent <= 100
                ? status.BatteryLifePercent
                : null;

            return (onAc, hasBattery, percent);
        }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS safety probe: GetSystemPowerStatus failed: {ex.Message}");
            return (null, null, null);
        }
    }

    [SupportedOSPlatform("windows")]
    private bool? ReadWindowsPendingReboot()
    {
        try
        {
            using (var cbs = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"))
            {
                if (cbs is not null)
                    return true;
            }

            using (var wu = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
            {
                if (wu is not null)
                    return true;
            }

            using (var sm = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager"))
            {
                if (sm?.GetValue("PendingFileRenameOperations") is string[] pending && pending.Any(s => !string.IsNullOrWhiteSpace(s)))
                    return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS safety probe: pending reboot registry check failed: {ex.Message}");
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private Task<(bool? Active, bool? Suspended)> ReadWindowsBitLockerStateAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.Run(() => ReadWindowsBitLockerStateCore(ct), ct);
    }

    [SupportedOSPlatform("windows")]
    private (bool? Active, bool? Suspended) ReadWindowsBitLockerStateCore(CancellationToken ct)
    {
        var systemDrive = ResolveSystemDrive(Environment.GetEnvironmentVariable("SystemDrive"));

        var shellCode = TryReadBitLockerCodeViaShellCom(systemDrive);
        if (shellCode.HasValue)
        {
            var parsed = ParseBitLockerProtectionCode(shellCode.Value);
            if (parsed.Active.HasValue || parsed.Suspended.HasValue)
                return parsed;
        }

        ct.ThrowIfCancellationRequested();
        return TryReadBitLockerViaWmi(systemDrive);
    }

    [SupportedOSPlatform("windows")]
    private int? TryReadBitLockerCodeViaShellCom(string systemDrive)
    {
        object? shellObj = null;
        object? folderObj = null;
        object? selfObj = null;
        try
        {
            var shellType = Type.GetTypeFromProgID("Shell.Application", throwOnError: false);
            if (shellType is null)
                return null;

            shellObj = Activator.CreateInstance(shellType);
            if (shellObj is null)
                return null;

            dynamic shell = shellObj;
            folderObj = shell.NameSpace(systemDrive + "\\");
            if (folderObj is null)
                return null;

            dynamic folder = folderObj;
            selfObj = folder.Self;
            if (selfObj is null)
                return null;

            dynamic self = selfObj;
            object? raw = self.ExtendedProperty("System.Volume.BitLockerProtection");
            return TryConvertToInt32(raw);
        }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS safety probe: Shell.Application BitLocker check failed: {ex.Message}");
            return null;
        }
        finally
        {
            ReleaseComObjectSafe(selfObj);
            ReleaseComObjectSafe(folderObj);
            ReleaseComObjectSafe(shellObj);
        }
    }

    [SupportedOSPlatform("windows")]
    private (bool? Active, bool? Suspended) TryReadBitLockerViaWmi(string systemDrive)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\CIMV2\Security\MicrosoftVolumeEncryption");
            scope.Connect();
            var query = new ObjectQuery(
                $"SELECT DriveLetter, ProtectionStatus, ConversionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = '{systemDrive}'");
            using var searcher = new ManagementObjectSearcher(scope, query);
            using var results = searcher.Get();
            foreach (var mo in results.OfType<ManagementObject>())
            {
                using (mo)
                {
                    var protectionStatus = TryConvertToInt32(SafeReadWmiProperty(mo, "ProtectionStatus"));
                    if (!protectionStatus.HasValue)
                        continue;

                    var conversionStatus = TryConvertToInt32(SafeReadWmiProperty(mo, "ConversionStatus"));
                    return ParseWmiBitLockerProtectionStatus(protectionStatus.Value, conversionStatus);
                }
            }
        }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS safety probe: WMI BitLocker check failed: {ex.Message}");
        }

        return (null, null);
    }

    [SupportedOSPlatform("windows")]
    private static object? SafeReadWmiProperty(ManagementObject mo, string propertyName)
    {
        try
        {
            return mo[propertyName];
        }
        catch (ManagementException)
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ReleaseComObjectSafe(object? comObject)
    {
        if (comObject is null)
            return;

        try
        {
            if (Marshal.IsComObject(comObject))
                Marshal.ReleaseComObject(comObject);
        }
        catch (ArgumentException)
        {
            // Ignore non-COM objects or already-released RCWs.
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);
}
