using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Default <see cref="IBiosInstallSafetyProbe"/> that reads AC power, battery charge, pending Windows reboot markers,
/// BitLocker protection state on the system drive, and elevation status before flashing firmware.
/// </summary>
public sealed class DefaultBiosInstallSafetyProbe : IBiosInstallSafetyProbe
{
    private const string BitLockerProbeScript =
        "$ErrorActionPreference='SilentlyContinue';" +
        "(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive+'\\').Self.ExtendedProperty('System.Volume.BitLockerProtection')";

    private readonly IElevationContext? _elevation;
    private readonly SystemCommandRunner? _commands;
    private readonly ILogger? _log;

    public DefaultBiosInstallSafetyProbe(
        IElevationContext? elevation = null,
        SystemCommandRunner? commands = null,
        ILogger? log = null)
    {
        _elevation = elevation;
        _commands = commands;
        _log = log;
    }

    public async Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default)
    {
        var hasElevation = _elevation?.HasAdminCapabilities ?? ElevationService.DetectProcessElevated();

        if (!OperatingSystem.IsWindows())
        {
            return new BiosSafetySnapshot(
                OnAcPower: null,
                HasBattery: null,
                BatteryPercent: null,
                BitLockerActive: null,
                BitLockerSuspended: null,
                HasElevation: hasElevation,
                PendingReboot: null);
        }

        var (onAcPower, hasBattery, batteryPercent) = ReadWindowsPowerStatus();
        var pendingReboot = ReadWindowsPendingReboot();
        var (bitLockerActive, bitLockerSuspended) = await ReadWindowsBitLockerStateAsync(ct).ConfigureAwait(false);

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

        return code switch
        {
            1 or 3 or 6 => (true, false),
            5 => (true, true),
            0 or 2 or 4 or 7 or 8 => (false, false),
            _ => (null, null),
        };
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
    private async Task<(bool? Active, bool? Suspended)> ReadWindowsBitLockerStateAsync(CancellationToken ct)
    {
        if (_commands is null)
            return (null, null);

        try
        {
            var result = await _commands.RunPowerShellAsync(BitLockerProbeScript, TimeSpan.FromSeconds(5), ct).ConfigureAwait(false);
            if (result is { ExitCode: 0 })
                return ParseBitLockerProtectionCode(result.StdOut);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS safety probe: BitLocker state check failed: {ex.Message}");
        }

        return (null, null);
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
