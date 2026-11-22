using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Default vendor-independent <see cref="IBiosSystemProbe"/>. Reads Windows SMBIOS registry values when available
/// and supplements with osquery (<c>system_info</c> and <c>platform_info</c>) so vendor providers receive
/// Manufacturer, Model, SystemSKU, BaseBoardProduct, SerialNumber, FirmwareMode, and current BIOS version/date.
/// </summary>
public sealed class DefaultBiosSystemProbe : IBiosSystemProbe
{
    private readonly OsqueryRunner? _osquery;
    private readonly ILogger? _log;

    public DefaultBiosSystemProbe(OsqueryRunner? osquery = null, ILogger? log = null)
    {
        _osquery = osquery;
        _log = log;
    }

    public async Task<BiosSystemIdentity> ProbeAsync(CancellationToken ct = default)
    {
        var reg = OperatingSystem.IsWindows() ? ReadWindowsBiosRegistry() : default;
        var firmwareMode = OperatingSystem.IsWindows() ? ReadWindowsFirmwareMode() : BiosFirmwareMode.Unknown;

        SystemInfo? sys = null;
        BiosInfo? bios = null;

        if (_osquery is { Exists: true })
        {
            try
            {
                var sysQuery = await _osquery.RunQueryAsync(HardwareInventory.SystemSql, ct).ConfigureAwait(false);
                if (sysQuery.Success && sysQuery.Rows is { Count: > 0 })
                    sys = SystemInfo.FromRow(sysQuery.Rows[0]);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _log?.Warn($"BIOS system probe: osquery system_info failed: {ex.Message}");
            }

            try
            {
                var biosQuery = await _osquery.RunQueryAsync(HardwareInventory.BiosSql, ct).ConfigureAwait(false);
                if (biosQuery.Success && biosQuery.Rows is { Count: > 0 })
                    bios = BiosInfo.FromRow(biosQuery.Rows[0]);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _log?.Warn($"BIOS system probe: osquery platform_info failed: {ex.Message}");
            }
        }

        return MergeIdentity(
            reg,
            sys,
            bios,
            firmwareMode,
            RuntimeInformation.OSDescription,
            RuntimeInformation.OSArchitecture.ToString());
    }

    internal readonly record struct WindowsBiosRegistrySnapshot(
        string SystemManufacturer,
        string SystemProductName,
        string SystemSku,
        string BaseBoardManufacturer,
        string BaseBoardProduct,
        string BaseBoardVersion,
        string BiosVendor,
        string BiosVersion,
        string BiosReleaseDate);

    internal static BiosSystemIdentity MergeIdentity(
        WindowsBiosRegistrySnapshot reg,
        SystemInfo? sys,
        BiosInfo? bios,
        BiosFirmwareMode firmwareMode,
        string osVersion,
        string architecture)
    {
        var manufacturer = FirstReported(reg.SystemManufacturer, sys?.HardwareVendor);
        var model = FirstReported(reg.SystemProductName, sys?.HardwareModel);
        var sku = FirstReported(reg.SystemSku);
        var boardManufacturer = FirstReported(reg.BaseBoardManufacturer, sys?.BoardVendor);
        var boardProduct = FirstReported(reg.BaseBoardProduct, sys?.BoardModel);
        var boardVersion = FirstReported(reg.BaseBoardVersion, sys?.BoardVersion);
        var serial = FirstReported(sys?.HardwareSerial, sys?.BoardSerial);

        var biosVendor = FirstReported(bios?.Vendor, reg.BiosVendor);
        var biosVersion = FirstReported(bios?.Version, reg.BiosVersion);
        var releaseDateRaw = FirstReported(bios?.Date, reg.BiosReleaseDate);
        var releaseDate = BiosVersionComparer.TryParseReleaseDate(releaseDateRaw);
        var smbiosRevision = FirstReported(bios?.Revision);

        var current = new BiosCurrentInfo(
            Vendor: biosVendor,
            Version: biosVersion,
            ReleaseDate: releaseDate,
            ReleaseDateRaw: releaseDateRaw,
            SmbiosRevision: smbiosRevision,
            FirmwareMode: firmwareMode);

        return new BiosSystemIdentity(
            Manufacturer: manufacturer,
            Model: model,
            SystemSku: sku,
            BoardManufacturer: boardManufacturer,
            BoardProduct: boardProduct,
            BoardVersion: boardVersion,
            SerialNumber: serial,
            OsVersion: osVersion ?? "",
            Architecture: architecture ?? "",
            CurrentBios: current);
    }

    private static string FirstReported(params string?[] candidates)
    {
        foreach (var raw in candidates)
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;
            var cleaned = SystemInfo.Reported(raw).Trim();
            if (cleaned.Length > 0)
                return cleaned;
        }
        return "";
    }

    [SupportedOSPlatform("windows")]
    private WindowsBiosRegistrySnapshot ReadWindowsBiosRegistry()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            if (key is null)
                return default;

            static string Str(RegistryKey k, string name) => k.GetValue(name) as string ?? "";

            return new WindowsBiosRegistrySnapshot(
                SystemManufacturer: Str(key, "SystemManufacturer"),
                SystemProductName: Str(key, "SystemProductName"),
                SystemSku: Str(key, "SystemSKU"),
                BaseBoardManufacturer: Str(key, "BaseBoardManufacturer"),
                BaseBoardProduct: Str(key, "BaseBoardProduct"),
                BaseBoardVersion: Str(key, "BaseBoardVersion"),
                BiosVendor: Str(key, "BIOSVendor"),
                BiosVersion: Str(key, "BIOSVersion"),
                BiosReleaseDate: Str(key, "BIOSReleaseDate"));
        }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS system probe: reading HKLM BIOS registry failed: {ex.Message}");
            return default;
        }
    }

    [SupportedOSPlatform("windows")]
    private BiosFirmwareMode ReadWindowsFirmwareMode()
    {
        try
        {
            if (GetFirmwareType(out var type))
            {
                return type switch
                {
                    1 => BiosFirmwareMode.Legacy,
                    2 => BiosFirmwareMode.Uefi,
                    _ => BiosFirmwareMode.Unknown,
                };
            }
        }
        catch (Exception ex)
        {
            _log?.Warn($"BIOS system probe: GetFirmwareType failed: {ex.Message}");
        }

        var env = Environment.GetEnvironmentVariable("firmware_type")?.Trim();
        if (string.Equals(env, "UEFI", StringComparison.OrdinalIgnoreCase))
            return BiosFirmwareMode.Uefi;
        if (string.Equals(env, "Legacy", StringComparison.OrdinalIgnoreCase))
            return BiosFirmwareMode.Legacy;
        return BiosFirmwareMode.Unknown;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFirmwareType(out uint firmwareType);
}
