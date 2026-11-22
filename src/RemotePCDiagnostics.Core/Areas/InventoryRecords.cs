using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

// The records Programs & updates and Device Manager & drivers report, here so their readers (WMI and the legacy osquery ones) can make them.

public sealed record InstalledProgram(string Name, string Version, string Publisher, DateOnly? InstalledOn)
{
    public static InstalledProgram FromRow(IReadOnlyDictionary<string, string> r) =>
        new(r.Str("name"), r.Str("version"), r.Str("publisher"), OsqueryDates.Parse(r.Str("install_date")));
}

public sealed record InstalledUpdate(string Id, string Description, DateOnly? InstalledOn)
{
    public static InstalledUpdate FromRow(IReadOnlyDictionary<string, string> r) =>
        new(r.Str("hotfix_id"), r.Str("description"), OsqueryDates.Parse(r.Str("installed_on")));
}

/// <summary>One device in Device Manager that has a non-zero <c>ConfigManagerErrorCode</c> (<c>Win32_PnPEntity</c>).</summary>
public sealed record ProblemDevice(string Name, string Class, string DeviceId, int ErrorCode, string Status)
{
    public static ProblemDevice FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("Name").Length > 0 ? r.Str("Name") : "Unknown device",
        r.Str("Class"), r.Str("DeviceId"), r.Int("ErrorCode") ?? 0, r.Str("Status"));

    public bool IsDisabledOnly => ErrorCode == 22;

    public string FriendlyError => ErrorCode switch
    {
        1 => "Not configured correctly (Code 1)",
        10 => "Cannot start (Code 10)",
        12 => "Not enough free resources (Code 12)",
        14 => "Restart required (Code 14)",
        18 => "Reinstall drivers (Code 18)",
        19 => "Registry configuration damaged (Code 19)",
        22 => "Disabled (Code 22)",
        24 => "Not present or not working (Code 24)",
        28 => "Drivers not installed (Code 28)",
        31 => "Cannot load required drivers (Code 31)",
        32 => "Driver service disabled (Code 32)",
        37 => "Driver initialization failed (Code 37)",
        39 => "Driver corrupted or missing (Code 39)",
        43 => "Device reported a problem and was stopped (Code 43)",
        45 => "Not connected (Code 45)",
        47 => "Prepared for safe removal (Code 47)",
        48 => "Blocked from starting (Code 48)",
        52 => "Unsigned driver signature (Code 52)",
        _ => $"Problem code {ErrorCode}",
    };
}

/// <summary>One installed hardware driver from osquery <c>drivers</c>.</summary>
public sealed record DriverEntry(string DeviceName, string Class, string Provider, string Version, DateOnly? Date, bool Signed)
{
    public static DriverEntry FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("device_name").Length > 0 ? r.Str("device_name") : r.Str("description"),
        r.Str("class"),
        r.Str("provider").Length > 0 ? r.Str("provider") : r.Str("manufacturer"),
        r.Str("version"),
        OsqueryDates.Parse(r.Str("date")),
        r.Str("signed") != "0");
}

