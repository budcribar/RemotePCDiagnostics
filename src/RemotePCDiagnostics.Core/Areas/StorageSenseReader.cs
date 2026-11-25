using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Snapshot of Windows Storage Sense user settings and machine Group Policy.</summary>
public sealed record StorageSenseStatus(
    bool Enabled,
    bool PolicyControlled,
    int? PolicyGlobalValue,
    int? Cadence,
    int? CleanTempFiles,
    int? CleanRecycleBin,
    int? RecycleBinDays,
    int? CleanDownloads,
    int? DownloadsDays)
{
    public bool CanOfferEnable => !Enabled && !PolicyControlled;

    public string CadenceText => Cadence switch
    {
        1 => "Every day",
        7 => "Every week",
        30 => "Every month",
        0 or null => "During low free disk space (Windows default)",
        _ => $"Every {Cadence} days",
    };

    public string TempFilesText => CleanTempFiles switch
    {
        0 => "Off",
        1 => "On",
        _ => "On (Windows default)",
    };

    public string RecycleBinText => CleanRecycleBin switch
    {
        0 => "Never",
        1 => RecycleBinDays is > 0 ? $"After {RecycleBinDays} days" : "After 30 days (Windows default)",
        _ => RecycleBinDays is > 0 ? $"After {RecycleBinDays} days" : "After 30 days (Windows default)",
    };

    public string DownloadsText => CleanDownloads switch
    {
        1 => DownloadsDays is > 0 ? $"After {DownloadsDays} days" : "On (existing setting preserved)",
        0 => "Never",
        _ => "Never (Windows default)",
    };

    /// <summary>Plain-English description of what turning Storage Sense on will actually do, preserving existing user choices.</summary>
    public string DescribeEffectiveBehavior() =>
        $"Schedule: {CadenceText}; temporary files: {TempFilesText}; Recycle Bin: {RecycleBinText}; Downloads: {DownloadsText}. " +
        "Existing schedule and retention choices are preserved. Undo restores the Storage Sense setting, but cannot recover files Windows has already deleted.";
}

/// <summary>Reads Storage Sense HKCU settings and HKLM policy through <see cref="IRegistrySource"/> so record/replay captures it.</summary>
public static class StorageSenseReader
{
    public const string PolicyKey = @"SOFTWARE\Policies\Microsoft\Windows\StorageSense";
    public const string PolicyGlobalValueName = "AllowStorageSenseGlobal";
    public const string UserKey = @"Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy";

    public static async Task<StorageSenseStatus?> ReadAsync(IRegistrySource registry, CancellationToken ct)
    {
        var policyRead = await registry.ReadAsync(new RegistryRead(DataSources.RegistryRoot.LocalMachine, PolicyKey, [PolicyGlobalValueName]), ct).ConfigureAwait(false);
        var userRead = await registry.ReadAsync(new RegistryRead(DataSources.RegistryRoot.CurrentUser, UserKey, ["01", "2048", "04", "08", "256", "32", "512"]), ct).ConfigureAwait(false);

        if (!policyRead.Success && !userRead.Success)
            return null;

        var policyRow = policyRead.Rows?.FirstOrDefault();
        var userRow = userRead.Rows?.FirstOrDefault();

        int? Int(WmiRow? row, string name) => row?.Long(name) is { } v and >= int.MinValue and <= int.MaxValue ? (int)v : null;

        var policyGlobal = Int(policyRow, PolicyGlobalValueName);
        var policyControlled = policyGlobal.HasValue;
        var userEnabled = Int(userRow, "01");

        var enabled = policyControlled
            ? policyGlobal == 1
            : userEnabled == 1;

        return new StorageSenseStatus(
            Enabled: enabled,
            PolicyControlled: policyControlled,
            PolicyGlobalValue: policyGlobal,
            Cadence: Int(userRow, "2048"),
            CleanTempFiles: Int(userRow, "04"),
            CleanRecycleBin: Int(userRow, "08"),
            RecycleBinDays: Int(userRow, "256"),
            CleanDownloads: Int(userRow, "32"),
            DownloadsDays: Int(userRow, "512"));
    }
}
