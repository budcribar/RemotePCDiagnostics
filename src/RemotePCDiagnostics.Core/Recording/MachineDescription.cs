using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>Which PC a recording comes from, and the names its scrubber replaces. Shared by the recorder tool and the app's RPCD_LOG switch.</summary>
public static class MachineDescription
{
    /// <summary>Which PC this is. Read through a source that doesn't record: it describes the recording rather than being part of it.</summary>
    public static async Task<RecordedMachine> DescribeAsync(IWmiSource wmi, string appVersion, bool elevated, CancellationToken ct = default)
    {
        async Task<WmiRow?> One(string sql) => (await wmi.QueryAsync(@"root\cimv2", sql, ct).ConfigureAwait(false)).Rows?.FirstOrDefault();
        var cs = await One("SELECT Manufacturer, Model, SystemSKUNumber, SystemFamily FROM Win32_ComputerSystem").ConfigureAwait(false);
        var product = await One("SELECT UUID, Name, Version FROM Win32_ComputerSystemProduct").ConfigureAwait(false);
        var board = await One("SELECT Product FROM Win32_BaseBoard").ConfigureAwait(false);
        var bios = await One("SELECT SMBIOSBIOSVersion FROM Win32_BIOS").ConfigureAwait(false);
        var os = await One("SELECT Version, BuildNumber FROM Win32_OperatingSystem").ConfigureAwait(false);

        var sku = Clean(cs?.Str("SystemSKUNumber"));
        var boardProduct = Clean(board?.Str("Product"));
        var model = Clean(cs?.Str("Model"));
        return new RecordedMachine
        {
            ProductId = ProductId(Clean(cs?.Str("Manufacturer")), sku, boardProduct, model),
            Manufacturer = Clean(cs?.Str("Manufacturer")),
            Model = model,
            SystemSku = sku,
            SystemFamily = Clean(cs?.Str("SystemFamily")),
            BaseBoardProduct = boardProduct,
            SmbiosUuid = Clean(product?.Str("UUID")),
            BiosVersion = Clean(bios?.Str("SMBIOSBIOSVersion")),
            WindowsVersion = Clean(os?.Str("Version")),
            WindowsBuild = Clean(os?.Str("BuildNumber")),
            AppVersion = appVersion,
            Elevated = elevated,
        };
    }

    /// <summary>
    /// The BIOS identifier that names the hardware platform. HP's is the System Board ID (Win32_BaseBoard.Product, "8CBE" on the OmniBook X 14
    /// and EliteBook Ultra G1q), so its recordings are keyed by maker and board ("HP-8CBE"). Other makers' board names are generic (Lenovo's
    /// "LNVNB161216"), so their SKU is used, which on Lenovo holds the machine type ("LENOVO_MT_82R4_…").
    /// </summary>
    public static string ProductId(string manufacturer, string sku, string boardProduct, string model)
    {
        var hp = manufacturer.Equals("HP", StringComparison.OrdinalIgnoreCase) || manufacturer.StartsWith("Hewlett", StringComparison.OrdinalIgnoreCase);
        if (hp && boardProduct.Length > 0) return "HP-" + boardProduct;
        return sku.Length > 0 ? sku : boardProduct.Length > 0 ? boardProduct : model;
    }

    /// <summary>Firmware placeholders ("To be filled by O.E.M.", "Default string") count as empty.</summary>
    public static string Clean(string? s)
    {
        s = (s ?? "").Trim();
        string[] junk = ["To be filled by O.E.M.", "Default string", "System Product Name", "None", "Not Applicable", "N/A", "0"];
        return junk.Contains(s, StringComparer.OrdinalIgnoreCase) ? "" : s;
    }

    /// <summary>A folder name made of the id's letters, digits, '-' and '_'.</summary>
    public static string Safe(string s)
    {
        var chars = s.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_').ToArray();
        var t = new string(chars).Trim('_');
        return t.Length == 0 ? "unknown" : t;
    }

    /// <summary>The signed-in user and every profile folder's name, so they are replaced wherever they appear.</summary>
    public static IEnumerable<string> UserNames()
    {
        yield return Environment.UserName;
        var users = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\", "Users");
        string[] profiles;
        try { profiles = Directory.GetDirectories(users); } catch { yield break; }
        string[] shared = ["Public", "Default", "Default User", "All Users", "defaultuser0", "WDAGUtilityAccount"];
        foreach (var p in profiles)
        {
            var name = Path.GetFileName(p);
            if (!shared.Contains(name, StringComparer.OrdinalIgnoreCase)) yield return name;
        }
    }
}
