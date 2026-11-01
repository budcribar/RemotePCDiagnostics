using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>
/// #24: this account's default printer, read from the registry by the Host.
/// </summary>
/// <param name="CurrentName">The default printer's name (from <c>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Device</c> = "name,winspool,port"); null = none set / couldn't read.</param>
/// <param name="CurrentPort">Its port from <c>HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers\&lt;name&gt;\Port</c>; null for shared (\\server\printer) connections or when unreadable.</param>
/// <param name="LegacyDefaultPrinterMode">HKCU <c>LegacyDefaultPrinterMode</c>: 1 = the user picks the default; 0 or absent = "Let Windows manage my default printer" (Windows keeps switching it to the last one used).</param>
/// <param name="HasPrintToPdf">"Microsoft Print to PDF" is installed.</param>
public sealed record DefaultPrinterInfo(string? CurrentName, string? CurrentPort, int? LegacyDefaultPrinterMode, bool HasPrintToPdf)
{
    /// <summary>The default printer is reached over the network (WSD, a TCP/IP port, or a \\server\printer connection).</summary>
    public bool CurrentIsNetwork => CurrentName is not null && (DefaultPrinter.IsConnectionName(CurrentName) || DefaultPrinter.IsNetworkPort(CurrentPort));

    /// <summary>Offer only when the default is a network printer, it isn't already Print to PDF, and Print to PDF exists.</summary>
    public bool Offer => CurrentIsNetwork && HasPrintToPdf && !DefaultPrinter.IsPdf(CurrentName);

    /// <summary>Windows is managing the default printer (LegacyDefaultPrinterMode 0 or absent).</summary>
    public bool WindowsManages => LegacyDefaultPrinterMode is null or 0;
}

/// <summary>Rules for #24 "Make Microsoft Print to PDF the default printer" (opt-in).</summary>
public static class DefaultPrinter
{
    /// <summary>The only printer this app ever makes the default.</summary>
    public const string PdfPrinter = "Microsoft Print to PDF";

    /// <summary>Journal target of the <see cref="RemotePCDiagnostics.Core.Changes.ChangeKind.DefaultPrinter"/> record (one per account; Previous = the old printer's name).</summary>
    public const string JournalTarget = "HKCU|DefaultPrinter";

    /// <summary>HKCU key holding <c>Device</c> and <c>LegacyDefaultPrinterMode</c>.</summary>
    public const string WindowsKey = @"Software\Microsoft\Windows NT\CurrentVersion\Windows";

    /// <summary>HKLM key with one subkey per installed printer.</summary>
    public const string PrintersKey = @"SYSTEM\CurrentControlSet\Control\Print\Printers";

    /// <summary>HKCU key with one subkey per shared-printer connection (",,server,printer").</summary>
    public const string ConnectionsKey = @"Printers\Connections";

    public static bool IsPdf(string? name) => string.Equals(name?.Trim(), PdfPrinter, StringComparison.OrdinalIgnoreCase);

    /// <summary>"HP LaserJet,winspool,Ne01:" → "HP LaserJet". Null when empty or malformed.</summary>
    public static string? ParseDevice(string? device)
    {
        if (string.IsNullOrWhiteSpace(device)) return null;
        var comma = device.IndexOf(',');
        var name = (comma < 0 ? device : device[..comma]).Trim();
        return name.Length == 0 ? null : name;
    }

    /// <summary>WSD-…, IP_10.0.0.5 (Standard TCP/IP port) or a \\server\share port.</summary>
    public static bool IsNetworkPort(string? port) =>
        port is not null && (port.StartsWith("WSD", StringComparison.OrdinalIgnoreCase) || port.StartsWith("IP_", StringComparison.OrdinalIgnoreCase)
            || port.StartsWith(@"\\", StringComparison.Ordinal));

    private static readonly Regex Connection = new(@"^\\\\[^\\,""]+\\[^\\,""]+$", RegexOptions.CultureInvariant);

    /// <summary>A shared printer connection: "\\server\printer".</summary>
    public static bool IsConnectionName(string? name) => name is not null && Connection.IsMatch(name);

    /// <summary>
    /// A printer name this app may hand to SetDefaultPrinter when undoing: 1–220 characters, no commas, quotes or control characters,
    /// and either no backslash at all (a local printer) or exactly the "\\server\printer" form. Anything else read back from the journal is refused.
    /// </summary>
    public static bool IsSafeName(string? name) =>
        name is { Length: > 0 and <= 220 } && name.Trim() == name
        && !name.Any(c => char.IsControl(c) || c is ',' or '"')
        && (!name.Contains('\\') || IsConnectionName(name));

    /// <summary>"\\server\printer" → ",,server,printer" (its subkey under HKCU\Printers\Connections).</summary>
    public static string ConnectionKeyName(string name) => name.Replace('\\', ',');

    /// <summary>
    /// Puts the journaled default printer back (only names that pass <see cref="IsSafeName"/> and are still installed), then reads it back.
    /// Refuses any other journal target. May throw.
    /// </summary>
    public static (bool Ok, string Message) Restore(IMemorySystem sys, string target, string? previous)
    {
        if (!string.Equals(target, JournalTarget, StringComparison.OrdinalIgnoreCase)) return (false, "That isn't a printer setting this app changes, so it was left as is.");
        if (!IsSafeName(previous)) return (false, "The previous default printer wasn't recorded.");
        if (!sys.PrinterExists(previous!))
            return (false, $"The previous default printer, \"{previous}\", is no longer installed, so the default stays {PdfPrinter}. Pick a printer in Settings > Bluetooth & devices > Printers & scanners.");
        var r = sys.SetDefaultPrinter(previous!);
        if (!r.Success) return (false, r.Message);
        return string.Equals(sys.ReadDefaultPrinter()?.CurrentName, previous, StringComparison.OrdinalIgnoreCase)
            ? (true, $"\"{previous}\" is the default printer again.")
            : (false, $"Windows didn't keep \"{previous}\" as the default printer.");
    }
}
