using System.Globalization;
using System.Text;

namespace RemotePCDiagnostics.Core.Display;

/// <summary>
/// What a monitor's EDID (the identity block it sends over the cable) says, parsed in the app. <see cref="Serial"/> is named so the
/// recording scrubber replaces it. <see cref="Problem"/> is set when the block is damaged: a bad header or a checksum that doesn't add up,
/// which usually points at the cable, an adapter or a KVM switch rather than the monitor.
/// </summary>
public sealed record EdidInfo(
    bool HeaderValid,
    bool ChecksumValid,
    int Blocks,
    int Length,
    string? Manufacturer = null,
    int ProductCode = 0,
    string? Serial = null,
    string? Name = null,
    int? WidthCm = null,
    int? HeightCm = null,
    int? Year = null,
    string? Version = null,
    int? PreferredWidth = null,
    int? PreferredHeight = null,
    double? PreferredRefreshHz = null,
    bool? Digital = null)
{
    public bool Valid => HeaderValid && ChecksumValid;

    /// <summary>Plain words for a damaged EDID; null when it is fine.</summary>
    public string? Problem =>
        !HeaderValid ? "The monitor's identity (EDID) is damaged: it doesn't start the way EDID must"
        : !ChecksumValid ? "The monitor's identity (EDID) failed its checksum"
        : null;

    /// <summary>The screen's diagonal in inches, from the size in the EDID; null when the EDID gives none (a projector, say).</summary>
    public double? DiagonalInches => WidthCm is > 0 && HeightCm is > 0
        ? Math.Round(Math.Sqrt(WidthCm.Value * WidthCm.Value + HeightCm.Value * HeightCm.Value) / 2.54, 1) : null;
}

/// <summary>Parses EDID 1.x blocks (VESA E-EDID: a 128-byte base block, then 128-byte extension blocks).</summary>
public static class Edid
{
    private static readonly byte[] Header = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

    public static EdidInfo? Parse(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0) return null;
        if (bytes.Length < 128) return new EdidInfo(false, false, 0, bytes.Length);
        var header = bytes.AsSpan(0, 8).SequenceEqual(Header);
        var blocks = bytes.Length / 128;
        var checksum = true;
        for (var b = 0; b < blocks; b++)
        {
            var sum = 0;
            for (var i = 0; i < 128; i++) sum += bytes[b * 128 + i];
            if ((sum & 0xFF) != 0) { checksum = false; break; }
        }
        if (!header) return new EdidInfo(false, checksum, blocks, bytes.Length);

        string? name = null, serialText = null;
        int? prefW = null, prefH = null;
        double? prefHz = null;
        for (var d = 0; d < 4; d++)
        {
            var at = 54 + d * 18;
            if (bytes[at] != 0 || bytes[at + 1] != 0)
            {
                // A detailed timing; the first one is the monitor's preferred (native) mode.
                if (prefW is null) (prefW, prefH, prefHz) = Timing(bytes, at);
                continue;
            }
            var tag = bytes[at + 3];
            if (tag == 0xFC) name = Text(bytes, at + 5);
            else if (tag == 0xFF) serialText = Text(bytes, at + 5);
        }
        var serialNumber = BitConverter.ToUInt32(bytes, 12);
        var year = bytes[17] > 0 ? 1990 + bytes[17] : (int?)null;
        return new EdidInfo(true, checksum, blocks, bytes.Length,
            Manufacturer: PnpId((ushort)(bytes[8] << 8 | bytes[9])),
            ProductCode: bytes[10] | bytes[11] << 8,
            Serial: serialText ?? (serialNumber is 0 or 0x01010101 ? null : serialNumber.ToString(CultureInfo.InvariantCulture)),
            Name: name,
            WidthCm: bytes[21] > 0 ? bytes[21] : null,
            HeightCm: bytes[22] > 0 ? bytes[22] : null,
            Year: year,
            Version: $"{bytes[18]}.{bytes[19]}",
            PreferredWidth: prefW, PreferredHeight: prefH, PreferredRefreshHz: prefHz,
            Digital: (bytes[20] & 0x80) != 0);
    }

    /// <summary>The three-letter PNP maker code packed into two bytes (big-endian, five bits a letter, 1 = A).</summary>
    public static string? PnpId(ushort packed)
    {
        var a = (packed >> 10) & 31;
        var b = (packed >> 5) & 31;
        var c = packed & 31;
        if (a is < 1 or > 26 || b is < 1 or > 26 || c is < 1 or > 26) return null;
        return new string([(char)('A' + a - 1), (char)('A' + b - 1), (char)('A' + c - 1)]);
    }

    private static (int?, int?, double?) Timing(byte[] e, int at)
    {
        var clock = (e[at] | e[at + 1] << 8) * 10_000L;
        var hActive = e[at + 2] | (e[at + 4] & 0xF0) << 4;
        var hBlank = e[at + 3] | (e[at + 4] & 0x0F) << 8;
        var vActive = e[at + 5] | (e[at + 7] & 0xF0) << 4;
        var vBlank = e[at + 6] | (e[at + 7] & 0x0F) << 8;
        if (hActive == 0 || vActive == 0) return (null, null, null);
        var total = (long)(hActive + hBlank) * (vActive + vBlank);
        double? hz = total > 0 ? Math.Round(clock / (double)total, 2) : null;
        return (hActive, vActive, hz);
    }

    private static string? Text(byte[] e, int at)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < 13; i++)
        {
            var c = e[at + i];
            if (c is 0x0A or 0x00) break;
            if (c is >= 0x20 and < 0x7F) sb.Append((char)c);
        }
        var s = sb.ToString().Trim();
        return s.Length > 0 ? s : null;
    }

    /// <summary>Common monitor and panel makers by PNP code; any other code is shown as it is.</summary>
    private static readonly Dictionary<string, string> Makers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ACR"] = "Acer", ["AOC"] = "AOC", ["APP"] = "Apple", ["AUO"] = "AU Optronics", ["AUS"] = "ASUS", ["BNQ"] = "BenQ", ["BOE"] = "BOE",
        ["CMN"] = "Innolux", ["DEL"] = "Dell", ["ENC"] = "EIZO", ["GBT"] = "Gigabyte", ["GSM"] = "LG", ["HPN"] = "HP", ["HWP"] = "HP",
        ["IVO"] = "InfoVision", ["LEN"] = "Lenovo", ["LGD"] = "LG Display", ["MSI"] = "MSI", ["NEC"] = "NEC", ["PHL"] = "Philips",
        ["SAM"] = "Samsung", ["SDC"] = "Samsung Display", ["SEC"] = "Samsung", ["SHP"] = "Sharp", ["SNY"] = "Sony", ["VSC"] = "ViewSonic",
        ["CSO"] = "CSOT", ["MEI"] = "Panasonic", ["HKC"] = "HKC", ["KTC"] = "KTC", ["XMI"] = "Xiaomi", ["MS_"] = "Microsoft",
    };

    public static string? MakerName(string? pnp) => pnp is null ? null : Makers.TryGetValue(pnp, out var n) ? n : pnp;
}
