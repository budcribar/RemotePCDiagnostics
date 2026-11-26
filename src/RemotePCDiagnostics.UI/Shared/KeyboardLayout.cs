using System.Globalization;
using Microsoft.Win32;
using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.UI.Shared;

internal sealed record KeyboardLayout(string Id, string Name, int Width, IReadOnlyList<KeyboardCap> Caps)
{
    private sealed record KeyLegend(string Code, string Label);
    private static readonly KeyLegend[][] KeyRows =
    [
        [
            new("Escape", "Esc"), new("F1", "F1"), new("F2", "F2"), new("F3", "F3"), new("F4", "F4"),
            new("F5", "F5"), new("F6", "F6"), new("F7", "F7"), new("F8", "F8"),
            new("F9", "F9"), new("F10", "F10"), new("F11", "F11"), new("F12", "F12"), new("Delete", "Del"),
        ],
        [
            new("Backquote", "`"), new("Digit1", "1"), new("Digit2", "2"), new("Digit3", "3"), new("Digit4", "4"),
            new("Digit5", "5"), new("Digit6", "6"), new("Digit7", "7"), new("Digit8", "8"), new("Digit9", "9"),
            new("Digit0", "0"), new("Minus", "-"), new("Equal", "="), new("Backspace", "Bksp"),
        ],
        [
            new("Tab", "Tab"), new("KeyQ", "Q"), new("KeyW", "W"), new("KeyE", "E"), new("KeyR", "R"),
            new("KeyT", "T"), new("KeyY", "Y"), new("KeyU", "U"), new("KeyI", "I"), new("KeyO", "O"),
            new("KeyP", "P"), new("BracketLeft", "["), new("BracketRight", "]"), new("Backslash", "\\"),
        ],
        [
            new("CapsLock", "Caps"), new("KeyA", "A"), new("KeyS", "S"), new("KeyD", "D"), new("KeyF", "F"),
            new("KeyG", "G"), new("KeyH", "H"), new("KeyJ", "J"), new("KeyK", "K"), new("KeyL", "L"),
            new("Semicolon", ";"), new("Quote", "'"), new("Enter", "Enter"),
        ],
        [
            new("ShiftLeft", "Shift"), new("KeyZ", "Z"), new("KeyX", "X"), new("KeyC", "C"), new("KeyV", "V"),
            new("KeyB", "B"), new("KeyN", "N"), new("KeyM", "M"), new("Comma", ","), new("Period", "."),
            new("Slash", "/"), new("ShiftRight", "RShift"),
        ],
        [
            new("ControlLeft", "Ctrl"), new("MetaLeft", "Win"), new("AltLeft", "Alt"),
            new("Space", "Space"),
            new("AltRight", "RAlt"), new("ControlRight", "RCtrl"),
            new("ArrowLeft", "←"), new("ArrowUp", "↑"), new("ArrowDown", "↓"), new("ArrowRight", "→"),
        ],
    ];

    private static readonly (string Manufacturer, string ModelPattern, bool Numpad)[] ModelRules =
    [
        // Lenovo PSREF
        ("Lenovo", @"(?:15ALC7|82R4[A-Z0-9]*|15IAN8|15AMN8|15ABR8|15IRH8|15IRU9|15IRX9|16AHP11|16IAH10|16ABR8)", true),
        // Dell owner manuals. The product line is needed to distinguish similar model numbers.
        ("Dell", @"(?:DC15250|Inspiron 15 3530|(?:Inspiron|Latitude) 3530|Latitude (?:5520|5530|5540))", true),
        ("Dell", @"Latitude (?:5420|5440)", false),
        // HP maintenance and service guides. Match the documented chassis series.
        ("HP", @"(?:15-fd[012]|15-fc1|15-fr0|17-cn5|17-d[kmnp]0|16-c[bc]0)[A-Z0-9]*", true),
        ("HP", @"(?:15-eg3|15-f[ab][123])[A-Z0-9]*", true),
        ("HP", @"ProBook 450(?: 15\.6 inch)? G10", true),
        // ASUS tech specs and e-manuals. X1404's optional touchpad NumberPad is not a key cluster.
        ("ASUS", @"(?:X1504|X1605|M1502)[A-Z0-9]*", true),
        ("ASUS", @"X1404[A-Z0-9]*", false),
        // Acer Aspire 3 user manual
        ("Acer", @"A315-24P", true),
    ];

    internal static IReadOnlyList<KeyboardLayout> GetCandidates()
    {
        var (language, manufacturer, model, sku) = ReadHostHints();
        return GetCandidates(language, manufacturer, model, sku);
    }

    internal static IReadOnlyList<KeyboardLayout> GetCandidates(
        string language, string manufacturer, string model, string sku)
    {
        var identity = $"{model} {sku}".Replace('_', ' ');
        var withNumpad = false;
        foreach (var rule in ModelRules)
        {
            if ((manufacturer.Contains(rule.Manufacturer, StringComparison.OrdinalIgnoreCase)
                    || (rule.Manufacturer == "HP" && manufacturer.StartsWith("Hewlett-Packard", StringComparison.OrdinalIgnoreCase)))
                && Regex.IsMatch(identity, $@"\b{rule.ModelPattern}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2)))
            {
                withNumpad = rule.Numpad;
                break;
            }
        }

        var preferred = language switch
        {
            "ja-JP" => "jis",
            "en-GB" => "iso-uk",
            "de-DE" => "iso-de",
            "fr-FR" => "iso-fr",
            _ => "ansi",
        };

        if (manufacturer.Contains("Lenovo", StringComparison.OrdinalIgnoreCase))
        {
            if (Regex.IsMatch(identity, @"\b82R4002PUS\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                preferred = "ansi";
            else if (Regex.IsMatch(identity, @"\b82R4010NJP\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                preferred = "jis";
        }

        return new[] { ("ansi", "ANSI US"), ("iso-uk", "ISO UK"), ("iso-de", "ISO German"),
                ("iso-fr", "ISO French"), ("jis", "JIS Japanese") }
            .SelectMany(layout => new[] { false, true }.Select(numpad => (layout, numpad)))
            .OrderByDescending(candidate => candidate.numpad == withNumpad)
            .ThenByDescending(candidate => candidate.layout.Item1 == preferred)
            .Select(candidate => Create(candidate.layout.Item1, candidate.layout.Item2, candidate.numpad))
            .ToArray();
    }

    private static (string Language, string Manufacturer, string Model, string Sku) ReadHostHints()
    {
        var language = CultureInfo.CurrentCulture.Name;
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var bios = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
                var manufacturer = bios?.GetValue("SystemManufacturer") as string ?? "";
                var model = $"{bios?.GetValue("SystemProductName")} {bios?.GetValue("SystemFamily")}";
                var sku = bios?.GetValue("SystemSKU") as string ?? "";
                using var preload = Registry.CurrentUser.OpenSubKey(@"Keyboard Layout\Preload");
                if (preload?.GetValue("1") is string klid
                    && int.TryParse(klid, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var id))
                    language = CultureInfo.GetCultureInfo(id & 0xffff).Name;
                return (language, manufacturer, model, sku);
            }
            catch (Exception error) when (error is ArgumentException or UnauthorizedAccessException
                or System.Security.SecurityException or System.IO.IOException) { }
        }

        return (language, "", "", "");
    }

    private static KeyboardLayout Create(string id, string name, bool numpad)
    {
        var caps = new List<KeyboardCap>();
        var iso = id.StartsWith("iso-", StringComparison.Ordinal);
        var jis = id == "jis";
        for (var rowIndex = 0; rowIndex < KeyRows.Length; rowIndex++)
        {
            var row = KeyRows[rowIndex].ToList();
            if (iso && rowIndex == 2)
                row.RemoveAt(row.Count - 1);
            if (iso && rowIndex == 3)
            {
                row.RemoveAt(row.Count - 1);
                row.Add(new("Backslash", "#"));
            }
            if (iso && rowIndex == 4)
                row.Insert(1, new("IntlBackslash", "\\"));
            if (jis && rowIndex == 1)
            {
                row.RemoveAt(0);
                row.Insert(0, new("Backquote", "半角"));
                row.Insert(row.Count - 1, new("IntlYen", "¥"));
            }
            if (jis && rowIndex == 4)
                row.Insert(row.Count - 1, new("IntlRo", "\\"));
            if (jis && rowIndex == 5)
            {
                row.Insert(3, new("NonConvert", "無変換"));
                row.Insert(5, new("Convert", "変換"));
                row.Insert(6, new("KanaMode", "かな"));
            }

            var x = 2;
            var y = rowIndex * 42 + 2;
            foreach (var key in row)
            {
                var width = KeyWidth(key, rowIndex, iso, jis);
                caps.Add(Key(key.Code, Legend(id, key), x, y, width));
                x += width;
            }
        }

        if (iso)
        {
            const int x = 554;
            const int y = 86;
            caps.Add(new("Enter", "Enter", x, y, 76,
                "M554 86 H630 V166 H568 V124 H554 Z"));
        }

        if (numpad)
        {
            string[][] codes =
            [
                ["NumLock", "NumpadDivide", "NumpadMultiply", "NumpadSubtract"],
                ["Numpad7", "Numpad8", "Numpad9", "NumpadAdd"],
                ["Numpad4", "Numpad5", "Numpad6"],
                ["Numpad1", "Numpad2", "Numpad3", "NumpadEnter"],
                ["Numpad0", "", "NumpadDecimal"],
            ];
            string[][] labels =
            [
                ["Num", "/", "*", "-"], ["7", "8", "9", "+"], ["4", "5", "6"],
                ["1", "2", "3", "Enter"], ["0", "", "."],
            ];
            for (var row = 0; row < codes.Length; row++)
            for (var col = 0; col < codes[row].Length; col++)
            {
                var code = codes[row][col];
                if (code.Length == 0)
                    continue;
                caps.Add(Key(code, labels[row][col], 650 + col * 42, 44 + row * 42,
                    code == "Numpad0" ? 84 : 42, code is "NumpadAdd" or "NumpadEnter" ? 80 : 38));
            }
        }

        return new(id + (numpad ? "-numpad" : ""), name + (numpad ? " with numpad" : " compact"),
            numpad ? 820 : 640, caps);
    }

    private static int KeyWidth(KeyLegend key, int row, bool iso, bool jis) => key.Code switch
    {
        "Backspace" => jis ? 42 : 84,
        "Tab" => iso ? 48 : 62,
        "CapsLock" => iso ? 62 : 72,
        "ShiftLeft" => iso ? 48 : 82,
        "ShiftRight" => 82,
        "Space" => jis ? 124 : 250,
        "Enter" => 94,
        "Backslash" when row == 2 => 64,
        "IntlBackslash" when iso => 34,
        _ => 42,
    };

    private static KeyboardCap Key(string code, string label, int x, int y, int width, int height = 38) =>
        new(code, label, x, y, width - 4,
            FormattableString.Invariant($"M{x + 5} {y} h{width - 14} q5 0 5 5 v{height - 10} q0 5 -5 5 h-{width - 14} q-5 0 -5 -5 v-{height - 10} q0 -5 5 -5 Z"));

    private static string Legend(string id, KeyLegend key) => (id, key.Code) switch
    {
        ("iso-uk", "Backquote") => "`",
        ("iso-uk", "AltRight") => "AltGr",
        ("iso-de", "KeyY") => "Z", ("iso-de", "KeyZ") => "Y",
        ("iso-de", "Minus") => "ß", ("iso-de", "Equal") => "´",
        ("iso-de", "BracketLeft") => "Ü", ("iso-de", "BracketRight") => "+",
        ("iso-de", "Semicolon") => "Ö", ("iso-de", "Quote") => "Ä",
        ("iso-de", "Backquote") => "^", ("iso-de", "Backslash") => "#",
        ("iso-de", "IntlBackslash") => "<", ("iso-de", "Slash") => "-",
        ("iso-de", "AltRight") => "AltGr",
        ("iso-fr", "KeyQ") => "A", ("iso-fr", "KeyA") => "Q",
        ("iso-fr", "KeyW") => "Z", ("iso-fr", "KeyZ") => "W",
        ("iso-fr", "KeyM") => ",", ("iso-fr", "Semicolon") => "M",
        ("iso-fr", "Digit1") => "&", ("iso-fr", "Digit2") => "é",
        ("iso-fr", "Digit3") => "\"", ("iso-fr", "Digit4") => "'",
        ("iso-fr", "Digit5") => "(", ("iso-fr", "Digit6") => "-",
        ("iso-fr", "Digit7") => "è", ("iso-fr", "Digit8") => "_",
        ("iso-fr", "Digit9") => "ç", ("iso-fr", "Digit0") => "à",
        ("iso-fr", "Backquote") => "²", ("iso-fr", "Minus") => ")",
        ("iso-fr", "BracketLeft") => "^", ("iso-fr", "BracketRight") => "$",
        ("iso-fr", "Quote") => "ù", ("iso-fr", "Backslash") => "*",
        ("iso-fr", "IntlBackslash") => "<", ("iso-fr", "Comma") => ";",
        ("iso-fr", "Period") => ":", ("iso-fr", "Slash") => "!",
        ("iso-fr", "AltRight") => "AltGr",
        ("jis", "Equal") => "^", ("jis", "BracketLeft") => "@",
        ("jis", "BracketRight") => "[", ("jis", "Backslash") => "]",
        ("jis", "Quote") => ":",
        _ => key.Label,
    };
}

internal sealed record KeyboardCap(string Code, string Label, int LabelX, int Y, int Width, string Path);
