using System.Globalization;

namespace RemotePCDiagnostics.Core.Security;

/// <summary>One security setting this app can turn on (and put back). All text is end-user friendly.</summary>
/// <param name="Key">Stable id: the <see cref="Areas.AreaAction.Target"/> of the fix and the change journal's target. Never rename.</param>
/// <param name="DefaultOn">Ticked by default in the fix list; false for a fix that can get in the way (guest logons and old NAS drives).</param>
public sealed record SecurityFix(string Key, string Label, string ButtonText, string WhatItIs, string WhatHappens, string? Caveat, string Done, string UndoDone, bool DefaultOn = true);

/// <summary>
/// The fixed set of security settings the Security essentials check offers to change, with the PowerShell that reads, applies and
/// restores each one. Scripts are built only from constants here; a journaled previous value is parsed and validated before it is used,
/// so nothing read back from the journal file reaches PowerShell as text.
/// </summary>
public static class SecurityFixes
{
    public const string Pua = "pua", NetworkProtection = "network-protection", AsrRules = "asr", Llmnr = "llmnr", AutoRun = "autorun", GuestLogons = "guest-logons";

    /// <summary>Attack Surface Reduction rules that rarely get in a home user's way (the ones Microsoft suggests starting with).</summary>
    public static readonly IReadOnlyList<(string Id, string Name)> SafeAsrRules =
    [
        ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block password theft from the Windows sign-in process (LSASS)"),
        ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of vulnerable signed drivers"),
        ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block scripts that hide what they do (obfuscated)"),
        ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block Office apps from starting other programs"),
        ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block programs in email attachments and webmail"),
    ];

    public const string LlmnrKey = @"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    public const string LlmnrValue = "EnableMulticast";
    public const string AutoRunKey = @"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    public const string AutoRunValue = "NoDriveTypeAutoRun";
    /// <summary>0xFF: AutoRun off on every kind of drive.</summary>
    public const int AutoRunAllDrives = 255;
    /// <summary>Policy "Enable insecure guest logons" (Lanman Workstation): 0 = off.</summary>
    public const string GuestKey = @"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation";
    public const string GuestValue = "AllowInsecureGuestAuth";

    public static readonly IReadOnlyList<SecurityFix> All =
    [
        new(Pua, "Potentially unwanted app blocking", "Turn on PUA blocking",
            "Microsoft Defender can block adware, browser hijackers and junk bundled with free downloads, but this protection is off.",
            "Turns on Defender's potentially unwanted app (PUA) blocking (the Settings toggle under Windows Security > App & browser control > Reputation-based protection).",
            "Some download helpers and toolbars may be blocked; you can allow one in Windows Security > Protection history.",
            "Turned on potentially unwanted app blocking.", "Potentially unwanted app blocking is back to how it was."),
        new(NetworkProtection, "Network protection", "Turn on network protection",
            "Network protection stops every app, not just Edge, from connecting to known phishing and malware sites. It's off.",
            "Turns on Microsoft Defender network protection.",
            "A site Microsoft rates as dangerous is blocked in every browser and app.",
            "Turned on network protection.", "Network protection is back to how it was."),
        new(AsrRules, "Attack Surface Reduction rules", "Turn on 5 protection rules",
            "Attack Surface Reduction rules block the most common ways malware gets in: Office macros starting programs, disguised scripts, email attachments, and password theft. They're off on every Windows PC unless turned on.",
            "Turns on 5 Microsoft Defender rules: " + string.Join("; ", SafeAsrRules.Select(r => r.Name)) + ".",
            "Rarely, an Office add-in or an old script tool is blocked; Windows Security shows a notice when that happens.",
            "Turned on 5 Attack Surface Reduction rules.", "Attack Surface Reduction rules are back to how they were."),
        new(Llmnr, "Local name lookups (LLMNR)", "Turn off LLMNR",
            "LLMNR is an old way of finding PCs by name on a local network. On public Wi-Fi, an attacker can answer these lookups and capture your sign-in details.",
            "Turns off LLMNR with the Windows policy (EnableMulticast = 0). Normal DNS keeps working.",
            null,
            "Turned off LLMNR.", "LLMNR is back to how it was."),
        new(AutoRun, "AutoRun for drives", "Turn off AutoRun",
            "Windows can start a program automatically when a USB stick or disc is inserted, which is a way malware spreads.",
            "Turns off AutoRun on all drives (policy NoDriveTypeAutoRun = 255). You can still open a drive yourself in File Explorer.",
            null,
            "Turned off AutoRun for all drives.", "AutoRun is back to how it was."),
        new(GuestLogons, "Network drive guest logons", "Turn off insecure guest logons",
            "Guest logons let this PC open shared folders without a password. Someone on the same network can pretend to be that shared folder and send this PC harmful files.",
            "Turns off insecure guest logons with the Windows policy (AllowInsecureGuestAuth = 0), so shared folders need a user name and password.",
            "An older network drive (NAS) that only allows guest access stops opening until you set a password on it. Not ticked by default for that reason.",
            "Turned off insecure guest logons.", "Insecure guest logons are back to how they were.", DefaultOn: false),
    ];

    public static SecurityFix? Find(string? key) => All.FirstOrDefault(f => string.Equals(f.Key, key, StringComparison.OrdinalIgnoreCase));

    private static string IdList => string.Join(",", SafeAsrRules.Select(r => $"'{r.Id}'"));

    private static string ReadDword(string key, string value) =>
        $"$v=(Get-ItemProperty -Path '{key}' -Name '{value}' -ErrorAction SilentlyContinue).'{value}';if($null -eq $v){{''}}else{{[int64]$v}}";

    /// <summary>Prints the setting's current value in journal form (see <see cref="ParsePrevious"/>). Read-only.</summary>
    public static string? ReadScript(string key) => Find(key)?.Key switch
    {
        Pua => "$ErrorActionPreference='Stop';[int](Get-MpPreference).PUAProtection",
        NetworkProtection => "$ErrorActionPreference='Stop';[int](Get-MpPreference).EnableNetworkProtection",
        AsrRules => "$ErrorActionPreference='Stop';$p=Get-MpPreference;$m=@{};$ids=@($p.AttackSurfaceReductionRules_Ids);$a=@($p.AttackSurfaceReductionRules_Actions);" +
                    "for($i=0;$i -lt $ids.Count;$i++){if($ids[$i]){$m[$ids[$i].ToLowerInvariant()]=$a[$i]}};" +
                    $"(@({IdList})|ForEach-Object{{if($m.ContainsKey($_)){{$_+'='+[int]$m[$_]}}else{{$_+'='}}}}) -join ';'",
        Llmnr => ReadDword(LlmnrKey, LlmnrValue),
        AutoRun => ReadDword(AutoRunKey, AutoRunValue),
        GuestLogons => ReadDword(GuestKey, GuestValue),
        _ => null,
    };

    /// <summary>Changes the setting, then reads it back: exits 0 only when Windows kept the new value (Tamper Protection or an
    /// organization's policy can silently refuse a Defender change).</summary>
    public static string? ApplyScript(string key) => Find(key)?.Key switch
    {
        Pua => "$ErrorActionPreference='Stop';Set-MpPreference -PUAProtection 1;if([int](Get-MpPreference).PUAProtection -ne 1){exit 3}",
        NetworkProtection => "$ErrorActionPreference='Stop';Set-MpPreference -EnableNetworkProtection 1;if([int](Get-MpPreference).EnableNetworkProtection -ne 1){exit 3}",
        AsrRules => $"$ErrorActionPreference='Stop';$r=@({IdList});Add-MpPreference -AttackSurfaceReductionRules_Ids $r -AttackSurfaceReductionRules_Actions ($r|ForEach-Object{{'Enabled'}});" +
                    "$p=Get-MpPreference;$ids=@($p.AttackSurfaceReductionRules_Ids|ForEach-Object{$_.ToLowerInvariant()});foreach($x in $r){if($ids -notcontains $x){exit 3}}",
        Llmnr => WriteDword(LlmnrKey, LlmnrValue, 0),
        AutoRun => WriteDword(AutoRunKey, AutoRunValue, AutoRunAllDrives),
        GuestLogons => WriteDword(GuestKey, GuestValue, 0),
        _ => null,
    };

    private static string WriteDword(string key, string value, long data) =>
        $"$ErrorActionPreference='Stop';if(-not(Test-Path '{key}')){{New-Item -Path '{key}' -Force|Out-Null}};" +
        $"New-ItemProperty -Path '{key}' -Name '{value}' -PropertyType DWord -Value {data.ToString(CultureInfo.InvariantCulture)} -Force|Out-Null";

    private static string RestoreDword(string key, string value, long? data) => data is { } d
        ? WriteDword(key, value, d)
        : $"$ErrorActionPreference='Stop';Remove-ItemProperty -Path '{key}' -Name '{value}' -ErrorAction SilentlyContinue";

    /// <summary>A journaled previous value: one number ("2"), "" (the registry value didn't exist), or for ASR "guid=action;guid=" (empty = rule not set).</summary>
    public sealed record Previous(long? Value, IReadOnlyList<(string Id, int? Action)> Rules);

    /// <summary>Validates a journaled value for <paramref name="key"/>; null when it isn't one this app wrote.</summary>
    public static Previous? ParsePrevious(string key, string? text)
    {
        text = (text ?? "").Trim();
        switch (Find(key)?.Key)
        {
            case Pua or NetworkProtection:
                return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n is >= 0 and <= 6 ? new(n, []) : null;
            case Llmnr or AutoRun or GuestLogons:
                if (text.Length == 0) return new(null, []);
                return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) && d is >= 0 and <= uint.MaxValue ? new(d, []) : null;
            case AsrRules:
                var rules = new List<(string, int?)>();
                foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var eq = part.IndexOf('=');
                    if (eq <= 0) return null;
                    var id = part[..eq].ToLowerInvariant();
                    if (!SafeAsrRules.Any(r => r.Id == id)) return null;
                    var a = part[(eq + 1)..];
                    if (a.Length == 0) rules.Add((id, null));
                    else if (int.TryParse(a, NumberStyles.Integer, CultureInfo.InvariantCulture, out var act) && act is >= 0 and <= 6) rules.Add((id, act));
                    else return null;
                }
                return rules.Count > 0 ? new(null, rules) : null;
            default:
                return null;
        }
    }

    /// <summary>Puts the setting back to the journaled value; null when the key or value isn't valid (nothing is run).</summary>
    public static string? RestoreScript(string key, string? previous)
    {
        if (ParsePrevious(key, previous) is not { } p) return null;
        return Find(key)!.Key switch
        {
            Pua => $"$ErrorActionPreference='Stop';Set-MpPreference -PUAProtection {p.Value!.Value.ToString(CultureInfo.InvariantCulture)}",
            NetworkProtection => $"$ErrorActionPreference='Stop';Set-MpPreference -EnableNetworkProtection {p.Value!.Value.ToString(CultureInfo.InvariantCulture)}",
            Llmnr => RestoreDword(LlmnrKey, LlmnrValue, p.Value),
            AutoRun => RestoreDword(AutoRunKey, AutoRunValue, p.Value),
            GuestLogons => RestoreDword(GuestKey, GuestValue, p.Value),
            AsrRules => "$ErrorActionPreference='Stop';" + string.Concat(p.Rules.Select(r => r.Action is { } a
                ? $"Add-MpPreference -AttackSurfaceReductionRules_Ids '{r.Id}' -AttackSurfaceReductionRules_Actions {a.ToString(CultureInfo.InvariantCulture)};"
                : $"Remove-MpPreference -AttackSurfaceReductionRules_Ids '{r.Id}';")),
            _ => null,
        };
    }
}
