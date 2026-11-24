using System.Runtime.InteropServices;
using System.Text.Json;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Windows Update and the Security fixes run in the Agent as C# (<see cref="AgentWindowsUpdate"/>, <see cref="AgentSecuritySettings"/>)
/// instead of PowerShell: same JSON and exit codes, and Windows' real errors instead of "nothing to do".
/// </summary>
public sealed class AgentNativeUpdatesAndSecurityTests
{
    private sealed class FakeUpdate(string title, bool downloaded = false, bool eula = true) : IFoundUpdate
    {
        public string Title => title;
        public bool EulaAccepted { get; private set; } = eula;
        public void AcceptEula() => EulaAccepted = true;
        public bool IsDownloaded { get; set; } = downloaded;
    }

    private sealed class FakeWua : IWindowsUpdateApi
    {
        public List<FakeUpdate> Updates { get; } = [];
        public List<string> Criteria { get; } = [];
        public Exception? SearchError, DownloadError, InstallError;
        public bool DownloadWorks = true, Scanned;
        public UpdateInstallOutcome Outcome = new(2, 0, false);
        public List<IReadOnlyList<IFoundUpdate>> Installed { get; } = [];

        public IReadOnlyList<IFoundUpdate> Search(string criteria) { Criteria.Add(criteria); if (SearchError is not null) throw SearchError; return Updates; }
        public int Download(IReadOnlyList<IFoundUpdate> updates)
        {
            if (DownloadError is not null) throw DownloadError;
            if (DownloadWorks) foreach (FakeUpdate u in updates) u.IsDownloaded = true;
            return DownloadWorks ? 2 : 4;
        }
        public UpdateInstallOutcome Install(IReadOnlyList<IFoundUpdate> updates) { if (InstallError is not null) throw InstallError; Installed.Add(updates); return Outcome; }
        public void StartInteractiveScan() => Scanned = true;
    }

    private static JsonElement Json(string s) => JsonDocument.Parse(s).RootElement;

    [Fact]
    public void Windows_update_installs_every_pending_update_and_names_them()
    {
        var wua = new FakeWua { Outcome = new(2, 0, true) };
        wua.Updates.AddRange([new FakeUpdate("Intel - Display", eula: false), new FakeUpdate("Realtek - Audio")]);
        var r = AgentWindowsUpdate.InstallAll(wua, driversOnly: true);

        Assert.Equal(0, r.ExitCode);
        Assert.Equal(["IsInstalled=0 and Type='Driver'"], wua.Criteria);
        Assert.All(wua.Updates, u => Assert.True(u.EulaAccepted));
        var j = Json(r.StdOut);
        Assert.Equal(2, j.GetProperty("Count").GetInt32());
        Assert.Equal(2, j.GetProperty("Installed").GetInt32());
        Assert.Equal(2, j.GetProperty("InstallResult").GetInt32());
        Assert.True(j.GetProperty("RebootRequired").GetBoolean());
        Assert.Equal(["Intel - Display", "Realtek - Audio"], j.GetProperty("Titles").EnumerateArray().Select(t => t.GetString()));
    }

    [Fact]
    public void Nothing_pending_is_up_to_date()
    {
        var wua = new FakeWua();
        var r = AgentWindowsUpdate.InstallAll(wua, driversOnly: false);
        Assert.Equal(0, r.ExitCode);
        Assert.Equal(["IsInstalled=0 and Type='Software'"], wua.Criteria);
        Assert.Equal(0, Json(r.StdOut).GetProperty("Count").GetInt32());
        Assert.Empty(wua.Installed);
        Assert.False(wua.Scanned);
    }

    [Fact]
    public void A_search_that_fails_is_an_error_not_up_to_date()
    {
        // The script ran with SilentlyContinue and printed Count = 0, which the app showed as "Windows is up to date".
        var wua = new FakeWua { SearchError = new COMException("Exception from HRESULT: 0x8024402C", unchecked((int)0x8024402C)) };
        var r = AgentWindowsUpdate.InstallAll(wua, driversOnly: false);
        Assert.Equal(1, r.ExitCode);
        Assert.Contains("0x8024402C", r.StdErr);
        Assert.Equal("", r.StdOut);
    }

    [Fact]
    public void Nothing_downloaded_asks_windows_to_scan()
    {
        var wua = new FakeWua { DownloadWorks = false };
        wua.Updates.Add(new FakeUpdate("Cumulative Update"));
        var j = Json(AgentWindowsUpdate.InstallAll(wua, driversOnly: false).StdOut);
        Assert.True(wua.Scanned);
        Assert.Empty(wua.Installed);
        Assert.Equal(-1, j.GetProperty("InstallResult").GetInt32());
        Assert.Equal(0, j.GetProperty("Installed").GetInt32());
    }

    [Fact]
    public void Only_downloaded_updates_are_installed_and_a_failed_install_says_why()
    {
        var wua = new FakeWua { DownloadError = new COMException("Download failed", unchecked((int)0x80240022)) };
        wua.Updates.AddRange([new FakeUpdate("A", downloaded: true), new FakeUpdate("B")]);
        wua.Outcome = new(4, unchecked((int)0x80070643), false);
        var j = Json(AgentWindowsUpdate.InstallAll(wua, driversOnly: false).StdOut);
        Assert.Equal(["A"], wua.Installed.Single().Select(u => u.Title));
        Assert.Equal(4, j.GetProperty("InstallResult").GetInt32());
        Assert.Equal(0, j.GetProperty("Installed").GetInt32());
        Assert.Contains("0x80240022", j.GetProperty("Error").GetString());

        wua.DownloadError = null;
        wua.InstallError = new COMException("Install failed", unchecked((int)0x80240016));
        j = Json(AgentWindowsUpdate.InstallAll(wua, driversOnly: false).StdOut);
        Assert.Equal(4, j.GetProperty("InstallResult").GetInt32());
        Assert.Contains("0x80240016", j.GetProperty("Error").GetString());
    }

    [Fact]
    public void Install_one_update_reads_like_the_script_did()
    {
        var id = Guid.Parse("748279c7-4309-452c-8b30-e02ec52e498f");
        var wua = new FakeWua { Outcome = new(2, 0, true) };
        wua.Updates.Add(new FakeUpdate("2026-11 Cumulative Update", eula: false));
        var r = AgentWindowsUpdate.InstallOne(wua, id);

        Assert.Equal(0, r.ExitCode);
        Assert.Equal(["IsInstalled=0 and UpdateID='748279c7-4309-452c-8b30-e02ec52e498f'"], wua.Criteria);
        var j = Json(r.StdOut);
        Assert.True(j.GetProperty("Found").GetBoolean());
        Assert.Equal(2, j.GetProperty("DownloadResult").GetInt32());
        var result = RemediationService.ParseInstallUpdate(r.StdOut, "the update");
        Assert.True(result.Success);
        Assert.Equal("Installed 2026-11 Cumulative Update. Restart the PC to finish.", result.Message);
    }

    [Fact]
    public void Install_one_update_reports_windows_errors_and_missing_updates()
    {
        var id = Guid.NewGuid();
        var gone = RemediationService.ParseInstallUpdate(AgentWindowsUpdate.InstallOne(new FakeWua(), id).StdOut, "KB1");
        Assert.False(gone.Success);
        Assert.Contains("no longer offers", gone.Message);

        var wua = new FakeWua { SearchError = new COMException("The service is not running", unchecked((int)0x8024A000)) };
        var r = AgentWindowsUpdate.InstallOne(wua, id);
        Assert.Equal(0, r.ExitCode);
        var failed = RemediationService.ParseInstallUpdate(r.StdOut, "KB1");
        Assert.False(failed.Success);
        Assert.Contains("0x8024A000", failed.Message);

        var refused = new FakeWua { Outcome = new(4, unchecked((int)0x80070643), false) };
        refused.Updates.Add(new FakeUpdate("KB2", downloaded: true));
        var msg = RemediationService.ParseInstallUpdate(AgentWindowsUpdate.InstallOne(refused, id).StdOut, "KB2").Message;
        Assert.Contains("0x80070643", msg);
    }

    private sealed class FakeSecurity : ISecuritySettingsStore
    {
        public int Pua, Network;
        public int Cloud;
        public bool IgnoreDefenderChanges;
        public Dictionary<string, int> Asr { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, long> Registry { get; } = [];
        public List<string> Calls { get; } = [];

        public DefenderPreferences ReadDefender() => new(Pua, Network, [.. Asr.Keys], [.. Asr.Values], Cloud);
        public void SetDefender(string name, int value)
        {
            Calls.Add($"Set {name}={value}");
            if (IgnoreDefenderChanges) return;
            if (name == "PUAProtection") Pua = value;
            else if (name == "EnableNetworkProtection") Network = value;
            else if (name == "MAPSReporting") Cloud = value;
            else throw new InvalidOperationException(name);
        }
        public void AddAsrRules(IReadOnlyList<string> ids, IReadOnlyList<int> actions)
        {
            Calls.Add($"Add {string.Join(',', ids)}={string.Join(',', actions)}");
            if (!IgnoreDefenderChanges) for (var i = 0; i < ids.Count; i++) Asr[ids[i]] = actions[i];
        }
        public void RemoveAsrRules(IReadOnlyList<string> ids) { Calls.Add($"Remove {string.Join(',', ids)}"); foreach (var id in ids) Asr.Remove(id); }
        public long? ReadDword(string key, string name) => Registry.TryGetValue(key + "\\" + name, out var v) ? v : null;
        public void WriteDword(string key, string name, long value) { Calls.Add($"Write {key}\\{name}={value}"); Registry[key + "\\" + name] = value; }
        public void DeleteValue(string key, string name) { Calls.Add($"Delete {key}\\{name}"); Registry.Remove(key + "\\" + name); }
    }

    private const string Llmnr = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast";

    [Fact]
    public void Policy_fixes_read_write_and_restore_the_registry()
    {
        var s = new FakeSecurity();
        Assert.Equal("", AgentSecuritySettings.Read(s, SecurityFixes.Llmnr).StdOut);   // not set: journaled as ""
        Assert.Equal(0, AgentSecuritySettings.Apply(s, SecurityFixes.Llmnr).ExitCode);
        Assert.Equal("0", AgentSecuritySettings.Read(s, SecurityFixes.Llmnr).StdOut);
        Assert.Equal(0, AgentSecuritySettings.Restore(s, SecurityFixes.Llmnr, SecurityFixes.ParsePrevious(SecurityFixes.Llmnr, "")!).ExitCode);
        Assert.False(s.Registry.ContainsKey(Llmnr));

        AgentSecuritySettings.Apply(s, SecurityFixes.AutoRun);
        Assert.Equal("255", AgentSecuritySettings.Read(s, SecurityFixes.AutoRun).StdOut);
        AgentSecuritySettings.Restore(s, SecurityFixes.AutoRun, SecurityFixes.ParsePrevious(SecurityFixes.AutoRun, "145")!);
        Assert.Equal("145", AgentSecuritySettings.Read(s, SecurityFixes.AutoRun).StdOut);

        AgentSecuritySettings.Apply(s, SecurityFixes.GuestLogons);
        Assert.Contains(@"Write SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth=0", s.Calls);
    }

    [Fact]
    public void Defender_fixes_exit_3_when_windows_does_not_keep_them()
    {
        var s = new FakeSecurity { Pua = 2, Cloud = 0 };
        Assert.Equal("2", AgentSecuritySettings.Read(s, SecurityFixes.Pua).StdOut);
        Assert.Equal(0, AgentSecuritySettings.Apply(s, SecurityFixes.Pua).ExitCode);
        Assert.Equal(1, s.Pua);
        AgentSecuritySettings.Restore(s, SecurityFixes.Pua, SecurityFixes.ParsePrevious(SecurityFixes.Pua, "2")!);
        Assert.Equal(2, s.Pua);

        Assert.Equal("0", AgentSecuritySettings.Read(s, SecurityFixes.CloudProtection).StdOut);
        Assert.Equal(0, AgentSecuritySettings.Apply(s, SecurityFixes.CloudProtection).ExitCode);
        Assert.Equal(2, s.Cloud);
        AgentSecuritySettings.Restore(s, SecurityFixes.CloudProtection, SecurityFixes.ParsePrevious(SecurityFixes.CloudProtection, "0")!);
        Assert.Equal(0, s.Cloud);

        var tamper = new FakeSecurity { IgnoreDefenderChanges = true };
        Assert.Equal(AgentSecuritySettings.NotKeptExitCode, AgentSecuritySettings.Apply(tamper, SecurityFixes.NetworkProtection).ExitCode);
        Assert.Equal(AgentSecuritySettings.NotKeptExitCode, AgentSecuritySettings.Apply(tamper, SecurityFixes.CloudProtection).ExitCode);
        Assert.Equal(AgentSecuritySettings.NotKeptExitCode, AgentSecuritySettings.Apply(tamper, SecurityFixes.AsrRules).ExitCode);
    }

    [Fact]
    public void Asr_rules_are_journaled_in_order_and_put_back_rule_by_rule()
    {
        var s = new FakeSecurity();
        s.Asr["56A863A9-875E-4185-98A7-B882C64B5CE5"] = 2;
        s.Asr["01443614-cd74-433a-b99e-2ecdc07bfc25"] = 1;   // not one of ours: left out of the journal
        var before = AgentSecuritySettings.Read(s, SecurityFixes.AsrRules).StdOut;
        Assert.Equal("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2=;56a863a9-875e-4185-98a7-b882c64b5ce5=2;5beb7efe-fd9a-4556-801d-275e5ffc04cc=;"
            + "d4f940ab-401b-4efc-aadc-ad5f3c50688a=;be9ba2d9-53ea-4cdc-84e5-9b1eeee46550=", before);
        Assert.NotNull(SecurityFixes.ParsePrevious(SecurityFixes.AsrRules, before));

        Assert.Equal(0, AgentSecuritySettings.Apply(s, SecurityFixes.AsrRules).ExitCode);
        Assert.All(SecurityFixes.SafeAsrRules, r => Assert.Equal(1, s.Asr[r.Id]));

        s.Calls.Clear();
        AgentSecuritySettings.Restore(s, SecurityFixes.AsrRules, SecurityFixes.ParsePrevious(SecurityFixes.AsrRules, before)!);
        Assert.Equal(2, s.Asr["56a863a9-875e-4185-98a7-b882c64b5ce5"]);
        Assert.False(s.Asr.ContainsKey("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"));
        Assert.Contains("Remove 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", s.Calls);
        Assert.Contains("Add 56a863a9-875e-4185-98a7-b882c64b5ce5=2", s.Calls);
    }

    [Fact]
    public void Windows_errors_come_back_on_stderr_with_exit_1()
    {
        var r = AgentSecuritySettings.Run(new ThrowingSecurity(), new SecurityApplyAction(SecurityFixes.Pua));
        Assert.Equal(1, r.ExitCode);
        Assert.Contains("Defender isn't available", r.StdErr);
        Assert.Equal(1, AgentSecuritySettings.Run(new FakeSecurity(), new SecurityReadAction("firewall")).ExitCode);
    }

    private sealed class ThrowingSecurity : ISecuritySettingsStore
    {
        private static Exception E() => new InvalidOperationException("Defender isn't available");
        public DefenderPreferences ReadDefender() => throw E();
        public void SetDefender(string name, int value) => throw E();
        public void AddAsrRules(IReadOnlyList<string> ids, IReadOnlyList<int> actions) => throw E();
        public void RemoveAsrRules(IReadOnlyList<string> ids) => throw E();
        public long? ReadDword(string key, string name) => throw E();
        public void WriteDword(string key, string name, long value) => throw E();
        public void DeleteValue(string key, string name) => throw E();
    }
}
