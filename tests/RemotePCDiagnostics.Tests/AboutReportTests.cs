using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class AboutReportTests
{
    private const string Secret = "rpd_live_SECRET";
    private const string AgentId = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    [Fact]
    public void Schema_keeps_every_key_and_uses_null_when_the_fact_is_unknown()
    {
        using var doc = JsonDocument.Parse(AboutReport.ToJson(new AboutReportInput()));
        var root = doc.RootElement;

        Assert.Equal(1, root.GetProperty("schema").GetInt32());
        Assert.Equal(2, BrowserContract.About);
        Assert.Equal("about", AboutReport.NavigationTarget);
        Assert.Equal("stable", root.GetProperty("channel").GetString());
        Assert.Equal("local", root.GetProperty("mode").GetString());
        Assert.False(root.GetProperty("agentConnected").GetBoolean());
        foreach (var name in new[]
        {
            "appVersion", "informationalVersion", "build", "agentVersion", "agentServiceStatus",
            "machineName", "osVersion", "installPath", "lastUpdateCheck", "lastUpdateResult",
        })
            Assert.Equal(JsonValueKind.Null, root.GetProperty(name).ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("architecture").GetProperty("process").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("architecture").GetProperty("os").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("shop").GetProperty("group").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("shop").GetProperty("name").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("shop").GetProperty("agentId").ValueKind);
        Assert.False(root.TryGetProperty("key", out _));
        Assert.False(root.TryGetProperty("server", out _));
    }

    [Theory]
    [InlineData("1.2.0-ci.12.1+abc", "prerelease")]
    [InlineData("1.2.0-local+abc", "stable")]
    [InlineData("1.2.0+abc", "stable")]
    public void Channel_follows_the_informational_version(string version, string channel)
    {
        using var doc = JsonDocument.Parse(AboutReport.ToJson(new AboutReportInput
        {
            AppVersion = "1.2.0",
            InformationalVersion = version,
            ProcessArchitecture = "X64",
            OsArchitecture = "Arm64",
            SessionMode = SessionMode.Remote,
        }));
        var root = doc.RootElement;

        Assert.Equal("1.2.0", root.GetProperty("appVersion").GetString());
        Assert.Equal(version, root.GetProperty("informationalVersion").GetString());
        Assert.Equal(version, root.GetProperty("build").GetString());
        Assert.Equal(channel, root.GetProperty("channel").GetString());
        Assert.Equal("X64", root.GetProperty("architecture").GetProperty("process").GetString());
        Assert.Equal("Arm64", root.GetProperty("architecture").GetProperty("os").GetString());
        Assert.Equal("agent", root.GetProperty("mode").GetString());
    }

    [Fact]
    public void Enrollment_file_contributes_the_agent_id_and_group_and_not_the_key()
    {
        var raw = $$"""
            {"machineId":"{{AgentId}}","key":"{{Secret}}","server":"https://relay.example/secret","group":"TestShop"}
            """;
        var facts = AboutMachineFacts.ReadEnrollment(raw);

        Assert.Equal(AgentId, facts.AgentId);
        Assert.Equal("testshop", facts.ShopGroup);
        Assert.Null(facts.AgentVersion);
        Assert.DoesNotContain(Secret, facts.AgentId, StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, facts.ShopGroup, StringComparison.Ordinal);

        var at = DateTimeOffset.Parse("2026-11-21T02:00:00Z");
        using var doc = JsonDocument.Parse(AboutReport.ToJson(new AboutReportInput
        {
            AgentId = facts.AgentId,
            ShopGroup = AboutReport.FirstShopGroup(null, "saved-shop", facts.ShopGroup),
            ShopName = "Northwind",
            AgentVersion = "1.2.0",
            AgentServiceStatus = "Running",
            AgentConnected = true,
            MachineName = "BENCH",
            OsVersion = "Microsoft Windows 10.0.26100",
            InstallPath = @"C:\Program Files\RemotePCDiagnostics\",
            UserName = "Alice",
            UserProfile = @"C:\Users\Alice",
            LastUpdateCheck = at,
            UpdateAvailable = false,
            LatestVersion = "1.2.0",
        }));
        var root = doc.RootElement;
        var json = root.GetRawText();

        Assert.Equal("saved-shop", root.GetProperty("shop").GetProperty("group").GetString());
        Assert.Equal("Northwind", root.GetProperty("shop").GetProperty("name").GetString());
        Assert.Equal(AgentId, root.GetProperty("shop").GetProperty("agentId").GetString());
        Assert.Equal("Running", root.GetProperty("agentServiceStatus").GetString());
        Assert.True(root.GetProperty("agentConnected").GetBoolean());
        Assert.Equal(@"C:\Program Files\RemotePCDiagnostics", root.GetProperty("installPath").GetString());
        Assert.Equal(at.ToUniversalTime().ToString("O"), root.GetProperty("lastUpdateCheck").GetString());
        Assert.False(root.GetProperty("lastUpdateResult").GetProperty("updateAvailable").GetBoolean());
        Assert.Equal("1.2.0", root.GetProperty("lastUpdateResult").GetProperty("latestVersion").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("lastUpdateResult").GetProperty("error").ValueKind);
        Assert.DoesNotContain(Secret, json, StringComparison.Ordinal);
        Assert.DoesNotContain("relay.example", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Alice", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Profile_and_home_folders_are_masked_and_secrets_are_dropped()
    {
        Assert.Equal(@"%USERPROFILE%\AppData\Local\RemotePCDiagnostics",
            AboutReport.MaskInstallPath(@"C:\Users\Alice\AppData\Local\RemotePCDiagnostics", "Alice", @"C:\Users\Alice"));
        Assert.Equal(@"C:\Users\<user>\AppData",
            AboutReport.MaskInstallPath(@"C:\Users\ALICE\AppData", "Alice", userProfile: null));
        Assert.Equal("%USERPROFILE%/app",
            AboutReport.MaskInstallPath("/home/alice/app", "alice", "/home/alice"));
        Assert.Equal("/home/<user>/app",
            AboutReport.MaskInstallPath("/home/alice/app", "alice", userProfile: null));
        Assert.Equal(@"C:\Program Files\RemotePCDiagnostics",
            AboutReport.MaskInstallPath(@"C:\Program Files\RemotePCDiagnostics", "Program", @"C:\Users\Program"));

        using var doc = JsonDocument.Parse(AboutReport.ToJson(new AboutReportInput
        {
            ShopName = Secret,
            AgentId = "not-a-guid",
            AgentServiceStatus = @"Access denied: C:\secret",
            LatestVersion = "https://secret.example/feed",
            UpdateError = "Update check failed.",
            LastUpdateCheck = DateTimeOffset.Parse("2026-11-21T02:00:00Z"),
            InstallPath = @"C:\Users\Alice\RemotePCDiagnostics",
            UserName = "Alice",
            UserProfile = @"C:\Users\Alice",
        }));
        var root = doc.RootElement;

        Assert.Equal(JsonValueKind.Null, root.GetProperty("shop").GetProperty("name").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("shop").GetProperty("agentId").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("agentServiceStatus").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("lastUpdateResult").GetProperty("latestVersion").ValueKind);
        Assert.Equal("Update check failed.", root.GetProperty("lastUpdateResult").GetProperty("error").GetString());
        Assert.Equal(@"%USERPROFILE%\RemotePCDiagnostics", root.GetProperty("installPath").GetString());
        Assert.DoesNotContain(Secret, root.GetRawText(), StringComparison.Ordinal);
        Assert.DoesNotContain("Alice", root.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public void Installed_agent_file_is_read_without_its_key_and_a_bad_status_is_unknown()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpcd-about-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var config = Path.Combine(dir, "agent.json");
            File.WriteAllText(config, $$"""{"machineId":"{{AgentId}}","key":"{{Secret}}","group":"TestShop"}""");
            var missingExe = Path.Combine(dir, "missing.exe");

            var facts = AboutMachineFacts.Read(missingExe, config, () => "Running");
            Assert.Null(facts.AgentVersion);
            Assert.Equal("Running", facts.AgentServiceStatus);
            Assert.Equal(AgentId, facts.AgentId);
            Assert.Equal("testshop", facts.ShopGroup);

            var hidden = AboutMachineFacts.Read(missingExe, config, () => @"C:\Users\Alice\key " + Secret);
            Assert.Null(hidden.AgentServiceStatus);

            var text = Path.Combine(dir, "not-an-exe.txt");
            File.WriteAllText(text, "not a pe file");
            Assert.Null(AboutMachineFacts.Read(text, Path.Combine(dir, "absent.json"), () => "Not installed").AgentVersion);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void About_page_publishes_the_contract_and_does_not_name_secrets()
    {
        var page = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Pages", "AboutPage.razor"));
        var nav = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Shared", "NavRail.razor"));

        Assert.Contains("@page \"/about\"", page, StringComparison.Ordinal);
        Assert.Contains("data-rpcd-page=\"about\"", page, StringComparison.Ordinal);
        Assert.Contains("data-rpcd-contract=\"@BrowserContract.About\"", page, StringComparison.Ordinal);
        Assert.Contains("TestId=\"about-report-data\"", page, StringComparison.Ordinal);
        Assert.Contains("AboutReport.ToJson", page, StringComparison.Ordinal);
        Assert.Contains("data-testid=\"about-title\"", page, StringComparison.Ordinal);
        Assert.DoesNotContain("ShopApiKey", page, StringComparison.Ordinal);
        Assert.DoesNotContain(".Key", page, StringComparison.Ordinal);
        Assert.Contains("data-testid=\"nav-about\"", nav, StringComparison.Ordinal);
        Assert.Contains("href=\"about\"", nav, StringComparison.Ordinal);
        Assert.Equal(2, BrowserContract.Pages["about"]);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "RemotePCDiagnostics.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate repository root containing RemotePCDiagnostics.sln.");
    }
}
