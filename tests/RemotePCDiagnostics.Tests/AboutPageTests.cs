using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Preferences;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests;

public class AboutPageTests : BunitContext
{
    private const string Secret = "rpd_live_SECRET";

    [Fact]
    public void About_page_renders_the_contract_and_leaves_secrets_out_of_the_report()
    {
        using var monitor = new AgentModeMonitor(_ => AgentModeSnapshot.LocalOnly, startLoop: false);
        var store = new MemoryPreferencesStore();
        store.Save(new UserPreferences
        {
            ShopApiKey = Secret,
            ShopGroupSlug = "TestShop",
            RelayServerUrl = "https://relay.example/secret",
            Branding = new ShopBranding
            {
                ShopName = "Northwind",
                Email = "owner@example.com",
                Phone = "555-0100",
                Address = "1 Secret Street",
            },
        });
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local, group: "Live-Shop"));
        Services.AddSingleton(new AppServices(Preferences: new PreferencesService(store)));
        Services.AddSingleton(monitor);

        var cut = Render<AboutPage>();

        var root = cut.Find("[data-rpcd-page='about']");
        Assert.Equal("about", root.GetAttribute("data-rpcd-page"));
        Assert.Equal(BrowserContract.About.ToString(), root.GetAttribute("data-rpcd-contract"));
        Assert.Equal("2", root.GetAttribute("data-rpcd-contract"));
        Assert.Contains("About Remote PC Diagnostics", cut.Find("[data-testid='about-title']").TextContent);
        // The commit has its own row, so the build version leaves out the +commit; the data attribute keeps the full string.
        var version = cut.Find("[data-testid='about-version']");
        Assert.Equal(AppVersionComparer.ForDisplay(AppBuildInfo.Version), version.TextContent);
        Assert.DoesNotContain("+", version.TextContent);
        Assert.Equal(AppBuildInfo.Version, version.GetAttribute("data-rpcd-version"));

        var data = cut.Find("[data-testid='about-report-data']");
        Assert.Equal("1", data.GetAttribute("data-schema"));
        using var doc = JsonDocument.Parse(data.GetAttribute("data-report")!);
        var report = doc.RootElement;
        var json = report.GetRawText();

        Assert.Equal(1, report.GetProperty("schema").GetInt32());
        Assert.Equal(AppBuildInfo.Release, report.GetProperty("appVersion").GetString());
        Assert.Equal(AppBuildInfo.Version, report.GetProperty("informationalVersion").GetString());
        Assert.Equal(AppBuildInfo.Version, report.GetProperty("build").GetString());
        Assert.Equal(AboutReport.ChannelFor(AppBuildInfo.Version), report.GetProperty("channel").GetString());
        Assert.Equal("local", report.GetProperty("mode").GetString());
        Assert.False(report.GetProperty("agentConnected").GetBoolean());
        Assert.Equal("live-shop", report.GetProperty("shop").GetProperty("group").GetString());
        Assert.Equal("Northwind", report.GetProperty("shop").GetProperty("name").GetString());
        Assert.Equal(Environment.MachineName, report.GetProperty("machineName").GetString());
        Assert.False(report.GetProperty("architecture").GetProperty("process").ValueKind == JsonValueKind.Null);
        Assert.False(report.GetProperty("architecture").GetProperty("os").ValueKind == JsonValueKind.Null);
        if (report.GetProperty("shop").GetProperty("agentId").ValueKind == JsonValueKind.String)
            Assert.True(Guid.TryParse(report.GetProperty("shop").GetProperty("agentId").GetString(), out _));
        AssertNoSecretFields(report);
        Assert.DoesNotContain(Secret, json, StringComparison.Ordinal);
        Assert.DoesNotContain("owner@example.com", json, StringComparison.Ordinal);
        Assert.DoesNotContain("555-0100", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Secret Street", json, StringComparison.Ordinal);
        Assert.DoesNotContain("relay.example", json, StringComparison.Ordinal);
        if (Environment.UserName.Length >= 3 && report.GetProperty("installPath").ValueKind == JsonValueKind.String)
        {
            var path = report.GetProperty("installPath").GetString()!;
            Assert.DoesNotContain(Path.DirectorySeparatorChar + Environment.UserName + Path.DirectorySeparatorChar, path, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Path.AltDirectorySeparatorChar + Environment.UserName + Path.AltDirectorySeparatorChar, path, StringComparison.OrdinalIgnoreCase);
        }

        Assert.DoesNotContain("CI builds include a build number", cut.Markup, StringComparison.Ordinal);
    }

    [Fact]
    public void About_page_module_lists_expand_and_collapse()
    {
        using var monitor = new AgentModeMonitor(_ => AgentModeSnapshot.LocalOnly, startLoop: false);
        var session = new SessionContext(SessionMode.Local);
        var registrar = new RemotePCDiagnostics.Core.Plugins.PluginRegistrar(session, new Version(1, 0));
        registrar.RecordDisabled(new RemotePCDiagnostics.Core.Plugins.PluginRecord("sample.plugin", ModuleSource.Plugin, RemotePCDiagnostics.Core.Plugins.PluginState.Disabled, "unsigned")
        {
            DisplayName = "Sample Plugin",
            Version = "1.2.3",
        });
        registrar.RecordDisabled(new RemotePCDiagnostics.Core.Plugins.PluginRecord("builtin.sample", ModuleSource.BuiltIn, RemotePCDiagnostics.Core.Plugins.PluginState.Disabled, "test")
        {
            DisplayName = "Sample Built-in",
            Path = "/app/builtin-modules/Sample.dll",
        });

        Services.AddSingleton<ISessionContext>(session);
        Services.AddSingleton(new AppServices(Plugins: registrar));
        Services.AddSingleton(monitor);

        var cut = Render<AboutPage>();

        foreach (var testId in new[] { "about-plugins", "about-builtin-modules" })
        {
            var details = cut.Find($"details[data-testid='{testId}']");
            var toggle = cut.Find($"[data-testid='{testId}-toggle']");
            Assert.False(details.HasAttribute("open"));
            Assert.Equal("false", toggle.GetAttribute("aria-expanded"));

            toggle.Click();
            details = cut.Find($"details[data-testid='{testId}']");
            toggle = cut.Find($"[data-testid='{testId}-toggle']");
            Assert.True(details.HasAttribute("open"));
            Assert.Equal("true", toggle.GetAttribute("aria-expanded"));

            toggle.Click();
            details = cut.Find($"details[data-testid='{testId}']");
            toggle = cut.Find($"[data-testid='{testId}-toggle']");
            Assert.False(details.HasAttribute("open"));
            Assert.Equal("false", toggle.GetAttribute("aria-expanded"));
        }
    }

    private static readonly string[] SecretFieldNames =
        ["key", "enrollmentKey", "server", "apiKey", "shopApiKey", "email", "phone", "password", "token", "address"];

    private static void AssertNoSecretFields(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object) return;
        foreach (var property in element.EnumerateObject())
        {
            Assert.DoesNotContain(property.Name, SecretFieldNames);
            if (property.Value.ValueKind == JsonValueKind.Object)
                AssertNoSecretFields(property.Value);
        }
    }
}
