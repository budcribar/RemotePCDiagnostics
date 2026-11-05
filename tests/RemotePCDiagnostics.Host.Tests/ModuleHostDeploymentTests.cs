using System.IO;
using System.Linq;
using System.Text.Json;

namespace RemotePCDiagnostics.Host.Tests;

/// <summary>
/// The user-mode module host runs from the app's folder, where the DI, Components and JSInterop assemblies are not files (the app gets
/// them from the Microsoft.AspNetCore.App shared framework). The host must load that framework too, or every unsigned module fails with
/// "Could not load ... Microsoft.Extensions.DependencyInjection.Abstractions".
/// </summary>
public class ModuleHostDeploymentTests
{
    [Fact]
    public void Module_host_next_to_the_app_uses_the_aspnetcore_shared_framework()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.ModuleHost.runtimeconfig.json");
        Assert.True(File.Exists(path), $"{path} is missing");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var options = doc.RootElement.GetProperty("runtimeOptions");
        var names = options.TryGetProperty("frameworks", out var many)
            ? many.EnumerateArray().Select(f => f.GetProperty("name").GetString()).ToList()
            : [options.GetProperty("framework").GetProperty("name").GetString()];
        Assert.Contains("Microsoft.AspNetCore.App", names);
    }
}
