using RemotePCDiagnostics.Agent;

namespace RemotePCDiagnostics.Agent.Core.Tests;

public class ElevationRequiredMessageTests
{
    [Fact]
    public void Error_740_names_the_program_and_says_to_install_the_current_build()
    {
        var message = Win32Session.ElevationRequiredMessage(@"C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Host.exe");

        Assert.Contains(@"C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Host.exe", message);
        Assert.Contains("administrator rights", message);
        Assert.Contains("install the current Remote PC Diagnostics", message);
    }
}
