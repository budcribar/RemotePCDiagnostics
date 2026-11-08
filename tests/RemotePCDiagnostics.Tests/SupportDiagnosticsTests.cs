using System.Net;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class SupportDiagnosticsTests
{
    [Theory]
    [InlineData("https://example.com/resource", "example.com", true)]
    [InlineData(@"\\fileserver\shared\folder", "fileserver", false)]
    public void Endpoint_RecognizesWebAndShareTargets(string input, string host, bool web)
    {
        Assert.True(SupportDiagnostics.TryEndpoint(input, out var endpoint));
        Assert.Equal(host, endpoint.Host);
        Assert.Equal(web, endpoint.Web is not null);
    }

    [Theory]
    [InlineData("https://user:password@example.com/")]
    [InlineData("https://example.com/?token=secret")]
    [InlineData("file:///C:/Windows")]
    [InlineData(@"\\fileserver")]
    public void Endpoint_RejectsUnsupportedOrCredentialBearingTargets(string input) =>
        Assert.False(SupportDiagnostics.TryEndpoint(input, out _));

    [Fact]
    public void WebProbe_DistinguishesAuthenticationFromDenial()
    {
        Assert.Contains("Authentication required", SupportDiagnostics.DescribeHttp(HttpStatusCode.Unauthorized));
        Assert.Contains("denied this anonymous request", SupportDiagnostics.DescribeHttp(HttpStatusCode.Forbidden));
        Assert.Contains("redirected", SupportDiagnostics.DescribeHttp(HttpStatusCode.Found));
    }

    [Fact]
    public void SignIn_ReportsOnlyJoinFlagsAndQualifiedClockEvidence()
    {
        var join = SupportDiagnostics.ParseJoin("AzureAdJoined : YES\r\nDomainJoined : NO\r\nTenantId : private").ToList();
        Assert.Equal(["Joined", "Not joined"], join.Select(r => r.Result));
        Assert.Contains("not synchronized", SupportDiagnostics.DescribeClock("Leap Indicator: 3\nPhase Offset: 0.0000000s"));
        Assert.Contains("Last reported phase offset", SupportDiagnostics.DescribeClock("Leap Indicator: 0\nPhase Offset: -0.0020000s"));
        Assert.Contains("unavailable", SupportDiagnostics.DescribeClock(null));
    }

    [Fact]
    public void DockComparison_UsesInstanceIdRatherThanDisplayName()
    {
        DockDevice monitor = new("Display-1", "Display", "Monitor", "OK", null, true);
        DockDevice hub = new("Hub-1", "USB hub", "Hub", "OK", null, null);
        Assert.Equal(hub, Assert.Single(SupportDiagnostics.MissingDevices([monitor, hub], [monitor with { Id = "display-1", Name = "New name" }])));
    }
}
