using System.Text.Json;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>The app reads WMI through the Agent (wmi_query), which has administrator rights; the app never queries WMI itself.</summary>
public sealed class AgentWmiTests
{
    [Fact]
    public async Task A_query_is_answered_by_the_agent_over_the_pipe()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var fake = new FakeWmi();
        var (server, task, client) = await StartAsync(fake, cts.Token);
        using (server)
        {
            await using (client)
            {
                var wmi = new AgentWmiSource(client);
                var r = await wmi.QueryAsync(@"root\cimv2\power", "SELECT ElementName FROM Win32_PowerPlan WHERE IsActive = TRUE", cts.Token);
                Assert.True(r.Success, r.Error);
                Assert.Equal("Balanced", Assert.Single(r.Rows!).Str("ElementName"));
                Assert.Equal(42000, (await wmi.QueryAsync(@"root\wmi", "SELECT DesignedCapacity FROM BatteryStaticData", cts.Token)).Rows![0].Long("DesignedCapacity"));

                var failed = await wmi.QueryAsync(@"root\wmi", "SELECT * FROM Fails", cts.Token);
                Assert.False(failed.Success);
                Assert.Equal("NotSupported: Not supported", failed.Error);
            }
            await task;
        }
    }

    [Theory]
    [InlineData(@"root\subscription", "SELECT * FROM __EventFilter")]
    [InlineData(@"root\cimv2", "DELETE FROM Win32_Process")]
    [InlineData(@"root\cimv2", "")]
    [InlineData(@"root\cimv2", "SELECT * FROM Win32_Process\u0000x")]
    [InlineData(@"root\cimv2", "REFERENCES OF {Win32_Process.Handle=\"4\"}")]
    public async Task The_agent_runs_only_selects_in_the_namespaces_checks_read(string ns, string wql)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var fake = new FakeWmi();
        var (server, task, client) = await StartAsync(fake, cts.Token);
        using (server)
        {
            await using (client)
                Assert.False((await client.QueryWmiAsync(ns, wql, cts.Token)).Success);
            await task;
        }
        Assert.Equal(0, fake.Calls);
    }

    [Fact]
    public void A_disks_reliability_counters_are_read_through_its_link_as_windows_requires()
    {
        // A real MSFT_PhysicalDisk.ObjectId (name and GUIDs changed): backslashes and quotes must be escaped inside the WQL string.
        const string objectId = @"{1}\\PC1\root/Microsoft/Windows/Storage/Providers_v2\SPACES_PhysicalDisk.ObjectId=""{dd282e87-0000-0000-0000-000000000000}:PD:{12d8ecbc-0000-0000-0000-000000000000}""";
        var wql = Core.Areas.DriveReader.CounterSql(objectId);
        Assert.Equal(
            @"ASSOCIATORS OF {MSFT_PhysicalDisk.ObjectId=""{1}\\\\PC1\\root/Microsoft/Windows/Storage/Providers_v2\\SPACES_PhysicalDisk.ObjectId=\""{dd282e87-0000-0000-0000-000000000000}:PD:{12d8ecbc-0000-0000-0000-000000000000}\""""} WHERE AssocClass = MSFT_PhysicalDiskToStorageReliabilityCounter",
            wql);
        Assert.Null(WmiQueryPolicy.Problem(Core.Areas.DriveReader.StorageNamespace, wql));
    }

    [Fact]
    public async Task Without_the_agent_every_query_fails_and_nothing_is_read_locally()
    {
        var r = await new AgentWmiSource(new Disconnected()).QueryAsync(@"root\wmi", "SELECT * FROM BatteryStaticData", TestContext.Current.CancellationToken);
        Assert.False(r.Success);
        Assert.Equal(AgentWmiSource.NotConnected, r.Error);
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(IWmiSource wmi, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")), wmiSource: wmi);
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }

    private sealed class FakeWmi : IWmiSource
    {
        public int Calls;
        public Task<WmiQueryResult> QueryAsync(string ns, string wql, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Calls);
            WmiRow Row(string k, object v) => new(new Dictionary<string, JsonElement> { [k] = JsonSerializer.SerializeToElement(v) });
            return Task.FromResult(wql.Contains("Fails") ? WmiQueryResult.Failed(ns, wql, "NotSupported: Not supported")
                : wql.Contains("PowerPlan") ? new WmiQueryResult(ns, wql, [Row("ElementName", "Balanced")])
                : new WmiQueryResult(ns, wql, [Row("DesignedCapacity", 42000)]));
        }
    }

    private sealed class Disconnected : IElevatedCommandBridge
    {
        public bool IsConnected => false;
        public Task<RemotePCDiagnostics.Core.Osquery.ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            throw new InvalidOperationException("not connected");
        public Task<RemotePCDiagnostics.Core.Sensors.SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<IReadOnlyList<RemotePCDiagnostics.Core.Areas.DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<WmiQueryResult> QueryWmiAsync(string wmiNamespace, string wql, CancellationToken ct = default) => throw new InvalidOperationException("must not be asked");
    }
}
