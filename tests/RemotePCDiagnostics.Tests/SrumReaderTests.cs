using System.Text;
using System.Runtime.Versioning;
using Microsoft.Isam.Esent.Interop;
using NetworkUsagePrototype;

namespace RemotePCDiagnostics.Tests;

[SupportedOSPlatform("windows")]
public class SrumReaderTests
{
    [Fact]
    public void ReadsRealEseFixtureAndFiltersTimeWindow()
    {
        // A synthetic ESE database; never reads the machine's actual SRUM history.
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "rpd-srum-test-" + Guid.NewGuid().ToString("N"))).FullName;
        var database = Path.Combine(root, "fixture.dat");
        var end = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        try
        {
            SystemParameters.DatabasePageSize = 8192;
            using (var instance = new Instance("fixture-" + Guid.NewGuid().ToString("N")))
            {
                instance.Parameters.Recovery = false;
                instance.Parameters.NoInformationEvent = true;
                instance.Parameters.TempDirectory = root;
                instance.Init();
                using var session = new Session(instance);
                Api.JetCreateDatabase(session, database, null, out var db, CreateDatabaseGrbit.None);
                try
                {
                    Api.JetCreateTable(session, db, "SruDbIdMapTable", 0, 100, out var map);
                    try
                    {
                        var index = Add(session, map, "IdIndex", JET_coltyp.Long);
                        var type = Add(session, map, "IdType", JET_coltyp.UnsignedByte);
                        var blob = Add(session, map, "IdBlob", JET_coltyp.LongBinary);
                        using var tx = new Transaction(session);
                        using var update = new Update(session, map, JET_prep.Insert);
                        Api.SetColumn(session, map, index, 42);
                        Api.SetColumn(session, map, type, (byte)0);
                        Api.SetColumn(session, map, blob, Encoding.Unicode.GetBytes("C:\\Apps\\Example.exe\0"));
                        update.Save();
                        tx.Commit(CommitTransactionGrbit.None);
                    }
                    finally { Api.JetCloseTable(session, map); }
                    Api.JetCreateTable(session, db, "{973F5D5C-1D90-4944-BE8E-24B94231A174}", 0, 100, out var network);
                    try
                    {
                        var time = Add(session, network, "TimeStamp", JET_coltyp.DateTime);
                        var app = Add(session, network, "AppId", JET_coltyp.Long);
                        var user = Add(session, network, "UserId", JET_coltyp.Long);
                        var sent = Add(session, network, "BytesSent", JET_coltyp.Currency);
                        var received = Add(session, network, "BytesRecvd", JET_coltyp.Currency);
                        var adapter = Add(session, network, "InterfaceLuid", JET_coltyp.Currency);
                        using var tx = new Transaction(session);
                        foreach (var hours in new[] { -2, -48, 1 })
                        {
                            using var update = new Update(session, network, JET_prep.Insert);
                            Api.SetColumn(session, network, time, end.AddHours(hours).UtcDateTime);
                            Api.SetColumn(session, network, app, 42);
                            Api.SetColumn(session, network, user, 99);
                            Api.SetColumn(session, network, sent, 123L);
                            Api.SetColumn(session, network, received, 456L);
                            Api.SetColumn(session, network, adapter, 7L);
                            update.Save();
                        }
                        tx.Commit(CommitTransactionGrbit.None);
                    }
                    finally { Api.JetCloseTable(session, network); }
                }
                finally { Api.JetCloseDatabase(session, db, CloseDatabaseGrbit.None); }
            }
            var report = SrumReader.Read(database, end.AddDays(-1), end);
            var row = Assert.Single(report.Entries);
            Assert.Equal("Example.exe", row.App);
            Assert.Equal("C:\\Apps\\Example.exe", row.AppId);
            Assert.Equal("Unresolved UserId 99", row.User);
            Assert.Equal(123UL, row.Uploaded);
            Assert.Equal(456UL, row.Downloaded);
            Assert.Equal(end.AddHours(-2), row.TimeUtc);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static JET_COLUMNID Add(Session session, JET_TABLEID table, string name, JET_coltyp type)
    {
        Api.JetAddColumn(session, table, name, new JET_COLUMNDEF { coltyp = type }, null, 0, out var id);
        return id;
    }
}
