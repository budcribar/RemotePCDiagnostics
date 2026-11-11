using System.Buffers.Binary;
using System.Text;
using System.Security.Principal;
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
            Assert.Equal(8192, SrumReader.DetectPageSize(database));
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

    [Fact]
    public void DecodeIdentity_HandlesMalformedDataWithoutThrowing()
    {
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var validSidBytes = new byte[localSystem.BinaryLength];
        localSystem.GetBinaryForm(validSidBytes, 0);
        Assert.Equal("S-1-5-18", SrumReader.DecodeIdentity(10, 3, validSidBytes));

        Assert.Equal("Malformed SID 11", SrumReader.DecodeIdentity(11, 3, []));
        Assert.Equal("Malformed SID 12", SrumReader.DecodeIdentity(12, 3, [1, 1, 0]));
        Assert.Equal("Malformed SID 13", SrumReader.DecodeIdentity(13, 3, [99, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]));
        Assert.Equal("Malformed SID 14", SrumReader.DecodeIdentity(14, 3, [1, 5, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]));
        Assert.Equal(@"C:\Windows\System32\svchost.exe", SrumReader.DecodeIdentity(15, 0, Encoding.Unicode.GetBytes("C:\\Windows\\System32\\svchost.exe\0")));
    }

    [Fact]
    public void ParseHeaderPageSize_HandlesValidAndMalformedHeaders()
    {
        var header = new byte[240];
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4, 4), 0x89ABCDEFu);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(236, 4), 4096);
        Assert.Equal(4096, SrumReader.ParseHeaderPageSize(header));

        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(236, 4), 32768);
        Assert.Equal(32768, SrumReader.ParseHeaderPageSize(header));

        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(236, 4), 9999);
        Assert.Equal(SrumReader.DefaultPageSize, SrumReader.ParseHeaderPageSize(header));

        Assert.Equal(SrumReader.DefaultPageSize, SrumReader.ParseHeaderPageSize(new byte[32]));
        Assert.Equal(SrumReader.DefaultPageSize, SrumReader.ParseHeaderPageSize(new byte[240]));
    }

    [Fact]
    public void Read_SurvivesMalformedSidRow_AndConcurrentActiveEsentInstance()
    {
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "rpd-srum-sid-" + Guid.NewGuid().ToString("N"))).FullName;
        var activeTemp = Directory.CreateDirectory(Path.Combine(root, "active")).FullName;
        var database = Path.Combine(root, "fixture.dat");
        var end = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var validSid = new byte[localSystem.BinaryLength];
        localSystem.GetBinaryForm(validSid, 0);

        try
        {
            SystemParameters.DatabasePageSize = 8192;
            using (var creator = new Instance("creator-" + Guid.NewGuid().ToString("N")))
            {
                creator.Parameters.Recovery = false;
                creator.Parameters.NoInformationEvent = true;
                creator.Parameters.TempDirectory = root;
                creator.Init();
                using var session = new Session(creator);
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

                        using (var uApp = new Update(session, map, JET_prep.Insert))
                        {
                            Api.SetColumn(session, map, index, 1);
                            Api.SetColumn(session, map, type, (byte)0);
                            Api.SetColumn(session, map, blob, Encoding.Unicode.GetBytes("C:\\Apps\\Tool.exe\0"));
                            uApp.Save();
                        }
                        using (var uGoodSid = new Update(session, map, JET_prep.Insert))
                        {
                            Api.SetColumn(session, map, index, 2);
                            Api.SetColumn(session, map, type, (byte)3);
                            Api.SetColumn(session, map, blob, validSid);
                            uGoodSid.Save();
                        }
                        using (var uBadSid = new Update(session, map, JET_prep.Insert))
                        {
                            Api.SetColumn(session, map, index, 3);
                            Api.SetColumn(session, map, type, (byte)3);
                            Api.SetColumn(session, map, blob, new byte[] { 0xFF, 0x01, 0x02 });
                            uBadSid.Save();
                        }
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
                        foreach (var userId in new[] { 2, 3 })
                        {
                            using var update = new Update(session, network, JET_prep.Insert);
                            Api.SetColumn(session, network, time, end.AddHours(-1).UtcDateTime);
                            Api.SetColumn(session, network, app, 1);
                            Api.SetColumn(session, network, user, userId);
                            Api.SetColumn(session, network, sent, 100L);
                            Api.SetColumn(session, network, received, 200L);
                            Api.SetColumn(session, network, adapter, 1L);
                            update.Save();
                        }
                        tx.Commit(CommitTransactionGrbit.None);
                    }
                    finally { Api.JetCloseTable(session, network); }
                }
                finally { Api.JetCloseDatabase(session, db, CloseDatabaseGrbit.None); }
            }

            // Keep another ESENT instance active while SrumReader.Read executes.
            using var active = new Instance("active-" + Guid.NewGuid().ToString("N"));
            active.Parameters.Recovery = false;
            active.Parameters.NoInformationEvent = true;
            active.Parameters.TempDirectory = activeTemp;
            active.Init();

            var report = SrumReader.Read(database, end.AddDays(-1), end);
            Assert.Equal(2, report.Entries.Count);
            Assert.Contains(report.Entries, r => r.User == "S-1-5-18");
            Assert.Contains(report.Entries, r => r.User == "Malformed SID 3");
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static JET_COLUMNID Add(Session session, JET_TABLEID table, string name, JET_coltyp type)
    {
        Api.JetAddColumn(session, table, name, new JET_COLUMNDEF { coltyp = type }, null, 0, out var id);
        return id;
    }
}
