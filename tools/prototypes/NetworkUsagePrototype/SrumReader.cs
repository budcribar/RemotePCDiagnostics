using System.Text;
using System.Security.Principal;
using System.Runtime.Versioning;
using Microsoft.Isam.Esent.Interop;
using RemotePCDiagnostics.Core.NetworkUsage;

namespace NetworkUsagePrototype;

[SupportedOSPlatform("windows")]
internal static class SrumReader
{
    public static NetworkUsageReport Read(string copiedDatabase, DateTimeOffset start, DateTimeOffset end)
    {
        SystemParameters.DatabasePageSize = 8192;
        using var instance = new Instance("NetworkUsage-" + Guid.NewGuid().ToString("N"));
        instance.Parameters.Recovery = false;
        instance.Parameters.NoInformationEvent = true;
        instance.Parameters.TempDirectory = Path.GetDirectoryName(copiedDatabase)!;
        instance.Init();
        using var session = new Session(instance);
        Api.JetAttachDatabase(session, copiedDatabase, AttachDatabaseGrbit.ReadOnly);
        Api.JetOpenDatabase(session, copiedDatabase, null, out var db, OpenDatabaseGrbit.ReadOnly);
        try
        {
            var ids = new Dictionary<int, string>();
            using (var map = new Table(session, db, "SruDbIdMapTable", OpenTableGrbit.ReadOnly))
            {
                var cols = Api.GetColumnDictionary(session, map);
                if (Api.TryMoveFirst(session, map)) do
                {
                    var id = Api.RetrieveColumnAsInt32(session, map, cols["IdIndex"]);
                    var type = Api.RetrieveColumnAsByte(session, map, cols["IdType"]);
                    var blob = Api.RetrieveColumn(session, map, cols["IdBlob"]);
                    if (id is null || blob is null) continue;
                    ids[id.Value] = type == 3 ? new SecurityIdentifier(blob, 0).Value : Encoding.Unicode.GetString(blob).TrimEnd('\0');
                } while (Api.TryMoveNext(session, map));
            }
            var rows = new List<NetworkUsageEntry>();
            using (var table = new Table(session, db, "{973F5D5C-1D90-4944-BE8E-24B94231A174}", OpenTableGrbit.ReadOnly))
            {
                var cols = Api.GetColumnDictionary(session, table);
                if (Api.TryMoveFirst(session, table)) do
                {
                    var date = Api.RetrieveColumnAsDateTime(session, table, cols["TimeStamp"]);
                    if (date is null) throw new InvalidDataException("Network record has no timestamp.");
                    var time = new DateTimeOffset(DateTime.SpecifyKind(date.Value, DateTimeKind.Utc));
                    if (time < start || time >= end) continue;
                    var app = Api.RetrieveColumnAsInt32(session, table, cols["AppId"]);
                    var user = Api.RetrieveColumnAsInt32(session, table, cols["UserId"]);
                    var sent = Api.RetrieveColumnAsInt64(session, table, cols["BytesSent"]);
                    var received = Api.RetrieveColumnAsInt64(session, table, cols["BytesRecvd"]);
                    if (sent is null or < 0 || received is null or < 0) throw new InvalidDataException("Invalid network byte count.");
                    var identity = app is { } a && ids.TryGetValue(a, out var path) ? path : $"Unresolved AppId {app}";
                    var sid = user is { } u && ids.TryGetValue(u, out var value) ? value : $"Unresolved UserId {user}";
                    var adapter = Api.RetrieveColumnAsInt64(session, table, cols["InterfaceLuid"]);
                    rows.Add(new(identity, Path.GetFileName(identity.Replace('\\', '/')), sid, $"Interface LUID {adapter}", time, (ulong)sent.Value, (ulong)received.Value));
                } while (Api.TryMoveNext(session, table));
            }
            return new("Copied SRUM Network Data Usage table", start, end, rows,
                ["SRUM timestamps identify recording intervals, not exact app activity. Recent unflushed activity may be absent. Interface LUIDs are not resolved to Wi-Fi/Ethernet names in this prototype. All user SIDs are shown separately; this is not necessarily current-user-only data."]);
        }
        finally { Api.JetCloseDatabase(session, db, CloseDatabaseGrbit.None); }
    }
}
