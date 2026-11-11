using System.Buffers.Binary;
using System.Text;
using System.Security.Principal;
using System.Runtime.Versioning;
using Microsoft.Isam.Esent.Interop;
using RemotePCDiagnostics.Core.NetworkUsage;

namespace NetworkUsagePrototype;

[SupportedOSPlatform("windows")]
internal static class SrumReader
{
    internal const int DefaultPageSize = 8192;
    private static readonly object EsentGate = new();

    public static NetworkUsageReport Read(string copiedDatabase, DateTimeOffset start, DateTimeOffset end)
    {
        var pageSize = DetectPageSize(copiedDatabase);
        lock (EsentGate)
        {
            try
            {
                if (SystemParameters.DatabasePageSize != pageSize)
                    SystemParameters.DatabasePageSize = pageSize;
            }
            catch (EsentErrorException)
            {
                // JET_paramDatabasePageSize is process-global and throws JET_errAlreadyInitialized if another ESENT instance is active.
            }
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
                        ids[id.Value] = DecodeIdentity(id.Value, type, blob);
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

    internal static string DecodeIdentity(int id, byte? type, byte[] blob)
    {
        if (type == 3)
        {
            if (blob.Length < SecurityIdentifier.MinBinaryLength)
                return $"Malformed SID {id}";
            try
            {
                var sid = new SecurityIdentifier(blob, 0);
                return sid.BinaryLength <= blob.Length ? sid.Value : $"Malformed SID {id}";
            }
            catch (ArgumentException)
            {
                return $"Malformed SID {id}";
            }
        }
        return Encoding.Unicode.GetString(blob).TrimEnd('\0');
    }

    internal static int DetectPageSize(string databasePath)
    {
        try
        {
            Span<byte> header = stackalloc byte[240];
            using var fs = new FileStream(databasePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.ReadAtLeast(header, header.Length, throwOnEndOfStream: false) < header.Length) return DefaultPageSize;
            return ParseHeaderPageSize(header);
        }
        catch (IOException) { return DefaultPageSize; }
        catch (UnauthorizedAccessException) { return DefaultPageSize; }
    }

    internal static int ParseHeaderPageSize(ReadOnlySpan<byte> header)
    {
        if (header.Length < 240) return DefaultPageSize;
        if (BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(4, 4)) != 0x89ABCDEFu) return DefaultPageSize;
        var pageSize = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(236, 4));
        return pageSize is 2048 or 4096 or 8192 or 16384 or 32768 ? pageSize : DefaultPageSize;
    }
}
