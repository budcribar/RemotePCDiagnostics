using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>
/// Replaces personal details in a recording before it is saved, with the same placeholders the Admin uses: <c>&lt;pc:1a2b3c&gt;</c> for the
/// PC's name, <c>&lt;user:1a2b3c&gt;</c> for a Windows user, <c>&lt;serial:1a2b3c&gt;</c> for a serial number or other per-unit ID. The same
/// value always gets the same placeholder within one recording (an HMAC under a key that is never saved), so answers still line up.
/// Plain string handling only.
/// </summary>
public sealed class RecordingScrubber
{
    /// <summary>Property names (WMI or osquery columns) whose values identify one unit or one person, compared ignoring case.</summary>
    public static readonly IReadOnlySet<string> SensitiveNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "SerialNumber", "serial_number", "serial", "hardware_serial", "board_serial", "UniqueID", "IdentifyingNumber",
        "MACAddress", "mac", "PermanentAddress", "CSName", "__SERVER", "UserName", "RegisteredUser", "PrimaryOwnerName",
        "computer_name", "hostname", "local_hostname",
        "Id", // the DriveHealth script's name for a disk's UniqueId (its WWN / EUI)
    };

    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly List<(string Value, string Kind)> _names = [];
    private readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);

    /// <param name="machineName">This PC's name.</param>
    /// <param name="userNames">Windows user names on this PC (the signed-in user at least).</param>
    public RecordingScrubber(string machineName, IEnumerable<string> userNames)
    {
        if (machineName.Trim().Length >= 2) _names.Add((machineName.Trim(), "pc"));
        foreach (var u in userNames.Select(u => u.Trim()).Where(u => u.Length >= 2).Distinct(StringComparer.OrdinalIgnoreCase))
            _names.Add((u, "user"));
        // Longest first, so "BUDSLAPTOP" is replaced before "bud".
        _names.Sort((a, b) => b.Value.Length.CompareTo(a.Value.Length));
    }

    /// <summary>What was replaced, and how many times.</summary>
    public IReadOnlyDictionary<string, int> Counts => _counts;

    public MachineRecording Scrub(MachineRecording recording) => new()
    {
        Schema = recording.Schema,
        // The SMBIOS UUID is per unit on most makers (the product id names the model), so it is replaced like a serial.
        Machine = recording.Machine with
        {
            Notes = recording.Machine.Notes is { } n ? Text(n) : null,
            SmbiosUuid = Placeholder("serial", recording.Machine.SmbiosUuid),
        },
        CapturedAt = recording.CapturedAt,
        Calls = recording.Calls.Select(Scrub).ToList(),
    };

    public RecordedCall Scrub(RecordedCall c) => c with
    {
        Args = c.Args?.Select(Text).ToList(),
        StdOut = c.StdOut is { } o ? Output(o) : null,
        StdErr = c.StdErr is { } e ? Text(e) : null,
        Error = c.Error is { } err ? Text(err) : null,
        Rows = c.Rows?.Select(r => r.ToDictionary(p => p.Key, p => Value(p.Key, p.Value), StringComparer.OrdinalIgnoreCase)).ToList(),
    };

    /// <summary>Command output: JSON (osquery) has its sensitive columns replaced too; any text has names replaced.</summary>
    private string Output(string stdout)
    {
        var t = stdout.TrimStart();
        if (t.StartsWith('[') || t.StartsWith('{'))
        {
            try
            {
                if (JsonNode.Parse(stdout) is { } node)
                {
                    ScrubNode(node);
                    return node.ToJsonString(MachineRecording.Json);
                }
            }
            catch (JsonException) { /* not JSON after all: treat as text */ }
        }
        return Text(stdout);
    }

    private void ScrubNode(JsonNode node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var (name, child) in o.ToList())
                {
                    if (child is JsonValue v && v.TryGetValue<string>(out var s))
                        o[name] = SensitiveNames.Contains(name) ? Placeholder("serial", s) : Text(s);
                    else if (child is not null) ScrubNode(child);
                }
                break;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonValue v && v.TryGetValue<string>(out var s)) a[i] = Text(s);
                    else if (a[i] is { } child) ScrubNode(child);
                }
                break;
        }
    }

    private JsonElement Value(string name, JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.String)
        {
            var s = value.GetString()!;
            return JsonSerializer.SerializeToElement(SensitiveNames.Contains(name) ? Placeholder("serial", s) : Text(s));
        }
        if (value.ValueKind == JsonValueKind.Array)
            return JsonSerializer.SerializeToElement(value.EnumerateArray().Select(e => Value(name, e)).ToList());
        if (SensitiveNames.Contains(name) && value.ValueKind == JsonValueKind.Number)
            return JsonSerializer.SerializeToElement(Placeholder("serial", value.GetRawText()));
        return value;
    }

    private string Placeholder(string kind, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return value;
        _counts[kind] = _counts.GetValueOrDefault(kind) + 1;
        var mac = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(kind + "\n" + value.Trim().ToUpperInvariant()));
        return $"<{kind}:{Convert.ToHexString(mac, 0, 3).ToLowerInvariant()}>";
    }

    /// <summary>Replaces the PC's name and user names where they stand as a whole word (not inside a longer word).</summary>
    public string Text(string s)
    {
        foreach (var (value, kind) in _names)
        {
            var at = 0;
            while ((at = s.IndexOf(value, at, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                var end = at + value.Length;
                var wordStart = at == 0 || !char.IsLetterOrDigit(s[at - 1]);
                var wordEnd = end == s.Length || !char.IsLetterOrDigit(s[end]);
                if (!wordStart || !wordEnd) { at = end; continue; }
                var p = Placeholder(kind, value);
                s = string.Concat(s.AsSpan(0, at), p, s.AsSpan(end));
                at += p.Length;
            }
        }
        return s;
    }
}
