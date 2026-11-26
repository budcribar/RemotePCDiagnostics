using System.Text.Json;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Replay;

public sealed class RecordingScrubberTests
{
    private static RecordingScrubber Scrubber() => new("BUDSLAPTOP", ["bud", "Public"]);

    [Fact]
    public void ReplacesThePcAndUserNamesOnlyAsWholeWords()
    {
        var s = Scrubber();
        var t = s.Text(@"C:\Users\bud\AppData on BUDSLAPTOP; budget and BUDSLAPTOP2 stay");
        Assert.DoesNotContain(@"\bud\", t);
        Assert.DoesNotContain("BUDSLAPTOP;", t);
        Assert.Contains("budget", t);
        Assert.Contains("BUDSLAPTOP2", t);
        Assert.Equal(s.Text("bud"), s.Text("BUD")); // same name, same placeholder
        Assert.StartsWith("<user:", s.Text("bud"));
        Assert.StartsWith("<pc:", s.Text("budslaptop"));
    }

    [Fact]
    public void ScrubsThePcNameInAQueryTheSameWayAsInTheRowItCameFrom()
    {
        var s = Scrubber();
        const string objectId = @"{1}\\BUDSLAPTOP\root/Microsoft/Windows/Storage/Providers_v2\SPACES_PhysicalDisk.ObjectId=""{x}:PD:{y}""";
        var disk = s.Scrub(new RecordedCall
        {
            Kind = RecordedCall.WmiKind, Namespace = @"root\Microsoft\Windows\Storage", Query = "q",
            Rows = [new() { ["ObjectId"] = JsonSerializer.SerializeToElement(objectId) }],
        });
        var counter = s.Scrub(new RecordedCall { Kind = RecordedCall.WmiKind, Query = Core.Areas.DriveReader.CounterSql(objectId), Rows = [] });
        Assert.DoesNotContain("BUDSLAPTOP", counter.Query);
        // Replay builds the counter query from the scrubbed disk row, so it must equal the scrubbed recorded query.
        Assert.Equal(Core.Areas.DriveReader.CounterSql(disk.Rows![0]["ObjectId"].GetString()!), counter.Query);
    }

    [Fact]
    public void ReplacesSerialsInWmiRowsAndOsqueryOutput()
    {
        var s = Scrubber();
        var call = s.Scrub(new RecordedCall
        {
            Kind = RecordedCall.WmiKind, Namespace = @"root\wmi", Query = "q",
            Rows = [new() { ["SerialNumber"] = JsonSerializer.SerializeToElement("ABC123"), ["DesignedCapacity"] = JsonSerializer.SerializeToElement(42000) }],
        });
        Assert.StartsWith("<serial:", call.Rows![0]["SerialNumber"].GetString());
        Assert.Equal(42000, call.Rows[0]["DesignedCapacity"].GetInt32());

        var osq = s.Scrub(new RecordedCall
        {
            Kind = RecordedCall.ProcessKind, File = "osqueryi.exe", Args = [],
            StdOut = """[{"serial_number":"ABC123","model":"L21D3PF0","path":"C:\\Users\\bud\\x"}]""",
        });
        Assert.DoesNotContain("ABC123", osq.StdOut);
        Assert.Contains("L21D3PF0", osq.StdOut);
        Assert.DoesNotContain(@"\\bud\\", osq.StdOut);
        // The same serial gets the same placeholder in both answers.
        Assert.Contains(call.Rows[0]["SerialNumber"].GetString()!, osq.StdOut);
        Assert.Equal(2, s.Counts["serial"]);
    }

    [Fact]
    public void ScrubsTheBatteryReportsSerialAndPcNameButKeepsItReadable()
    {
        var s = Scrubber();
        const string xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?><BatteryReport xmlns=\"http://schemas.microsoft.com/battery/2012\">"
            + "<SystemInformation><ComputerName>BUDSLAPTOP</ComputerName></SystemInformation><Batteries><Battery><SerialNumber>ABC123</SerialNumber>"
            + "<DesignCapacity>42000</DesignCapacity></Battery></Batteries><RecentUsage><UsageEntry Timestamp=\"2026-11-19T02:16:18Z\" EntryType=\"Suspend\" />"
            + "</RecentUsage><Note>C:\\Users\\bud\\report.xml</Note></BatteryReport>";
        var call = s.Scrub(RecordedCall.FromFile("powercfg /batteryreport /xml", xml));
        Assert.DoesNotContain("ABC123", call.StdOut);
        Assert.DoesNotContain("BUDSLAPTOP", call.StdOut);
        Assert.DoesNotContain(@"\bud\", call.StdOut);
        Assert.StartsWith("<?xml", call.StdOut);
        var doc = System.Xml.Linq.XDocument.Parse(call.StdOut!);
        Assert.Equal("42000", doc.Descendants().Single(e => e.Name.LocalName == "DesignCapacity").Value);
        Assert.Equal("Suspend", doc.Descendants().Single(e => e.Name.LocalName == "UsageEntry").Attribute("EntryType")!.Value);
        Assert.StartsWith("<serial:", doc.Descendants().Single(e => e.Name.LocalName == "SerialNumber").Value);
    }

    [Fact]
    public void KeepsWevtutilEventsReadableXmlWithThePcNameReplaced()
    {
        var s = Scrubber();
        const string events = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Disk'/><EventID>7</EventID>"
            + "<Computer>BUDSLAPTOP</Computer><Security UserID='S-1-5-21-1-2-3-1001'/></System><RenderingInfo Culture='en-US'><Message>C:\\Users\\bud\\x&#13;&#10;y</Message></RenderingInfo></Event>"
            + "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Disk'/><EventID>8</EventID><Computer>BUDSLAPTOP</Computer></System></Event>";
        var call = s.Scrub(new RecordedCall { Kind = RecordedCall.ProcessKind, File = "wevtutil.exe", Args = [], StdOut = events });
        Assert.DoesNotContain("BUDSLAPTOP", call.StdOut);
        Assert.DoesNotContain(@"\bud\", call.StdOut);
        Assert.DoesNotContain("S-1-5-21-1-2-3", call.StdOut);
        var parsed = RemotePCDiagnostics.Core.Areas.WindowsEventLog.Parse(call.StdOut!, "System");
        Assert.Equal(2, parsed.Count);
        Assert.StartsWith("C:\\Users\\<user:", parsed.Single(e => e.EventId == 7).Message);
    }

    [Fact]
    public void ReplacesTheSmbiosUuidButKeepsTheProductId()
    {
        var rec = Scrubber().Scrub(new MachineRecording
        {
            Machine = new RecordedMachine { ProductId = "LENOVO_MT_82R4", SmbiosUuid = "ECAF7E7E-0000-4276-90F3-C4C6E699C775" },
            Calls = [],
        });
        Assert.StartsWith("<serial:", rec.Machine.SmbiosUuid);
        Assert.Equal("LENOVO_MT_82R4", rec.Machine.ProductId);
    }

    [Fact]
    public void RoundTripsThroughDisk()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpd-recording-" + Guid.NewGuid().ToString("N"));
        try
        {
            var rec = RecordingLibrary.Load("sample/sample-laptop");
            rec.Save(dir);
            var back = MachineRecording.Load(dir);
            Assert.Equal(rec.Machine, back.Machine);
            Assert.Equal(rec.Calls.Count, back.Calls.Count);
            Assert.Equal(rec.Calls.Select(c => c.Describe()), back.Calls.Select(c => c.Describe()));
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }

    /// <summary>Nothing in a saved recording looks like a serial, a MAC address or a user's profile path that the scrubber missed.</summary>
    [Theory]
    [MemberData(nameof(BatteryPowerReplayTests.Recordings), MemberType = typeof(BatteryPowerReplayTests))]
    public void RecordingsHoldNoUnscrubbedIdentifiers(string name)
    {
        var text = File.ReadAllText(Path.Combine(RecordingLibrary.Folder(name), MachineRecording.CallsFile));
        using var doc = JsonDocument.Parse(text);
        var problems = new List<string>();
        void Walk(JsonElement e, string? key)
        {
            switch (e.ValueKind)
            {
                case JsonValueKind.Object: foreach (var p in e.EnumerateObject()) Walk(p.Value, p.Name); break;
                case JsonValueKind.Array: foreach (var x in e.EnumerateArray()) Walk(x, key); break;
                case JsonValueKind.String:
                    var s = e.GetString()!;
                    if (key is not null && RecordingScrubber.SensitiveNames.Contains(key) && s.Length > 0 && !s.StartsWith('<')) problems.Add($"{key} = {s}");
                    if (LooksLikeMac(s)) problems.Add($"MAC-like value under {key}: {s}");
                    if (ProfileUser(s) is { } u) problems.Add($"profile path under {key}: {u}");
                    if (key is "stdOut" && JsonRows(s) is { } rows) using (rows) Walk(rows.RootElement, null); // osquery's rows, not a log such as HardeningKitty's "[*] ..." lines
                    break;
            }
        }
        Walk(doc.RootElement, null);
        var uuid = RecordingLibrary.Load(name).Machine.SmbiosUuid;
        if (uuid.Length > 0 && !uuid.StartsWith('<')) problems.Add($"machine smbiosUuid = {uuid}");
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    private static JsonDocument? JsonRows(string s)
    {
        if (!s.TrimStart().StartsWith('[')) return null;
        try { return JsonDocument.Parse(s); } catch (JsonException) { return null; }
    }

    private static bool LooksLikeMac(string s)
    {
        for (var i = 0; i + 17 <= s.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < 17 && ok; j++)
                ok = j % 3 == 2 ? s[i + j] is ':' or '-' : Uri.IsHexDigit(s[i + j]);
            if (ok) return true;
        }
        return false;
    }

    private static string? ProfileUser(string s)
    {
        const string marker = @"\Users\";
        var at = s.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (at < 0) return null;
        var rest = s[(at + marker.Length)..];
        if (rest.StartsWith("&lt;", StringComparison.Ordinal)) return null; // A placeholder inside event XML is escaped.
        var end = rest.IndexOfAny(['\\', '"', ' ', ';']);
        var user = end < 0 ? rest : rest[..end];
        string[] shared = ["Public", "Default", "Default User", "All Users"];
        return user.Length == 0 || user.StartsWith('<') || shared.Contains(user, StringComparer.OrdinalIgnoreCase) ? null : user;
    }

    [Fact]
    public void ReplacesIpv6AndPublicAddressesKeepingTheFamily_KeepsPrivateIpv4()
    {
        var s = Scrubber();
        var row = s.Scrub(new RecordedCall
        {
            Kind = RecordedCall.WmiKind, Namespace = @"root\cimv2", Query = "q",
            Rows = [new()
            {
                ["IPAddress"] = JsonSerializer.SerializeToElement(new[] { "192.168.1.46", "fe80::877e:a690:b067:97e9", "fd21:7783:5a6:434::1" }),
                ["DefaultIPGateway"] = JsonSerializer.SerializeToElement(new[] { "203.0.113.7" }),
            }],
        }).Rows![0];
        var ips = row["IPAddress"].EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Equal("192.168.1.46", ips[0]);
        Assert.All(ips.Skip(1), ip => Assert.StartsWith(RecordingPlaceholders.Ipv6, ip));
        Assert.StartsWith(RecordingPlaceholders.Ipv4, row["DefaultIPGateway"][0].GetString());
        Assert.Equal("10.0.0.1", s.Address("10.0.0.1"));
        Assert.Equal("not an address", s.Address("not an address"));
    }
}
