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
                    if (key is "stdOut" && s.TrimStart().StartsWith('[')) Walk(JsonDocument.Parse(s).RootElement, null);
                    break;
            }
        }
        Walk(doc.RootElement, null);
        Assert.True(problems.Count == 0, string.Join("\n", problems));
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
        var end = rest.IndexOfAny(['\\', '"', ' ', ';']);
        var user = end < 0 ? rest : rest[..end];
        string[] shared = ["Public", "Default", "Default User", "All Users"];
        return user.Length == 0 || user.StartsWith('<') || shared.Contains(user, StringComparer.OrdinalIgnoreCase) ? null : user;
    }
}
