using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>
/// The raw answers one PC gave to the checks, saved so tests can replay them (record and replay testing). A recording is a folder with
/// <see cref="MachineFile"/> (which PC model, Windows build and app version) and <see cref="CallsFile"/> (every answer, in the order asked).
/// Personal details are replaced with placeholders before it is saved (<see cref="RecordingScrubber"/>).
/// </summary>
public sealed class MachineRecording
{
    public const string MachineFile = "machine.json";
    public const string CallsFile = "calls.json";
    public const int CurrentSchema = 1;

    public int Schema { get; init; } = CurrentSchema;
    public RecordedMachine Machine { get; init; } = new();
    public DateTimeOffset CapturedAt { get; init; }
    public List<RecordedCall> Calls { get; init; } = [];

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public void Save(string folder)
    {
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, MachineFile), JsonSerializer.Serialize(new MachineFileContent(Schema, Machine, CapturedAt), Json));
        File.WriteAllText(Path.Combine(folder, CallsFile), JsonSerializer.Serialize(new CallsFileContent(Calls), Json));
    }

    public static MachineRecording Load(string folder)
    {
        var m = JsonSerializer.Deserialize<MachineFileContent>(File.ReadAllText(Path.Combine(folder, MachineFile)), Json)
                ?? throw new InvalidDataException($"{MachineFile} is empty in {folder}");
        if (m.Schema > CurrentSchema) throw new InvalidDataException($"{folder} uses recording schema {m.Schema}; this build reads up to {CurrentSchema}.");
        var c = JsonSerializer.Deserialize<CallsFileContent>(File.ReadAllText(Path.Combine(folder, CallsFile)), Json)
                ?? throw new InvalidDataException($"{CallsFile} is empty in {folder}");
        return new() { Schema = m.Schema, Machine = m.Machine, CapturedAt = m.CapturedAt, Calls = c.Calls };
    }

    /// <summary>Whether <paramref name="folder"/> holds a recording.</summary>
    public static bool IsRecording(string folder) =>
        File.Exists(Path.Combine(folder, MachineFile)) && File.Exists(Path.Combine(folder, CallsFile));

    private sealed record MachineFileContent(int Schema, RecordedMachine Machine, DateTimeOffset CapturedAt);
    private sealed record CallsFileContent(List<RecordedCall> Calls);
}

/// <summary>
/// Which kind of PC a recording came from. <see cref="ProductId"/> is the product identifier from the BIOS that names the model (not one unit),
/// so several recordings can share it. The other fields are kept so it can be checked which BIOS field holds it on each make.
/// </summary>
public sealed record RecordedMachine
{
    public string ProductId { get; init; } = "";
    public string Manufacturer { get; init; } = "";
    public string Model { get; init; } = "";
    public string SystemSku { get; init; } = "";
    public string SystemFamily { get; init; } = "";
    public string BaseBoardProduct { get; init; } = "";
    public string SmbiosUuid { get; init; } = "";
    public string BiosVersion { get; init; } = "";
    public string WindowsVersion { get; init; } = "";
    public string WindowsBuild { get; init; } = "";
    public string AppVersion { get; init; } = "";
    /// <summary>Whether the capture ran with administrator rights (some answers differ without them).</summary>
    public bool Elevated { get; init; }
    public string? Notes { get; init; }
}

/// <summary>
/// One answer. <see cref="Kind"/> says which source: <see cref="ProcessKind"/> (osquery, PowerShell, powercfg), <see cref="WmiKind"/>, or
/// <see cref="RegistryKind"/> (kept like WMI: <see cref="Namespace"/> is the root and view, <see cref="Query"/> what was read).
/// </summary>
public sealed record RecordedCall
{
    public const string ProcessKind = "process";
    public const string WmiKind = "wmi";
    public const string RegistryKind = "registry";

    public string Kind { get; init; } = "";

    // process
    /// <summary>The program's file name only (<c>osqueryi.exe</c>, <c>powercfg.exe</c>), lower case.</summary>
    public string? File { get; init; }
    public List<string>? Args { get; init; }
    public int? ExitCode { get; init; }
    public string? StdOut { get; init; }
    public string? StdErr { get; init; }
    public bool? TimedOut { get; init; }

    // wmi and registry
    public string? Namespace { get; init; }
    public string? Query { get; init; }
    public List<Dictionary<string, JsonElement>>? Rows { get; init; }
    public string? Error { get; init; }

    public static string FileKey(string fileName) => Path.GetFileName(fileName.Replace('\\', '/')).ToLowerInvariant();

    public ProcessResult ToProcessResult() => new(ExitCode ?? 0, StdOut ?? "", StdErr ?? "", TimedOut ?? false);

    public WmiQueryResult ToWmiResult() =>
        Error is not null ? WmiQueryResult.Failed(Namespace ?? "", Query ?? "", Error)
            : new(Namespace ?? "", Query ?? "", (Rows ?? []).Select(r => new WmiRow(r)).ToList());

    public static RecordedCall FromProcess(string fileName, IReadOnlyList<string> args, ProcessResult r) => new()
    {
        Kind = ProcessKind, File = FileKey(fileName), Args = [.. args], ExitCode = r.ExitCode, StdOut = r.StdOut, StdErr = r.StdErr,
        TimedOut = r.TimedOut ? true : null,
    };

    public static RecordedCall FromWmi(WmiQueryResult r) => new()
    {
        Kind = WmiKind, Namespace = r.Namespace, Query = r.Query, Error = r.Error,
        Rows = r.Rows?.Select(row => row.Values.ToDictionary(p => p.Key, p => p.Value)).ToList(),
    };

    public static RecordedCall FromRegistry(WmiQueryResult r) => FromWmi(r) with { Kind = RegistryKind };

    /// <summary>Short text naming the call, for test messages.</summary>
    public string Describe() => Kind is WmiKind or RegistryKind ? $"{Kind} {Namespace} \"{Query}\"" : $"{File} {string.Join(' ', Args ?? [])}";
}
