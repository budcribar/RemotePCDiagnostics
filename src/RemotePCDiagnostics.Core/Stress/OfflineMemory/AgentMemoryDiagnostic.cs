using System.Globalization;
using System.Management;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// <see cref="AgentScripts.MemoryDiagnostic"/>: the Windows boot memory test (Windows Memory Diagnostic), which runs from the boot manager
/// before Windows starts. <see cref="Verb"/> is status, schedule (with <see cref="Mix"/>), cancel or clear.
/// </summary>
public sealed record MemoryDiagnosticAction(string Verb, OfflineMemoryMix? Mix) : AgentNativeAction;

/// <summary>Which test mix the boot test runs. Windows' own default is Standard; Extended takes several times longer.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<OfflineMemoryMix>))]
public enum OfflineMemoryMix { Standard, Extended }

/// <summary>What the Agent answers for every <see cref="MemoryDiagnosticAction"/> (JSON on standard output).</summary>
public sealed record MemoryDiagnosticAnswer
{
    /// <summary>True when the boot manager will start the memory test at the next boot (it is first in the one-time boot sequence).</summary>
    public bool Scheduled { get; init; }
    /// <summary>When this app asked for the test (UTC); null when no request of this app's is open.</summary>
    public DateTimeOffset? RequestedAtUtc { get; init; }
    /// <summary>The mix this app asked for; null with no open request.</summary>
    public OfflineMemoryMix? Mix { get; init; }
    /// <summary>True when BitLocker protects the system drive; null when it couldn't be read.</summary>
    public bool? BitLockerOn { get; init; }
    /// <summary>True when the system drive has a recovery password (the 48-digit key) protector; null when it couldn't be read.</summary>
    public bool? RecoveryPassword { get; init; }
    /// <summary>True when Fast Startup is on (a Shut down then power on resumes Windows instead of a full boot); null when unknown.</summary>
    public bool? FastStartup { get; init; }
    /// <summary>When Windows last started (UTC), so the app can tell a restart happened since the request.</summary>
    public DateTimeOffset? BootTimeUtc { get; init; }

    private static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public string ToJson() => JsonSerializer.Serialize(this, Options);

    public static MemoryDiagnosticAnswer? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<MemoryDiagnosticAnswer>(json, Options); }
        catch (JsonException) { return null; }
    }
}

/// <summary>The boot configuration store (<c>bcdedit.exe</c>), behind an interface so the Agent's steps can be tested.</summary>
public interface IBootConfig
{
    /// <summary>Runs bcdedit with these arguments.</summary>
    ProcessResult Run(IReadOnlyList<string> args);
}

/// <summary>Readings the warnings need, read with the Agent's administrator rights.</summary>
public interface IMemoryDiagnosticMachine
{
    bool? BitLockerOn();
    bool? HasRecoveryPassword();
    bool? FastStartupOn();
    DateTimeOffset? BootTimeUtc();
}

/// <summary>
/// The Agent's side of the boot memory test. Scheduling puts <c>{memdiag}</c> first in the boot manager's one-time boot sequence
/// (what Windows Memory Diagnostic's "Check for problems the next time I start my computer" does) and sets its test mix. The test mix it
/// found is kept in <see cref="StateFileName"/> and put back once the test has run (the boot sequence entry is used up at that boot),
/// when the request is cancelled, or when the Agent starts after the test ran.
/// </summary>
public static class AgentMemoryDiagnostic
{
    /// <summary>The boot manager's memory test entry.</summary>
    public const string MemDiagId = "{b2721d73-1db4-4c62-bf78-c548a880142d}";
    public const string StateFileName = "memdiag.json";

    public static readonly IReadOnlyList<string> Verbs = ["status", "schedule", "cancel", "clear"];

    public static bool IsVerb(string? verb) => verb is not null && Verbs.Contains(verb, StringComparer.Ordinal);

    public static OfflineMemoryMix? ParseMix(string? mix) => mix switch
    {
        "standard" => OfflineMemoryMix.Standard,
        "extended" => OfflineMemoryMix.Extended,
        _ => null,
    };

    public static string MixArg(OfflineMemoryMix mix) => mix == OfflineMemoryMix.Extended ? "extended" : "standard";

    /// <summary>What the Agent keeps between the request and the test (in the protected state folder).</summary>
    public sealed record SavedRequest(DateTimeOffset RequestedAtUtc, OfflineMemoryMix Mix, string? PreviousTestMix, bool Restored = false);

    public static ProcessResult Run(IBootConfig bcd, IMemoryDiagnosticMachine machine, string statePath, MemoryDiagnosticAction action, DateTimeOffset? now = null)
    {
        try
        {
            switch (action.Verb)
            {
                case "status":
                    RestoreIfRan(bcd, statePath);
                    return Answer(bcd, machine, statePath);

                case "schedule":
                    if (action.Mix is not { } mix) return WindowsAgentNativeOps.Failed("Choose the standard or extended test.");
                    return Schedule(bcd, machine, statePath, mix, now ?? DateTimeOffset.UtcNow);

                case "cancel":
                    var saved = Read(statePath);
                    var removed = bcd.Run(["/bootsequence", MemDiagId, "/remove"]);
                    if (saved is { Restored: false }) RestoreTestMix(bcd, saved.PreviousTestMix);
                    Delete(statePath);
                    if (IsScheduled(bcd) == true)
                        return WindowsAgentNativeOps.Failed("Windows still has the memory test set for the next start: " + Why(removed));
                    return Answer(bcd, machine, statePath);

                case "clear":
                    RestoreIfRan(bcd, statePath);
                    if (IsScheduled(bcd) != true) Delete(statePath);
                    return Answer(bcd, machine, statePath);

                default:
                    return WindowsAgentNativeOps.Failed("That isn't a memory test request.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return WindowsAgentNativeOps.Failed("The memory test request couldn't be saved: " + ex.Message);
        }
    }

    private static ProcessResult Schedule(IBootConfig bcd, IMemoryDiagnosticMachine machine, string statePath, OfflineMemoryMix mix, DateTimeOffset now)
    {
        var enumerated = bcd.Run(["/enum", MemDiagId, "/v"]);
        if (enumerated.ExitCode != 0)
            return WindowsAgentNativeOps.Failed("This PC's boot manager has no Windows memory test: " + Why(enumerated));

        // A request of ours still open keeps the test mix it found first, so cancelling puts back what was there before any of ours.
        var open = Read(statePath);
        var previous = open is { Restored: false } ? open.PreviousTestMix : ReadValue(enumerated.StdOut, "testmix");
        Write(statePath, new SavedRequest(now, mix, previous));

        var set = mix == OfflineMemoryMix.Extended
            ? bcd.Run(["/set", MemDiagId, "testmix", "extended"])
            : previous is null ? new ProcessResult(0, "", "") : bcd.Run(["/deletevalue", MemDiagId, "testmix"]);
        if (set.ExitCode != 0)
        {
            RestoreTestMix(bcd, previous);
            Delete(statePath);
            return WindowsAgentNativeOps.Failed($"Windows didn't take the {MixArg(mix)} test: " + Why(set));
        }

        var added = bcd.Run(["/bootsequence", MemDiagId, "/addfirst"]);
        if (added.ExitCode != 0 || IsScheduled(bcd) != true)
        {
            RestoreTestMix(bcd, previous);
            Delete(statePath);
            return WindowsAgentNativeOps.Failed("Windows didn't set the memory test for the next start: " + Why(added));
        }
        return Answer(bcd, machine, statePath);
    }

    /// <summary>
    /// Puts the test mix back once the boot sequence no longer holds the memory test (it ran, or someone removed it), keeping the request
    /// so the app can still match the result to it. Run by every status read and when the Agent starts.
    /// </summary>
    public static void RestoreIfRan(IBootConfig bcd, string statePath)
    {
        if (Read(statePath) is not { Restored: false } saved) return;
        if (IsScheduled(bcd) is not false) return;
        RestoreTestMix(bcd, saved.PreviousTestMix);
        Write(statePath, saved with { Restored = true });
    }

    private static ProcessResult Answer(IBootConfig bcd, IMemoryDiagnosticMachine machine, string statePath)
    {
        var saved = Read(statePath);
        var answer = new MemoryDiagnosticAnswer
        {
            Scheduled = IsScheduled(bcd) == true,
            RequestedAtUtc = saved?.RequestedAtUtc,
            Mix = saved?.Mix,
            BitLockerOn = Safe(machine.BitLockerOn),
            RecoveryPassword = Safe(machine.HasRecoveryPassword),
            FastStartup = Safe(machine.FastStartupOn),
            BootTimeUtc = Safe(machine.BootTimeUtc),
        };
        return new ProcessResult(0, answer.ToJson(), "");
    }

    private static T? Safe<T>(Func<T?> read)
    {
        try { return read(); }
        catch { return default; }
    }

    private static void RestoreTestMix(IBootConfig bcd, string? previous)
    {
        if (previous is { Length: > 0 } && IsMixValue(previous)) bcd.Run(["/set", MemDiagId, "testmix", previous.ToLowerInvariant()]);
        else bcd.Run(["/deletevalue", MemDiagId, "testmix"]);
    }

    /// <summary>The test mixes bcdedit takes (Standard is the default, with no value set).</summary>
    public static bool IsMixValue(string value) => value.Equals("basic", StringComparison.OrdinalIgnoreCase) || value.Equals("extended", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when <c>{bootmgr}</c>'s one-time boot sequence lists the memory test; null when the store couldn't be read.</summary>
    public static bool? IsScheduled(IBootConfig bcd)
    {
        var r = bcd.Run(["/enum", "{bootmgr}", "/v"]);
        if (r.ExitCode != 0) return null;
        return BootSequenceHasMemDiag(r.StdOut);
    }

    /// <summary>
    /// Reads the <c>bootsequence</c> element of <c>bcdedit /enum {bootmgr} /v</c>. Its value lists one entry per line, the first on the
    /// element's own line and the rest indented under it. Element names are not translated; with /v entries are GUIDs.
    /// </summary>
    public static bool BootSequenceHasMemDiag(string output)
    {
        var inSequence = false;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) { inSequence = false; continue; }
            var indented = char.IsWhiteSpace(line[0]);
            var text = line.Trim();
            if (!indented)
            {
                var (name, value) = SplitElement(text);
                inSequence = name.Equals("bootsequence", StringComparison.OrdinalIgnoreCase);
                if (inSequence && IsMemDiag(value)) return true;
            }
            else if (inSequence && IsMemDiag(text)) return true;
        }
        return false;
    }

    private static bool IsMemDiag(string value) =>
        value.Equals(MemDiagId, StringComparison.OrdinalIgnoreCase) || value.Equals("{memdiag}", StringComparison.OrdinalIgnoreCase);

    /// <summary>The value of element <paramref name="name"/> in bcdedit's listing, or null when it isn't set.</summary>
    public static string? ReadValue(string output, string name)
    {
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0 || char.IsWhiteSpace(line[0])) continue;
            var (key, value) = SplitElement(line.Trim());
            if (key.Equals(name, StringComparison.OrdinalIgnoreCase)) return value.Length > 0 ? value : null;
        }
        return null;
    }

    private static (string Name, string Value) SplitElement(string text)
    {
        var space = text.IndexOfAny([' ', '\t']);
        return space < 0 ? (text, "") : (text[..space], text[space..].Trim());
    }

    private static string Why(ProcessResult r)
    {
        var text = (r.StdErr.Trim().Length > 0 ? r.StdErr : r.StdOut).Trim();
        return text.Length > 0 ? text : $"bcdedit exited with code {r.ExitCode.ToString(CultureInfo.InvariantCulture)}.";
    }

    private static readonly JsonSerializerOptions StateJson = new() { WriteIndented = true };

    public static SavedRequest? Read(string path)
    {
        if (!File.Exists(path)) return null;
        try { return JsonSerializer.Deserialize<SavedRequest>(File.ReadAllText(path), StateJson); }
        catch (JsonException) { return null; }
    }

    private static void Write(string path, SavedRequest saved)
    {
        if (Path.GetDirectoryName(path) is { Length: > 0 } dir) Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(saved, StateJson));
    }

    private static void Delete(string path)
    {
        if (File.Exists(path)) File.Delete(path);
    }
}

/// <summary>The real boot store and readings on the PC (in the Agent).</summary>
[SupportedOSPlatform("windows")]
public static class AgentMemoryDiagnosticHost
{
    public static string StatePath() => ProtectedState.PathFor(AgentMemoryDiagnostic.StateFileName);

    public static ProcessResult Run(MemoryDiagnosticAction action) =>
        AgentMemoryDiagnostic.Run(new WindowsBootConfig(), new WindowsMemoryDiagnosticMachine(), StatePath(), action);

    /// <summary>At Agent start (usually just after the boot the test ran in): put the test mix back. Never throws.</summary>
    public static void RecoverAtStart(ILogger? log = null)
    {
        try
        {
            if (!File.Exists(StatePath())) return;
            AgentMemoryDiagnostic.RestoreIfRan(new WindowsBootConfig(), StatePath());
        }
        catch (Exception ex) { log.Warn($"Memory test: couldn't put the boot test settings back: {ex.Message}"); }
    }

    private sealed class WindowsBootConfig : IBootConfig
    {
        public ProcessResult Run(IReadOnlyList<string> args)
        {
            var psi = new System.Diagnostics.ProcessStartInfo(Areas.SystemCommandRunner.SystemTool("bcdedit.exe"))
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = System.Diagnostics.Process.Start(psi) ?? throw new IOException("bcdedit didn't start.");
            var stdout = p.StandardOutput.ReadToEndAsync();
            var stderr = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(30_000))
            {
                try { p.Kill(); } catch { }
                return new ProcessResult(-1, "", "bcdedit didn't answer in time.", TimedOut: true);
            }
            return new ProcessResult(p.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
        }
    }

    private sealed class WindowsMemoryDiagnosticMachine : IMemoryDiagnosticMachine
    {
        private const string VolumeNamespace = @"root\CIMV2\Security\MicrosoftVolumeEncryption";

        private static ManagementObject? SystemVolume()
        {
            var drive = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:").TrimEnd('\\');
            using var searcher = new ManagementObjectSearcher(new ManagementScope(VolumeNamespace),
                new ObjectQuery($"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter = '{drive.Replace("'", "")}'"));
            foreach (ManagementObject o in searcher.Get()) return o;
            return null;
        }

        public bool? BitLockerOn()
        {
            using var v = SystemVolume();
            if (v is null) return false;
            using var outArgs = v.InvokeMethod("GetProtectionStatus", null, null);
            return Convert.ToUInt32(outArgs?["ProtectionStatus"] ?? 0u, CultureInfo.InvariantCulture) == 1;
        }

        public bool? HasRecoveryPassword()
        {
            using var v = SystemVolume();
            if (v is null) return null;
            using var inArgs = v.GetMethodParameters("GetKeyProtectors");
            inArgs["KeyProtectorType"] = 3u; // numerical password
            using var outArgs = v.InvokeMethod("GetKeyProtectors", inArgs, null);
            return outArgs?["VolumeKeyProtectorID"] is string[] { Length: > 0 };
        }

        public bool? FastStartupOn()
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Power");
            if (k?.GetValue("HiberbootEnabled") is not int on) return null;
            using var h = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Power");
            // Fast Startup needs hibernation; with hibernation off the setting does nothing.
            return on == 1 && h?.GetValue("HibernateEnabled") is not 0;
        }

        public DateTimeOffset? BootTimeUtc() => DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
    }
}
