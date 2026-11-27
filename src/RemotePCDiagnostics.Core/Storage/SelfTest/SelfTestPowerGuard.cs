using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>The power settings the Agent changes while a drive self-test runs, behind an interface so restoring them can be tested.</summary>
public interface ISelfTestPowerSystem
{
    Guid? ActiveScheme();
    /// <summary>The setting's AC (<paramref name="ac"/> true) or DC value on <paramref name="scheme"/>, or null when the scheme doesn't have it.</summary>
    uint? Read(Guid scheme, Guid subgroup, Guid setting, bool ac);
    bool Write(Guid scheme, Guid subgroup, Guid setting, bool ac, uint value);
    /// <summary>Makes Windows apply changed values of the active scheme (<c>PowerSetActiveScheme</c>).</summary>
    void Apply(Guid scheme);
    /// <summary>Holds or releases a "system required" power request, so the idle timer doesn't sleep the PC.</summary>
    void HoldAwake(bool hold);
}

/// <summary>One power setting value as it was before the self-test changed it.</summary>
public sealed record SavedPowerValue(Guid Subgroup, Guid Setting, bool Ac, uint Value);

/// <summary>What the Agent changed, written before it changes anything, so a crash or restart still puts every value back.</summary>
public sealed record SelfTestPowerJournal(Guid Scheme, List<SavedPowerValue> Values, DateTimeOffset Since);

/// <summary>
/// Keeps the PC and its disks awake while a drive runs its own self-test: a self-test stops when the drive spins down, its link sleeps, or
/// the PC sleeps. Holds a system-required power request and sets the active plan's "Turn off hard disk after" to Never and AHCI link power
/// management to Active, on battery and plugged in. The previous values are journaled first (<see cref="ProtectedState"/>, Agent only) and
/// restored exactly when the last test ends, is cancelled, or the Agent next starts after a crash or restart.
/// </summary>
public sealed class SelfTestPowerGuard(ISelfTestPowerSystem power, string journalPath, ILogger? log = null)
{
    public const string JournalFile = "drive-selftest-power.json";
    public static readonly Guid DiskSubgroup = new("0012ee47-9041-4b5d-9b77-535fba8b1442");
    /// <summary>"Turn off hard disk after" (seconds; 0 is Never).</summary>
    public static readonly Guid DiskIdle = new("6738e2c4-e8a5-4a42-b16a-e040e769756e");
    /// <summary>"AHCI Link Power Management - HIPM/DIPM" (0 is Active: the link never sleeps).</summary>
    public static readonly Guid AhciLinkPower = new("0b2d69d7-a2a1-449c-9680-f91c70521c60");

    /// <summary>The settings changed and the value each is set to while a test runs.</summary>
    public static readonly IReadOnlyList<(Guid Subgroup, Guid Setting, uint During)> Targets =
    [
        (DiskSubgroup, DiskIdle, 0),
        (DiskSubgroup, AhciLinkPower, 0),
    ];

    private readonly object _gate = new();
    private bool _awake;

    /// <summary>True while the request is held or values are changed (a journal exists).</summary>
    public bool Holding { get { lock (_gate) return _awake || File.Exists(journalPath); } }

    /// <summary>Starts keeping the PC awake. Does nothing when it already does. Returns why it couldn't change the plan, or null.</summary>
    public string? Hold()
    {
        lock (_gate)
        {
            if (!_awake)
            {
                try { power.HoldAwake(true); _awake = true; }
                catch (Exception ex) { log.Warn($"[selftest] Couldn't hold the PC awake: {ex.Message}"); }
            }
            if (File.Exists(journalPath)) return null; // already changed (and journaled) for a test that is still running
            if (power.ActiveScheme() is not { } scheme) return "The active power plan couldn't be read.";
            var saved = new List<SavedPowerValue>();
            foreach (var (sub, setting, _) in Targets)
                foreach (var ac in new[] { true, false })
                    if (power.Read(scheme, sub, setting, ac) is { } value) saved.Add(new(sub, setting, ac, value));
            if (saved.Count == 0) return null;
            try { Save(new SelfTestPowerJournal(scheme, saved, DateTimeOffset.Now)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Without the journal a crash couldn't put them back, so they aren't changed at all.
                log.Warn($"[selftest] Couldn't journal the power settings, so they weren't changed: {ex.Message}");
                return "The power settings couldn't be saved first, so they weren't changed.";
            }
            foreach (var v in saved)
            {
                var during = Targets.First(t => t.Setting == v.Setting).During;
                if (v.Value != during && !power.Write(scheme, v.Subgroup, v.Setting, v.Ac, during))
                    log.Warn($"[selftest] Couldn't set power setting {v.Setting} ({(v.Ac ? "AC" : "DC")}) to {during}.");
            }
            power.Apply(scheme);
            log.Info($"[selftest] Holding the PC awake; disk idle and link power set to Never/Active on plan {scheme} ({saved.Count} values journaled).");
            return null;
        }
    }

    /// <summary>Puts every journaled value back on its plan and releases the request. Safe to call when nothing is held.</summary>
    public void Release()
    {
        lock (_gate)
        {
            if (_awake)
            {
                try { power.HoldAwake(false); } catch (Exception ex) { log.Warn($"[selftest] Couldn't release the power request: {ex.Message}"); }
                _awake = false;
            }
            if (Load() is not { } journal) return;
            var failed = 0;
            foreach (var v in journal.Values)
                if (!power.Write(journal.Scheme, v.Subgroup, v.Setting, v.Ac, v.Value)) failed++;
            if (power.ActiveScheme() == journal.Scheme) power.Apply(journal.Scheme);
            if (failed > 0)
            {
                // Kept, so the next release (or the next start of the Agent) tries again.
                log.Warn($"[selftest] {failed} of {journal.Values.Count} power settings couldn't be restored on plan {journal.Scheme}; will try again.");
                return;
            }
            try { File.Delete(journalPath); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"[selftest] Couldn't remove {journalPath}: {ex.Message}"); }
            log.Info($"[selftest] Power settings restored on plan {journal.Scheme} ({journal.Values.Count} values).");
        }
    }

    public SelfTestPowerJournal? Load()
    {
        try
        {
            return File.Exists(journalPath) ? JsonSerializer.Deserialize<SelfTestPowerJournal>(File.ReadAllText(journalPath)) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            log.Warn($"[selftest] Couldn't read {journalPath}: {ex.Message}");
            return null;
        }
    }

    private void Save(SelfTestPowerJournal journal)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(journalPath)!);
        var temp = journalPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(journal));
        File.Move(temp, journalPath, overwrite: true);
    }
}

/// <summary>The Agent's power plan and power request on Windows (powrprof, kernel32).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsSelfTestPowerSystem : ISelfTestPowerSystem, IDisposable
{
    private IntPtr _request;

    public Guid? ActiveScheme() => Areas.WindowsPowerPolicyReader.ReadActiveSchemeGuid();

    public uint? Read(Guid scheme, Guid subgroup, Guid setting, bool ac)
    {
        var err = ac ? PowerReadACValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, out var v)
                     : PowerReadDCValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, out v);
        return err == 0 ? v : null;
    }

    public bool Write(Guid scheme, Guid subgroup, Guid setting, bool ac, uint value) =>
        (ac ? PowerWriteACValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, value)
            : PowerWriteDCValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, value)) == 0;

    public void Apply(Guid scheme) => Areas.WindowsPowerPolicyReader.SetActiveScheme(scheme);

    public void HoldAwake(bool hold)
    {
        if (hold)
        {
            if (_request == IntPtr.Zero)
            {
                var context = new REASON_CONTEXT { Version = 0, Flags = 1, SimpleReasonString = "Remote PC Diagnostics: a drive is running its self-test" };
                var handle = PowerCreateRequest(ref context);
                if (handle == IntPtr.Zero || handle == new IntPtr(-1)) throw new InvalidOperationException($"PowerCreateRequest failed ({Marshal.GetLastWin32Error()}).");
                _request = handle;
            }
            if (!PowerSetRequest(_request, PowerRequestSystemRequired)) throw new InvalidOperationException($"PowerSetRequest failed ({Marshal.GetLastWin32Error()}).");
            return;
        }
        if (_request == IntPtr.Zero) return;
        PowerClearRequest(_request, PowerRequestSystemRequired);
        CloseHandle(_request);
        _request = IntPtr.Zero;
    }

    public void Dispose() => HoldAwake(false);

    private const int PowerRequestSystemRequired = 1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct REASON_CONTEXT
    {
        public uint Version;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string SimpleReasonString;
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr PowerCreateRequest(ref REASON_CONTEXT context);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool PowerSetRequest(IntPtr request, int type);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool PowerClearRequest(IntPtr request, int type);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("powrprof.dll")] private static extern uint PowerReadACValueIndex(IntPtr root, ref Guid scheme, ref Guid sub, ref Guid setting, out uint value);
    [DllImport("powrprof.dll")] private static extern uint PowerReadDCValueIndex(IntPtr root, ref Guid scheme, ref Guid sub, ref Guid setting, out uint value);
    [DllImport("powrprof.dll")] private static extern uint PowerWriteACValueIndex(IntPtr root, ref Guid scheme, ref Guid sub, ref Guid setting, uint value);
    [DllImport("powrprof.dll")] private static extern uint PowerWriteDCValueIndex(IntPtr root, ref Guid scheme, ref Guid sub, ref Guid setting, uint value);
}
