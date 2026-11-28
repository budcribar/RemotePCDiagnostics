using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary><see cref="AgentScripts.DriveSelfTest"/>: <paramref name="Verb"/> is list, status, start or abort; <paramref name="Disk"/> the
/// disk number (null for list); <paramref name="Kind"/> only for start.</summary>
public sealed record DriveSelfTestAction(string Verb, int? Disk, SelfTestKind? Kind) : AgentNativeAction;

/// <summary>The drives' self-test commands, as the Agent sends them (raw disk access needs administrator rights).</summary>
public interface ISelfTestDevices
{
    /// <summary>The disk numbers present (<c>\\.\PhysicalDriveN</c>).</summary>
    IReadOnlyList<int> Disks();
    SelfTestDriveAnswer Read(int disk);
    /// <summary>Asks the drive to start <paramref name="kind"/>; returns why it didn't, or null.</summary>
    string? Start(int disk, SelfTestProtocol protocol, SelfTestKind kind);
    /// <summary>Asks the drive to abort its running self-test; returns why it didn't, or null.</summary>
    string? Abort(int disk, SelfTestProtocol protocol);
}

/// <summary>
/// What the Agent does for <see cref="DriveSelfTestAction"/>, answering like its other changes (exit 0 with <see cref="SelfTestAnswer"/>
/// JSON, else exit 1 and why). Starting a test holds the PC awake (<see cref="SelfTestPowerGuard"/>); every answer that finds no drive
/// testing any more lets go of it, and so does <see cref="CheckIdle"/>, which the Agent calls on a timer in case the app went away.
/// </summary>
public sealed class AgentDriveSelfTest(ISelfTestDevices devices, SelfTestPowerGuard guard, ILogger? log = null)
{
    public const int MaxDisk = 63;
    private readonly object _gate = new();

    public static bool IsVerb(string? verb) => verb is "list" or "status" or "start" or "abort";

    public static bool IsDisk(string? text, out int disk) =>
        int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out disk) && disk is >= 0 and <= MaxDisk;

    public static SelfTestKind? ParseKind(string? text) => text switch { "short" => SelfTestKind.Short, "extended" => SelfTestKind.Extended, _ => null };

    public static string KindArg(SelfTestKind kind) => kind == SelfTestKind.Extended ? "extended" : "short";

    public ProcessResult Run(DriveSelfTestAction action)
    {
        lock (_gate)
        {
            try
            {
                switch (action.Verb)
                {
                    case "list":
                        return Answer(devices.Disks().Select(devices.Read).ToList(), allDrives: true);
                    case "status" when action.Disk is { } disk:
                        return Answer([devices.Read(disk)]);
                    case "start" when action.Disk is { } disk && action.Kind is { } kind:
                        return Start(disk, kind);
                    case "abort" when action.Disk is { } disk:
                        var before = SelfTestDecoder.Decode(devices.Read(disk));
                        if (before.Protocol == SelfTestProtocol.None) return Failed($"Disk {disk} can't be asked for a self-test.");
                        if (devices.Abort(disk, before.Protocol) is { } abortWhy) return Failed($"Disk {disk} didn't abort its self-test: {abortWhy}");
                        log.Info($"[selftest] Disk {disk}: abort sent.");
                        return Answer([devices.Read(disk)]);
                    default:
                        return Failed("That isn't a drive self-test request.");
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                return Failed(ex.Message);
            }
        }
    }

    private ProcessResult Start(int disk, SelfTestKind kind)
    {
        var state = SelfTestDecoder.Decode(devices.Read(disk));
        if (!state.Supported) return Failed($"Disk {disk} can't run a self-test: {state.Unsupported}");
        if (state.IsRunning) return Failed($"Disk {disk} is already running a self-test ({state.PercentDone ?? 0}% done).");
        var powerNote = guard.Hold();
        if (devices.Start(disk, state.Protocol, kind) is { } why)
        {
            ReleaseWhenIdle();
            return Failed($"Disk {disk} didn't start its {KindArg(kind)} self-test: {why}");
        }
        log.Info($"[selftest] Disk {disk} ({state.Model}): {KindArg(kind)} self-test started." + (powerNote is null ? "" : " " + powerNote));
        // The drive takes a moment to report the test; the app polls status from here, so don't release the power guard yet.
        return Answer([devices.Read(disk)], checkIdle: false);
    }

    /// <summary>Lets go of the PC's power settings when no drive is testing any more. Called on a timer while they are held.</summary>
    public void CheckIdle()
    {
        lock (_gate)
        {
            if (!guard.Holding) return;
            try { ReleaseWhenIdle(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                log.Warn($"[selftest] Couldn't check the drives: {ex.Message}");
            }
        }
    }

    private void ReleaseWhenIdle()
    {
        if (!devices.Disks().Select(d => SelfTestDecoder.Decode(devices.Read(d))).Any(s => s.IsRunning)) guard.Release();
    }

    private ProcessResult Answer(List<SelfTestDriveAnswer> drives, bool checkIdle = true, bool allDrives = false)
    {
        // Any answer that shows nothing testing lets the power settings go (a test ended, was aborted, or a reset stopped it).
        if (checkIdle && guard.Holding && !drives.Select(SelfTestDecoder.Decode).Any(s => s.IsRunning))
        {
            if (allDrives)
                guard.Release();
            else
            {
                var others = devices.Disks().Where(d => drives.All(x => x.Disk != d));
                if (!others.Select(d => SelfTestDecoder.Decode(devices.Read(d))).Any(s => s.IsRunning)) guard.Release();
            }
        }
        return new(0, new SelfTestAnswer { Drives = drives, KeepingAwake = guard.Holding }.ToJson(), "");
    }

    private static ProcessResult Failed(string why) => new(1, "", why);
}
