using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// One of the Agent's own changes that it makes in C#, in its own process, instead of running PowerShell. <see cref="AgentScripts.Plan"/>
/// builds it from the app's request after checking the arguments; <see cref="IAgentNativeOps"/> carries it out. Results keep the shape the
/// PowerShell versions had (exit code 0 on success, the same JSON on standard output), so the app reads them the same way.
/// </summary>
public abstract record AgentNativeAction;

/// <summary>Ends every process named <paramref name="ProcessName"/> (no ".exe"); prints <c>{"FreedMemoryBytes":n}</c>.</summary>
public sealed record StopProcessAction(string ProcessName) : AgentNativeAction;

/// <summary>Deletes files older than a day from the temp folders and empties the Recycle Bin; prints <c>{"RemovedFiles":n,"FreedBytes":n}</c>.</summary>
public sealed record CleanTempAction : AgentNativeAction;

/// <summary>Retrims each volume in <paramref name="DriveLetters"/> ("C", "DE"), as <c>Optimize-Volume -ReTrim</c> does.</summary>
public sealed record OptimizeVolumeAction(string DriveLetters) : AgentNativeAction;

/// <summary>Registers (or replaces) the sign-in task <paramref name="TaskName"/> from <paramref name="TaskXml"/> (<see cref="ResumeTaskXml"/>).</summary>
public sealed record RegisterTaskAction(string TaskName, string User, string TaskXml) : AgentNativeAction;

/// <summary>Removes the task <paramref name="TaskName"/>; a missing task is fine, and it fails only when the task is still there afterwards.</summary>
public sealed record RemoveTaskAction(string TaskName) : AgentNativeAction;

/// <summary>What the Agent does for an <see cref="AdminPipeScript"/>: PowerShell it built (<see cref="Script"/>) or a change it makes itself (<see cref="Native"/>).</summary>
public sealed record AgentPlan(string? Script, AgentNativeAction? Native);

/// <summary>Carries out <see cref="AgentNativeAction"/>s. <see cref="WindowsAgentNativeOps"/> on the PC; tests use a fake.</summary>
public interface IAgentNativeOps
{
    Task<ProcessResult> RunAsync(AgentNativeAction action, CancellationToken ct);
}

public static class AgentNativeRunner
{
    /// <summary>
    /// Runs <paramref name="action"/> with <paramref name="ops"/>, giving up after <paramref name="timeout"/> (a result with
    /// <see cref="ProcessResult.TimedOut"/> set; the work may still finish in the background, as a PowerShell script killed late would have).
    /// </summary>
    public static async Task<ProcessResult> RunAsync(IAgentNativeOps ops, AgentNativeAction action, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            return await Task.Run(() => ops.RunAsync(action, ct), ct).WaitAsync(timeout, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            return new ProcessResult(-1, "", "The change timed out.", TimedOut: true);
        }
    }
}

/// <summary>The sign-in task as Task Scheduler XML: the same task <see cref="ResumeTaskScript.Register"/> makes with PowerShell.</summary>
public static class ResumeTaskXml
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    /// <summary>
    /// At <paramref name="user"/>'s sign-in, runs <paramref name="execute"/> <paramref name="arguments"/> in <paramref name="workDir"/>, on
    /// battery too and without a time limit, until <paramref name="endBoundary"/> (local time) when there is one. <paramref name="highest"/>
    /// only for the Agent's launcher.
    /// </summary>
    public static string Build(string execute, string arguments, string? workDir, string user, DateTimeOffset? endBoundary, bool highest)
    {
        var trigger = new XElement(Ns + "LogonTrigger");
        if (endBoundary is { } end)
            trigger.Add(new XElement(Ns + "EndBoundary", end.LocalDateTime.ToString("s", CultureInfo.InvariantCulture)));
        trigger.Add(new XElement(Ns + "Enabled", "true"), new XElement(Ns + "UserId", user));

        var exec = new XElement(Ns + "Exec", new XElement(Ns + "Command", execute));
        if (!string.IsNullOrEmpty(arguments)) exec.Add(new XElement(Ns + "Arguments", arguments));
        if (!string.IsNullOrEmpty(workDir)) exec.Add(new XElement(Ns + "WorkingDirectory", workDir));

        var task = new XElement(Ns + "Task", new XAttribute("version", "1.2"),
            new XElement(Ns + "Triggers", trigger),
            new XElement(Ns + "Principals",
                new XElement(Ns + "Principal", new XAttribute("id", "Author"),
                    new XElement(Ns + "UserId", user),
                    new XElement(Ns + "LogonType", "InteractiveToken"),
                    new XElement(Ns + "RunLevel", highest ? "HighestAvailable" : "LeastPrivilege"))),
            new XElement(Ns + "Settings",
                new XElement(Ns + "MultipleInstancesPolicy", "IgnoreNew"),
                new XElement(Ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(Ns + "StopIfGoingOnBatteries", "false"),
                new XElement(Ns + "Enabled", "true"),
                new XElement(Ns + "ExecutionTimeLimit", "PT0S")),
            new XElement(Ns + "Actions", new XAttribute("Context", "Author"), exec));
        return task.ToString(SaveOptions.DisableFormatting);
    }
}

/// <summary>Temporary files the clean-up removes: older than a day, never through a junction or symbolic link.</summary>
public static class TempFileCleaner
{
    public static readonly TimeSpan MinAge = TimeSpan.FromHours(24);

    /// <summary>The Agent's own temp folder and %SystemRoot%\Temp, the folders the PowerShell version cleaned.</summary>
    public static IReadOnlyList<string> DefaultRoots()
    {
        var roots = new List<string>();
        var temp = Path.GetTempPath();
        if (!string.IsNullOrEmpty(temp)) roots.Add(temp);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(windows)) roots.Add(Path.Combine(windows, "Temp"));
        return roots;
    }

    /// <summary>Deletes files under <paramref name="roots"/> last written before <paramref name="cutoff"/>; returns how many went and their size.</summary>
    public static (int Files, long Bytes) Clean(IEnumerable<string> roots, DateTime cutoff, CancellationToken ct = default)
    {
        var files = 0;
        var bytes = 0L;
        var pending = new Stack<DirectoryInfo>();
        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var dir = new DirectoryInfo(root);
            if (dir.Exists && !dir.Attributes.HasFlag(FileAttributes.ReparsePoint)) pending.Push(dir);
        }
        while (pending.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var dir = pending.Pop();
            IEnumerable<FileSystemInfo> entries;
            try { entries = dir.EnumerateFileSystemInfos().ToList(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            foreach (var entry in entries)
            {
                if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;
                if (entry is DirectoryInfo sub) { pending.Push(sub); continue; }
                if (entry is not FileInfo file || file.LastWriteTime >= cutoff) continue;
                var length = file.Length;
                try
                {
                    if (file.IsReadOnly) file.IsReadOnly = false;
                    file.Delete();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
                if (!File.Exists(file.FullName)) { files++; bytes += length; }
            }
        }
        return (files, bytes);
    }
}

/// <summary>The Agent's C# changes on Windows. Each answers like the PowerShell it replaces: exit 0 and JSON when it worked, else exit 1 and why.</summary>
public sealed partial class WindowsAgentNativeOps : IAgentNativeOps
{
    public static readonly WindowsAgentNativeOps Instance = new();

    public Task<ProcessResult> RunAsync(AgentNativeAction action, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Task.FromResult(Failed("This change needs Windows."));
        try
        {
            return action switch
            {
                StopProcessAction stop => Task.FromResult(StopProcess(stop.ProcessName)),
                CleanTempAction => Task.FromResult(CleanTemp(ct)),
                OptimizeVolumeAction optimize => Task.FromResult(OptimizeVolumes(optimize.DriveLetters)),
                RegisterTaskAction register => Task.FromResult(RegisterTask(register)),
                RemoveTaskAction remove => Task.FromResult(RemoveTask(remove.TaskName)),
                _ => RunOtherAsync(action, ct),
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return Task.FromResult(Failed(ex.Message));
        }
    }

    /// <summary>Actions added in other files of this partial class; this one knows none.</summary>
    private Task<ProcessResult> RunOtherAsync(AgentNativeAction action, CancellationToken ct)
    {
        var result = Failed($"The Agent doesn't know how to make the change '{action.GetType().Name}'.");
        RunMore(action, ct, ref result);
        return Task.FromResult(result);
    }

    /// <summary>Hook for another file of this partial class to handle more actions (it sets <paramref name="result"/>).</summary>
    partial void RunMore(AgentNativeAction action, CancellationToken ct, ref ProcessResult result);

    public static ProcessResult Ok(object? json = null) => new(0, json is null ? "" : JsonSerializer.Serialize(json), "");
    public static ProcessResult Failed(string why) => new(1, "", why);

    private static ProcessResult StopProcess(string name)
    {
        var processes = System.Diagnostics.Process.GetProcessesByName(name);
        if (processes.Length == 0) return Failed($"No process named '{name}' is running.");
        long memory = 0;
        string? failure = null;
        foreach (var p in processes)
        {
            using (p)
            {
                try
                {
                    if (p.HasExited) continue;
                    var ws = p.WorkingSet64;
                    p.Kill();
                    memory += ws;
                }
                catch (InvalidOperationException) { } // it exited on its own meanwhile
                catch (Exception ex) { failure ??= $"Couldn't stop '{name}' (process {SafeId(p)}): {ex.Message}"; }
            }
        }
        return failure is null ? Ok(new { FreedMemoryBytes = memory }) : Failed(failure);
    }

    private static int SafeId(System.Diagnostics.Process p) { try { return p.Id; } catch { return 0; } }

    [SupportedOSPlatform("windows")]
    private static ProcessResult CleanTemp(CancellationToken ct)
    {
        var (files, bytes) = TempFileCleaner.Clean(TempFileCleaner.DefaultRoots(), DateTime.Now - TempFileCleaner.MinAge, ct);
        // Like Clear-RecycleBin -Force: no prompt, no progress, no sound. An empty bin answers with an error, which doesn't matter.
        try { _ = SHEmptyRecycleBin(IntPtr.Zero, null, SherbNoConfirmation | SherbNoProgressUi | SherbNoSound); } catch { }
        return Ok(new { RemovedFiles = files, FreedBytes = bytes });
    }

    private const uint SherbNoConfirmation = 0x1, SherbNoProgressUi = 0x2, SherbNoSound = 0x4;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBin(IntPtr hwnd, string? rootPath, uint flags);

    [SupportedOSPlatform("windows")]
    private static ProcessResult OptimizeVolumes(string letters)
    {
        var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Storage");
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_Volume"));
        var volumes = searcher.Get().Cast<ManagementObject>().ToList();
        try
        {
            foreach (var letter in letters)
            {
                var volume = volumes.FirstOrDefault(v => DriveLetterOf(v) == letter);
                if (volume is null) return Failed($"There's no volume {letter}:.");
                using var input = volume.GetMethodParameters("Optimize");
                input["ReTrim"] = true;
                using var output = volume.InvokeMethod("Optimize", input, null);
                var code = Convert.ToUInt32(output?["ReturnValue"] ?? 1u, CultureInfo.InvariantCulture);
                if (code != 0) return Failed($"Windows couldn't retrim {letter}: (error {code}).");
            }
            return Ok();
        }
        finally
        {
            foreach (var v in volumes) v.Dispose();
        }
    }

    /// <summary>MSFT_Volume.DriveLetter is a char16: a char, or its number, and 0 for a volume without a letter.</summary>
    [SupportedOSPlatform("windows")]
    private static char DriveLetterOf(ManagementObject volume) => volume["DriveLetter"] switch
    {
        char c => char.ToUpperInvariant(c),
        ushort n => char.ToUpperInvariant((char)n),
        string { Length: 1 } s => char.ToUpperInvariant(s[0]),
        _ => '\0',
    };

    [SupportedOSPlatform("windows")]
    private static ProcessResult RegisterTask(RegisterTaskAction task)
    {
        Platform.WindowsTaskScheduler.RegisterTask(task.TaskName, task.User, task.TaskXml);
        return Ok();
    }

    [SupportedOSPlatform("windows")]
    private static ProcessResult RemoveTask(string name) =>
        Platform.WindowsTaskScheduler.RemoveTask(name) ? Ok() : Failed($"The task '{name}' is still there.");
}
