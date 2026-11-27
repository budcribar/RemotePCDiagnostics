using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// In-process Task Scheduler 2.0 (<c>Schedule.Service</c> COM) operations, replacing PowerShell's
/// <c>Get-ScheduledTask</c>, <c>Enable/Disable-ScheduledTask</c>, and <c>Register/Unregister-ScheduledTask</c>.
/// </summary>
public static class WindowsTaskScheduler
{
    // Task Scheduler 2.0 constants from taskschd.h.
    private const int TaskCreateOrUpdate = 6;
    private const int TaskLogonInteractiveToken = 3;
    private const int TaskEnumHidden = 1;
    private const int TaskStateDisabled = 1;
    private const int ErrorFileNotFound = unchecked((int)0x80070002);
    private const int ErrorPathNotFound = unchecked((int)0x80070003);

    /// <summary>Maps Task Scheduler <c>TASK_STATE</c> enum values to the same names PowerShell's <c>Get-ScheduledTask</c> prints.</summary>
    public static string FormatTaskState(int state) => state switch
    {
        1 => "Disabled",
        2 => "Queued",
        3 => "Ready",
        4 => "Running",
        _ => "Unknown",
    };

    /// <summary>Normalizes a folder path for <c>ITaskService.GetFolder</c> (root is <c>"\\"</c>, subfolders have no trailing slash).</summary>
    public static string NormalizeFolder(string? folderPath)
    {
        if (string.IsNullOrWhiteSpace(folderPath)) return "\\";
        var trimmed = folderPath.Trim();
        if (trimmed == "\\") return "\\";
        return trimmed.TrimEnd('\\');
    }

    /// <summary>Registers (or replaces) a task in the root folder using Task Scheduler XML.</summary>
    [SupportedOSPlatform("windows")]
    public static void RegisterTask(string taskName, string user, string taskXml)
    {
        object? serviceObj = null;
        object? rootObj = null;
        try
        {
            serviceObj = ConnectService();
            dynamic service = serviceObj;
            rootObj = service.GetFolder("\\");
            dynamic root = rootObj;
            root.RegisterTask(taskName, taskXml, TaskCreateOrUpdate, user, null, TaskLogonInteractiveToken, null);
        }
        finally
        {
            SafeReleaseCom(rootObj);
            SafeReleaseCom(serviceObj);
        }
    }

    /// <summary>Removes a task from the root folder. Returns true if it is gone (or never existed), false if it still exists.</summary>
    [SupportedOSPlatform("windows")]
    public static bool RemoveTask(string taskName)
    {
        object? serviceObj = null;
        object? rootObj = null;
        object? checkObj = null;
        try
        {
            serviceObj = ConnectService();
            dynamic service = serviceObj;
            rootObj = service.GetFolder("\\");
            dynamic root = rootObj;
            // Through dynamic COM, a missing task can surface as FileNotFoundException (0x80070002) instead of COMException.
            try { root.DeleteTask(taskName, 0); }
            catch (Exception ex) when (IsNotFound(ex)) { }

            try
            {
                checkObj = root.GetTask(taskName);
                return false;
            }
            catch (Exception ex) when (IsNotFound(ex))
            {
                return true;
            }
        }
        finally
        {
            SafeReleaseCom(checkObj);
            SafeReleaseCom(rootObj);
            SafeReleaseCom(serviceObj);
        }
    }

    /// <summary>A missing task or folder, however COM reports it.</summary>
    internal static bool IsNotFound(Exception ex) =>
        ex is FileNotFoundException or DirectoryNotFoundException || ex.HResult is ErrorFileNotFound or ErrorPathNotFound;

    /// <summary>Returns the task's state ("Ready", "Disabled", "Running", "Queued", "Unknown") or "Missing" when not found.</summary>
    [SupportedOSPlatform("windows")]
    public static string GetTaskState(string folderPath, string taskName)
    {
        object? serviceObj = null;
        object? folderObj = null;
        object? taskObj = null;
        try
        {
            serviceObj = ConnectService();
            dynamic service = serviceObj;
            folderObj = service.GetFolder(NormalizeFolder(folderPath));
            dynamic folder = folderObj;
            taskObj = folder.GetTask(taskName);
            dynamic task = taskObj;
            int state = (int)task.State;
            return FormatTaskState(state);
        }
        catch (COMException ex) when (ex.HResult is ErrorFileNotFound or ErrorPathNotFound)
        {
            return "Missing";
        }
        catch (FileNotFoundException)
        {
            return "Missing";
        }
        finally
        {
            SafeReleaseCom(taskObj);
            SafeReleaseCom(folderObj);
            SafeReleaseCom(serviceObj);
        }
    }

    /// <summary>Enables or disables a scheduled task, then reads back and returns its state string (or "Missing").</summary>
    [SupportedOSPlatform("windows")]
    public static string SetTaskEnabled(string folderPath, string taskName, bool enabled)
    {
        object? serviceObj = null;
        object? folderObj = null;
        object? taskObj = null;
        try
        {
            serviceObj = ConnectService();
            dynamic service = serviceObj;
            folderObj = service.GetFolder(NormalizeFolder(folderPath));
            dynamic folder = folderObj;
            taskObj = folder.GetTask(taskName);
            dynamic task = taskObj;
            task.Enabled = enabled;
            int state = (int)task.State;
            return FormatTaskState(state);
        }
        finally
        {
            SafeReleaseCom(taskObj);
            SafeReleaseCom(folderObj);
            SafeReleaseCom(serviceObj);
        }
    }

    /// <summary>Sets <c>Settings.WakeToRun</c> on a scheduled task without disabling the task itself. Returns false if the task doesn't exist.</summary>
    [SupportedOSPlatform("windows")]
    public static bool SetTaskWakeToRun(string folderPath, string taskName, bool wakeToRun)
    {
        object? serviceObj = null;
        object? folderObj = null;
        object? taskObj = null;
        object? defObj = null;
        object? registeredObj = null;
        try
        {
            serviceObj = ConnectService();
            dynamic service = serviceObj;
            folderObj = service.GetFolder(NormalizeFolder(folderPath));
            dynamic folder = folderObj;
            taskObj = folder.GetTask(taskName);
            dynamic task = taskObj;
            defObj = task.Definition;
            dynamic def = defObj;
            def.Settings.WakeToRun = wakeToRun;
            int logonType = (int)def.Principal.LogonType;
            // TASK_CREATE_OR_UPDATE = 6; passing null user/password preserves the task's existing principal.
            registeredObj = folder.RegisterTaskDefinition(taskName, def, 6, null, null, logonType, null);
            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        finally
        {
            SafeReleaseCom(registeredObj);
            SafeReleaseCom(defObj);
            SafeReleaseCom(taskObj);
            SafeReleaseCom(folderObj);
            SafeReleaseCom(serviceObj);
        }
    }

    /// <summary>
    /// Counts non-disabled tasks across all folders except those under <paramref name="excludedFolderPrefix"/>
    /// (for example <c>"\\Microsoft\\Windows\\"</c>, matching PowerShell's <c>-notlike '\Microsoft\Windows\*'</c>).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static int CountActiveTasksExcluding(string excludedFolderPrefix, CancellationToken ct = default)
    {
        var excludedNormalized = excludedFolderPrefix.TrimEnd('\\');
        object? serviceObj = null;
        object? rootObj = null;
        try
        {
            serviceObj = ConnectService();
            dynamic service = serviceObj;
            rootObj = service.GetFolder("\\");
            return CountInFolder(rootObj, excludedNormalized, ct);
        }
        finally
        {
            SafeReleaseCom(rootObj);
            SafeReleaseCom(serviceObj);
        }
    }

    [SupportedOSPlatform("windows")]
    private static int CountInFolder(object folderObj, string excludedPrefix, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        dynamic folder = folderObj;
        string path = (string)(folder.Path ?? "\\");
        if (IsExcludedFolder(path, excludedPrefix))
            return 0;

        var count = 0;
        object? tasksObj = null;
        try
        {
            tasksObj = folder.GetTasks(TaskEnumHidden);
            dynamic tasks = tasksObj;
            int taskCount = (int)tasks.Count;
            for (var i = 1; i <= taskCount; i++)
            {
                ct.ThrowIfCancellationRequested();
                object? taskObj = null;
                try
                {
                    taskObj = tasks[i];
                    dynamic task = taskObj;
                    int state = (int)task.State;
                    if (state != TaskStateDisabled)
                        count++;
                }
                finally { SafeReleaseCom(taskObj); }
            }
        }
        finally { SafeReleaseCom(tasksObj); }

        object? subFoldersObj = null;
        try
        {
            subFoldersObj = folder.GetFolders(0);
            dynamic subFolders = subFoldersObj;
            int folderCount = (int)subFolders.Count;
            for (var i = 1; i <= folderCount; i++)
            {
                ct.ThrowIfCancellationRequested();
                object? subObj = null;
                try
                {
                    subObj = subFolders[i];
                    count += CountInFolder(subObj, excludedPrefix, ct);
                }
                finally { SafeReleaseCom(subObj); }
            }
        }
        finally { SafeReleaseCom(subFoldersObj); }

        return count;
    }

    internal static bool IsExcludedFolder(string folderPath, string excludedPrefix)
    {
        if (string.IsNullOrEmpty(excludedPrefix)) return false;
        var norm = folderPath.TrimEnd('\\');
        var excl = excludedPrefix.TrimEnd('\\');
        return norm.Equals(excl, StringComparison.OrdinalIgnoreCase)
            || norm.StartsWith(excl + "\\", StringComparison.OrdinalIgnoreCase);
    }

    [SupportedOSPlatform("windows")]
    private static object ConnectService()
    {
        var type = Type.GetTypeFromProgID("Schedule.Service")
            ?? throw new InvalidOperationException("Task Scheduler isn't available.");
        var serviceObj = Activator.CreateInstance(type)
            ?? throw new InvalidOperationException("Task Scheduler didn't start.");
        dynamic service = serviceObj;
        service.Connect();
        return serviceObj;
    }

    [SupportedOSPlatform("windows")]
    private static void SafeReleaseCom(object? obj)
    {
        if (obj is null) return;
        try
        {
            if (Marshal.IsComObject(obj))
                Marshal.FinalReleaseComObject(obj);
        }
        catch { }
    }
}
