using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Holds <see cref="AgentInstancePolicy.MutexName"/> for the life of this process.
/// The ACL grants LocalSystem, Administrators, service accounts, and ordinary users the right to open it,
/// so a service in session 0 and a console or dev process in another session contend for the same instance.
/// A default mutex DACL created by LocalSystem or an elevated process denies the other context.
/// </summary>
internal static class AgentSingleInstance
{
    /// <summary>The running instance, or null when another instance already holds the mutex. Null logs the reason.</summary>
    public static Lease? Acquire(Action<string>? alsoLog)
    {
        if (!OperatingSystem.IsWindows())
            return new Lease(null);

        var others = AgentMachineSnapshot.OtherProcesses();
        var services = AgentMachineSnapshot.ReadServices();
        var claim = AgentMachineSnapshot.ReadClaim();
        var currentImage = Environment.ProcessPath;

        Mutex? mutex = null;
        var global = true;
        try
        {
            mutex = CreateOrOpen(AgentInstancePolicy.MutexName);
        }
        catch (UnauthorizedAccessException)
        {
            Log(AgentInstancePolicy.LogPrefix + " " + AgentInstancePolicy.MutexName + " exists but this process cannot open it. Exiting without starting.", alsoLog);
            Log(AgentInstancePolicy.DescribeDenial(claim, others), alsoLog);
            return null;
        }

        if (mutex is null)
        {
            global = false;
            try
            {
                mutex = CreateOrOpen(AgentInstancePolicy.SessionMutexName);
            }
            catch (UnauthorizedAccessException)
            {
                Log(AgentInstancePolicy.LogPrefix + " Could not open a session mutex either. Exiting without starting.", alsoLog);
                return null;
            }
            if (mutex is not null)
                Log(AgentInstancePolicy.LogPrefix + " This process cannot create " + AgentInstancePolicy.MutexName + ". Using " + AgentInstancePolicy.SessionMutexName + " for this session.", alsoLog);
        }

        if (mutex is null)
        {
            Log(AgentInstancePolicy.LogPrefix + " Could not create an instance mutex. Continuing as the only copy this process can see.", alsoLog);
            LogIdentityAndStale(alsoLog, abandoned: false, claim, others, services, currentImage);
            return new Lease(null);
        }

        var owned = false;
        var abandoned = false;
        try
        {
            owned = mutex.WaitOne(0);
        }
        catch (AbandonedMutexException)
        {
            owned = true;
            abandoned = true;
        }
        catch (Exception ex)
        {
            Log(AgentInstancePolicy.LogPrefix + " Could not wait on the instance mutex: " + ex.Message + ". Exiting without starting.", alsoLog);
            mutex.Dispose();
            return null;
        }

        if (!owned)
        {
            Log(AgentInstancePolicy.DescribeDenial(claim, others), alsoLog);
            mutex.Dispose();
            return null;
        }

        if (global)
        {
            AgentMachineSnapshot.WriteClaim(new AgentInstanceClaim(
                Environment.ProcessId,
                AgentPaths.GetAgentVersion(),
                currentImage,
                DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture)));
        }

        LogIdentityAndStale(alsoLog, abandoned, claim, others, services, currentImage);
        return new Lease(mutex);
    }

    /// <summary>True when no process holds the global mutex. An abandoned mutex counts as free. Does not keep it.</summary>
    public static bool WaitUntilFree(TimeSpan timeout, Action<string>? log)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        var until = DateTime.UtcNow + timeout;
        while (true)
        {
            if (TryTakeAndRelease(out var missing, out var abandoned))
            {
                if (abandoned)
                    Log(AgentInstancePolicy.LogPrefix + " The previous agent abandoned " + AgentInstancePolicy.MutexName + ". It is free for the new service.", log);
                else if (missing)
                    Log(AgentInstancePolicy.LogPrefix + " " + AgentInstancePolicy.MutexName + " is not held.", log);
                return true;
            }

            if (DateTime.UtcNow >= until)
            {
                Log(AgentInstancePolicy.DescribeDenial(AgentMachineSnapshot.ReadClaim(), AgentMachineSnapshot.OtherProcesses()), log);
                return false;
            }
            Thread.Sleep(200);
        }
    }

    public static void Log(string line, Action<string>? also)
    {
        try { also?.Invoke(line); } catch { /* A log callback must not block the guard. */ }
        AgentWindowsService.AppendLogLineSafe(AgentLayout.AgentLogPath(), $"{DateTimeOffset.Now:O} {line}");
    }

    private static void LogIdentityAndStale(
        Action<string>? alsoLog,
        bool abandoned,
        AgentInstanceClaim? claim,
        IReadOnlyList<AgentProcessSighting> others,
        IReadOnlyList<AgentServiceRegistration> services,
        string? currentImage)
    {
        Log($"{AgentInstancePolicy.LogPrefix} Single instance pid {Environment.ProcessId}, version {AgentPaths.GetAgentVersion()}, path {AgentInstancePolicy.Shown(currentImage)}.", alsoLog);
        var alive = claim is not null && AgentMachineSnapshot.PidAlive(claim.Pid);
        var report = AgentInstancePolicy.DescribeStartup(true, abandoned, claim, alive, others, services, currentImage);
        foreach (var line in report.Lines)
            Log(line, alsoLog);
    }

    private static bool TryTakeAndRelease(out bool missing, out bool abandoned)
    {
        missing = false;
        abandoned = false;
        Mutex mutex;
        try
        {
            mutex = MutexAcl.Create(false, AgentInstancePolicy.MutexName, out _, Access());
        }
        catch (UnauthorizedAccessException)
        {
            try
            {
                mutex = Mutex.OpenExisting(AgentInstancePolicy.MutexName);
            }
            catch (WaitHandleCannotBeOpenedException)
            {
                missing = true;
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        var owned = false;
        try
        {
            try
            {
                owned = mutex.WaitOne(0);
            }
            catch (AbandonedMutexException)
            {
                owned = true;
                abandoned = true;
            }
            return owned;
        }
        finally
        {
            if (owned)
            {
                try { mutex.ReleaseMutex(); } catch { /* Already abandoned by the time we released. */ }
            }
            mutex.Dispose();
        }
    }

    private static Mutex? CreateOrOpen(string name)
    {
        try
        {
            return MutexAcl.Create(false, name, out _, Access());
        }
        catch (UnauthorizedAccessException)
        {
            try
            {
                return Mutex.OpenExisting(name);
            }
            catch (WaitHandleCannotBeOpenedException)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Everyone can wait on and release the mutex. LocalSystem creates it; a console or dev process has to open it.
    /// Full control for those SIDs is what makes the create succeed for the creator as well.
    /// </summary>
    private static MutexSecurity Access()
    {
        var security = new MutexSecurity();
        void Allow(WellKnownSidType sid) =>
            security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid, null), MutexRights.FullControl, AccessControlType.Allow));
        Allow(WellKnownSidType.LocalSystemSid);
        Allow(WellKnownSidType.BuiltinAdministratorsSid);
        Allow(WellKnownSidType.ServiceSid);
        Allow(WellKnownSidType.LocalServiceSid);
        Allow(WellKnownSidType.NetworkServiceSid);
        Allow(WellKnownSidType.BuiltinUsersSid);
        Allow(WellKnownSidType.InteractiveSid);
        Allow(WellKnownSidType.WorldSid);
        return security;
    }

    internal sealed class Lease : IDisposable
    {
        private Mutex? _mutex;
        private int _disposed;

        public Lease(Mutex? mutex) => _mutex = mutex;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            var mutex = _mutex;
            _mutex = null;
            if (mutex is null) return;
            try { mutex.ReleaseMutex(); } catch { /* Not the owner, or it was already abandoned. */ }
            mutex.Dispose();
            AgentMachineSnapshot.DeleteClaimIfOwned(Environment.ProcessId);
        }
    }
}
