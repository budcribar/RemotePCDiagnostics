namespace RemotePCDiagnostics.Agent.Core;

/// <summary>
/// The machine-wide lock that keeps an RPCD update and the app's own work apart. The app holds it while a check, fix, undo,
/// service workflow, stress test or benchmark runs. The agent holds it for a whole hub update, from the release check until
/// Setup returns. Windows releases a mutex when its process ends, so a crash cannot leave updates blocked. A process that
/// squats on the name can only delay an update, never start one.
/// </summary>
public static class UpdateBusyLock
{
    public const string MutexName = @"Global\RemotePCDiagnostics.UpdateBusy";

    /// <summary>The refusal when the app (or another update) holds the lock.</summary>
    public const string BusyMessage =
        "Remote PC Diagnostics is busy: a check, fix, undo, service workflow, stress test or benchmark is running. Wait until it finishes, then try again.";

    /// <summary>
    /// Takes the mutex on a thread of its own, because a mutex belongs to the thread that took it and async code changes thread.
    /// Null when another process held it for all of <paramref name="timeout"/>, or it could not be opened.
    /// Disposing the result releases it.
    /// </summary>
    /// <param name="open">Opens or creates the mutex. The agent service passes one that sets its permissions.</param>
    public static IDisposable? TryHold(TimeSpan timeout, string name = MutexName, Func<string, Mutex?>? open = null)
    {
        var acquired = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            Mutex? mutex = null;
            var owned = false;
            try
            {
                mutex = (open ?? OpenOrCreate)(name);
                if (mutex is not null)
                {
                    try { owned = mutex.WaitOne(timeout); }
                    catch (AbandonedMutexException) { owned = true; } // Its last holder ended without releasing it.
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
            {
                owned = false;
            }
            acquired.TrySetResult(owned);
            try
            {
                if (owned)
                {
                    release.Wait();
                    mutex!.ReleaseMutex();
                }
            }
            catch (ApplicationException) { } // Already released.
            finally
            {
                mutex?.Dispose();
                release.Dispose();
            }
        })
        {
            IsBackground = true,
            Name = "rpcd-update-busy-lock",
        };
        thread.Start();
        return acquired.Task.GetAwaiter().GetResult() ? new Held(release, thread) : null;
    }

    /// <summary>Opens the agent's mutex, or creates it with default permissions when no agent service made it.</summary>
    public static Mutex? OpenOrCreate(string name)
    {
        if (Mutex.TryOpenExisting(name, out var existing))
            return existing;
        return new Mutex(initiallyOwned: false, name);
    }

    private sealed class Held(ManualResetEventSlim release, Thread holder) : IDisposable
    {
        private int _disposed;

        /// <summary>
        /// Releases the mutex and waits until its thread has let go, so work that starts right after (the next fix) can take it.
        /// </summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            release.Set();
            if (Thread.CurrentThread != holder)
                holder.Join(TimeSpan.FromSeconds(5));
        }
    }
}

/// <summary>
/// Reference-counted hold on <see cref="UpdateBusyLock"/> for one process: the first <see cref="Enter"/> takes the mutex, the last
/// release gives it back. Work that overlaps (a check during a workflow, an undo during a check) shares one hold.
/// </summary>
public sealed class UpdateBusyHold
{
    private readonly object _gate = new();
    private readonly Func<IDisposable?> _take;
    private IDisposable? _held;
    private int _count;

    public UpdateBusyHold(Func<IDisposable?>? take = null) =>
        _take = take ?? (() => UpdateBusyLock.TryHold(TimeSpan.Zero));

    /// <summary>The one hold the app uses.</summary>
    public static UpdateBusyHold App { get; } = new();

    /// <summary>True while this process holds the mutex.</summary>
    public bool IsHeld { get { lock (_gate) return _held is not null; } }

    /// <summary>Why a fix or undo did not start: an RPCD update holds the lock and is about to install.</summary>
    public const string UpdateStartingMessage =
        "Remote PC Diagnostics is being updated on this PC, so this can't start now. The app closes and reopens when the update is done. Try again then.";

    /// <summary>
    /// Like <see cref="Enter"/>, for work that must not be cut off by Setup closing the app (a fix, an undo): null when another process
    /// holds the mutex, which means an RPCD update is about to install. Then nothing was marked running.
    /// </summary>
    public IDisposable? TryEnter()
    {
        var hold = Enter();
        // Work that just finished on another thread may still be letting go of the mutex: give it a moment before calling it busy.
        for (var i = 0; i < 4 && !IsHeld; i++)
        {
            Thread.Sleep(50);
            Retry();
        }
        if (IsHeld)
            return hold;
        hold.Dispose();
        return null;
    }

    /// <summary>
    /// Marks work as running. When an update already holds the mutex the work still runs (Setup closes the app anyway);
    /// the next <see cref="Enter"/> tries again.
    /// </summary>
    public IDisposable Enter()
    {
        lock (_gate)
        {
            _count++;
            _held ??= _take();
        }
        return new Exit(this);
    }

    /// <summary>
    /// Tries the mutex again while work is still marked running but this process does not hold it, because an update or another
    /// process had it when <see cref="Enter"/> ran. Does nothing when idle or already held.
    /// </summary>
    public void Retry()
    {
        lock (_gate)
        {
            if (_count > 0)
                _held ??= _take();
        }
    }

    private void Leave()
    {
        IDisposable? release = null;
        lock (_gate)
        {
            if (_count == 0)
                return;
            if (--_count == 0)
            {
                release = _held;
                _held = null;
            }
        }
        release?.Dispose();
    }

    private sealed class Exit(UpdateBusyHold owner) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                owner.Leave();
        }
    }
}
