namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// How many remote pages are attached to the shared session (everyone except the page in this app's own window), for the
/// top bar's badge. The window sets it from RemoteBlazorWebView's ParticipantsChanged.
/// </summary>
public sealed class RemoteUsers
{
    private int _count;

    public int Count => Volatile.Read(ref _count);

    /// <summary>Raised when <see cref="Count"/> changes (on the caller's thread).</summary>
    public event Action? Changed;

    public void Set(int count)
    {
        if (count < 0) count = 0;
        if (Interlocked.Exchange(ref _count, count) != count) Changed?.Invoke();
    }

    /// <summary>The badge text: "0 Remote Users", "1 Remote User", "2 Remote Users".</summary>
    public static string Label(int count) => count == 1 ? "1 Remote User" : $"{count} Remote Users";
}
