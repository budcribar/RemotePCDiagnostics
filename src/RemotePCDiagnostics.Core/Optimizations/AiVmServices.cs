using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>
/// #14: the services that start an AI app's background Linux VM at every Windows sign-in: Claude Desktop's <c>CoworkVMService</c>
/// (the VM shows as <c>vmmem</c>, hosted by <c>vmwp.exe</c>; it's a separate Hyper-V VM, not WSL) and OpenAI Codex's
/// <c>CodexSandboxService*</c> (packaged-app suffix, e.g. <c>CodexSandboxService.OpenAI.Codex_2p2nqf0c97628</c>).
/// Offered as "start only when needed" (Manual, ticked in the service workflow) when the service is Automatic AND its security
/// descriptor lets a signed-in (non-admin) user start it, so the app can start it again itself. Unknown or refused → not offered,
/// because Manual would then leave the app unable to start its VM.
/// </summary>
public static class AiVmServices
{
    public const string ClaudeService = "CoworkVMService";
    public const string CodexServicePrefix = "CodexSandboxService";

    public static bool Is(string serviceName) => IsClaude(serviceName) || IsCodex(serviceName);
    public static bool IsClaude(string serviceName) => serviceName.Equals(ClaudeService, StringComparison.OrdinalIgnoreCase);
    public static bool IsCodex(string serviceName) => serviceName.StartsWith(CodexServicePrefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>"Claude" / "OpenAI Codex".</summary>
    public static string AppName(string serviceName) => IsClaude(serviceName) ? "Claude" : "OpenAI Codex";

    /// <summary>The app's own startup entry (exe name as <see cref="StartupEntry.ExeName"/> reports it).</summary>
    public static string AppExe(string serviceName) => IsClaude(serviceName) ? "claude" : "Codex";

    public static ServiceCandidate Candidate(string serviceName) => IsClaude(serviceName)
        ? new("Claude Desktop's VM service (CoworkVMService) starts a background Linux virtual machine that some Claude features use.",
            "Nothing you'll notice: Claude starts its VM when a feature needs it instead of at every Windows sign-in (the first such task after a restart may take a little longer to begin).")
        : new("OpenAI Codex's sandbox service (CodexSandboxService) runs the background sandbox Codex uses for its tasks.",
            "Nothing you'll notice: Codex starts it when it needs it instead of at every Windows sign-in (the first task after a restart may take a little longer to begin).");

    /// <summary>Automatic, and a signed-in user may start it (so the app can start it on demand). Unknown = not offered.</summary>
    public static bool Offer(ServiceUsage su) => Is(su.Info.Name) && su.Info.IsAutomatic && su.UsersCanStart == true;

    public static MemorySuggestion? Suggest(ServiceUsage su, MemorySnapshot s)
    {
        if (!Offer(su)) return null;
        var svc = su.Info;
        var app = AppName(svc.Name);
        var claude = IsClaude(svc.Name);
        var mem = su.ProcessMemoryBytes is { } pm && !su.Shared ? $" The service itself is using {MemoryText.Size(pm)}." : "";
        var why = claude
            ? $"\"{svc.Label}\" (CoworkVMService) is set to start automatically, so Claude Desktop's background Linux virtual machine starts at every Windows sign-in, even on days nobody uses the Claude features that need it. While it runs, the VM shows as vmmem in Task Manager and can hold a GB or more of memory.{mem}"
            : $"\"{svc.Label}\" ({svc.Name}) is set to start automatically, so OpenAI Codex's background sandbox starts at every Windows sign-in, even on days nobody uses Codex.{mem}";
        var steps = new List<string>
        {
            "Sets the service to Manual (start only when needed). It doesn't stop the service or the VM now; the change takes effect after the next restart.",
            $"{app} starts the service itself when a feature needs it, so the first such task after a restart may take a little longer to begin.",
        };
        var exe = AppExe(svc.Name);
        if ((s.Startup ?? []).Any(e => e.Enabled && e.ExeName.Equals(exe, StringComparison.OrdinalIgnoreCase)))
            steps.Add($"{app} also starts with Windows on this PC, and opening it may start the VM right away. To keep the VM off until it's needed, also stop {app} from starting with Windows.");
        steps.Add("Undo sets it back to Automatic.");
        return new($"svc-{svc.Name}".ToLowerInvariant(),
            claude ? "Start Claude's Linux VM only when it's needed" : "Start the Codex sandbox only when it's needed",
            why, null, SuggestionRisk.Low, SuggestionKind.Automated, steps,
            [new(MemoryActionType.SetServiceManual, svc.Name, "Don't start automatically",
                $"Set \"{svc.Label}\" to start only when {app} needs it (Manual)? Undo sets it back to Automatic.")],
            "Services", "Takes effect after the next restart.");
    }
}

/// <summary>
/// Reads a service's DACL (self-relative security descriptor, as <c>QueryServiceObjectSecurity</c> returns it) to tell whether a
/// signed-in, non-admin user may start the service (SERVICE_START, or GENERIC_EXECUTE / GENERIC_ALL).
/// </summary>
public static class ServiceSecurity
{
    public const uint ServiceStart = 0x0010, GenericAll = 0x10000000, GenericExecute = 0x20000000;
    private const byte AccessAllowed = 0, AccessDenied = 1, InheritOnly = 0x08;
    private const ushort DaclPresent = 0x0004, SelfRelative = 0x8000;

    /// <summary>Everyone, INTERACTIVE, Authenticated Users, BUILTIN\Users: every signed-in user is in all of them.</summary>
    public static readonly IReadOnlySet<string> SignedInUserSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "S-1-1-0", "S-1-5-4", "S-1-5-11", "S-1-5-32-545" };

    /// <summary>
    /// True = a signed-in user may start it; false = the DACL doesn't allow it (or denies it first); null = unreadable / malformed.
    /// ACEs are checked in order, as Windows does: the first allow or deny ACE that covers SERVICE_START for one of those groups decides.
    /// No DACL (or a null DACL) means everyone may.
    /// </summary>
    public static bool? UsersCanStart(byte[]? sd)
    {
        try
        {
            if (sd is null || sd.Length < 20 || sd[0] != 1) return null;
            var control = U16(sd, 2);
            if ((control & SelfRelative) == 0) return null;
            if ((control & DaclPresent) == 0) return true;
            var dacl = (int)U32(sd, 16);
            if (dacl == 0) return true;
            if (dacl < 20 || dacl + 8 > sd.Length) return null;
            int aclSize = U16(sd, dacl + 2), count = U16(sd, dacl + 4);
            var end = dacl + aclSize;
            if (aclSize < 8 || end > sd.Length) return null;
            var p = dacl + 8;
            for (var i = 0; i < count; i++)
            {
                if (p + 8 > end) return null;
                byte type = sd[p], flags = sd[p + 1];
                int size = U16(sd, p + 2);
                if (size < 8 || p + size > end) return null;
                if (type is AccessAllowed or AccessDenied && (flags & InheritOnly) == 0)
                {
                    var mask = U32(sd, p + 4);
                    var sid = Sid(sd, p + 8, p + size);
                    if (sid is null) return null;
                    if ((mask & (ServiceStart | GenericAll | GenericExecute)) != 0 && SignedInUserSids.Contains(sid))
                        return type == AccessAllowed;
                }
                p += size;
            }
            return false;
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException) { return null; }
    }

    /// <summary>"S-1-5-11" from a binary SID at <paramref name="at"/> (null when it doesn't fit before <paramref name="end"/>).</summary>
    public static string? Sid(byte[] b, int at, int end)
    {
        if (at + 8 > end) return null;
        int n = b[at + 1];
        if (b[at] != 1 || at + 8 + 4 * n > end) return null;
        ulong auth = 0;
        for (var i = 0; i < 6; i++) auth = (auth << 8) | b[at + 2 + i];
        var parts = new List<string> { "S", "1", auth.ToString(System.Globalization.CultureInfo.InvariantCulture) };
        for (var i = 0; i < n; i++) parts.Add(U32(b, at + 8 + 4 * i).ToString(System.Globalization.CultureInfo.InvariantCulture));
        return string.Join('-', parts);
    }

    private static ushort U16(byte[] b, int at) => (ushort)(b[at] | b[at + 1] << 8);
    private static uint U32(byte[] b, int at) => (uint)(b[at] | b[at + 1] << 8 | b[at + 2] << 16 | b[at + 3] << 24);
}
