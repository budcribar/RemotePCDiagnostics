namespace RemotePCDiagnostics.Core.Memory;

/// <summary>
/// #14: "wsl --shutdown" on the live memory page only (never in the unattended workflow: the workflow restarts the PC anyway).
/// Offered when WSL 2's virtual machine (<c>vmmemWSL</c>) holds at least <see cref="MinVmBytes"/> and nothing on the Windows side looks
/// like it's using Linux. Conservative: any WSL console or interop host, distro launcher, Docker / Podman / Rancher Desktop process
/// blocks it (VS Code's WSL connection and Windows Terminal Linux tabs run wsl.exe, so they block it too).
/// Plain <c>vmmem</c> is not WSL on current Windows (it's Claude Desktop's VM, Hyper-V or Windows Sandbox), and wsl --shutdown
/// wouldn't free it, so it's never a reason to offer this. Nothing to undo: Linux starts again the next time it's used.
/// </summary>
public static class WslShutdown
{
    public const long MinVmBytes = 256L << 20;
    public const string VmProcess = "vmmemWSL";

    /// <summary>Exact process names (without .exe) that mean Linux is in use.</summary>
    public static readonly IReadOnlySet<string> BusyProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "wsl", "wslhost", "bash", "Docker Desktop", "dockerd", "docker", "docker-compose", "podman", "gvproxy", "win-sshproxy",
        "Rancher Desktop", "rdctl", "debian", "kali", "Arch", "fedoraremix", "alpine", "pengwin",
    };

    /// <summary>Process-name prefixes that mean Linux is in use: Docker's helpers and distro launchers (ubuntu2204, openSUSE-Tumbleweed, …).</summary>
    public static readonly IReadOnlyList<string> BusyPrefixes = ["com.docker.", "ubuntu", "openSUSE", "SLES-", "OracleLinux", "AlmaLinux"];

    public static bool IsBusyName(string processName) =>
        BusyProcesses.Contains(processName) || BusyPrefixes.Any(p => processName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    /// <summary>The Windows-side processes that show Linux is in use (empty = looks idle).</summary>
    public static IReadOnlyList<AppUsage> Busy(MemorySnapshot s) => s.Apps.Where(a => IsBusyName(a.Name)).ToList();

    public static AppUsage? IdleVm(MemorySnapshot s) =>
        s.App(VmProcess) is { MemoryBytes: >= MinVmBytes } vm && Busy(s).Count == 0 ? vm : null;

    public const string Confirm =
        "Shut down WSL? This closes all running Linux distributions and anything running in them (unsaved work in Linux apps, servers, Docker containers). "
        + "Any Claude, Claude Code or Codex task using Linux on this PC is interrupted until it starts again.";

    public static MemorySuggestion? Suggest(MemorySnapshot s)
    {
        if (IdleVm(s) is not { } vm) return null;
        return new("wsl-shutdown", "Shut down the idle Linux (WSL) virtual machine",
            $"Windows Subsystem for Linux keeps its virtual machine (vmmemWSL) in memory: it's using {MemoryText.Size(vm.MemoryBytes)} right now, and nothing on this PC looks like it's using Linux (no WSL window or terminal, Docker or VS Code connection is open).",
            vm.MemoryBytes, SuggestionRisk.Medium, SuggestionKind.Automated,
            ["Runs \"wsl --shutdown\": closes every running Linux distribution and anything still running inside them (background jobs, servers, Docker containers).",
             "Claude Desktop runs its own Linux virtual machine for some Claude features (it normally shows as vmmem, separate from WSL). If Claude, Claude Code or Codex is working on a task that uses Linux on this PC, shutting down interrupts that task until it starts again. Let it finish first.",
             "Nothing to undo: Linux starts again the next time it's opened or an app uses it (the first start takes a few seconds)."],
            [new(MemoryActionType.ShutdownWsl, "wsl", "Shut down WSL", Confirm)],
            "Developer tools", "Don't use this while Linux, Docker or an AI coding task is in use.");
    }
}
