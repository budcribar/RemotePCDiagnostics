using System.Diagnostics;
using System.Globalization;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Checks a staged or installed Host folder. Admin repair mode is hosted by
/// <c>RemotePCDiagnostics.Agent.exe --mode=helper</c> and speaks <see cref="AdminPipeFraming"/>;
/// there is no separate Admin helper executable.
/// </summary>
public static class PackageVerifier
{
    public const string RequiredFilesCheck = "required files";
    public const string MemTestCheck = "MemTest probe";
    public const string AgentSelfCheckCheck = "Agent self-check";
    public const string AgentAdminPipeCheck = "Agent admin pipe";

    public const long MemTestBytes = 1_048_576;
    public const int MemTestSeconds = 1;

    public static int Run(string baseDirectory, Action<string> log)
        => Run(baseDirectory, log, new LiveProbes());

    public static int Run(string baseDirectory, Action<string> log, IPackageProbes probes)
    {
        var missing = MissingRelativePaths(baseDirectory);
        log($"Package base: {baseDirectory}; missing: {(missing.Count == 0 ? "(none)" : string.Join(", ", missing))}.");
        if (missing.Count > 0)
        {
            log($"Package check '{RequiredFilesCheck}' failed. Expected these files under '{baseDirectory}': {string.Join(", ", missing)}. Found: not present.");
            return 1;
        }

        if (LogProbe(MemTestCheck, probes.MemTest(baseDirectory), log) != 0) return 1;
        if (LogProbe(AgentSelfCheckCheck, probes.AgentSelfCheck(baseDirectory), log) != 0) return 1;
        if (LogProbe(AgentAdminPipeCheck, probes.AgentAdminPipe(baseDirectory), log) != 0) return 1;
        return 0;
    }

    public static IReadOnlyList<string> MissingRelativePaths(string baseDirectory)
        => RelativePathsRequired(baseDirectory).Where(p => !File.Exists(Path.Combine(baseDirectory, p))).ToArray();

    public static IReadOnlyList<string> RelativePathsRequired(string baseDirectory)
    {
        var required = new List<string>
        {
            "tools/osquery/osqueryi.exe",
            "tools/HardeningKitty/HardeningKitty.psd1",
            "tools/HardeningKitty/HardeningKitty.psm1",
            "RemotePCDiagnostics.MemTest.exe",
            "RemotePCDiagnostics.ModuleHost.exe",
            "RemotePCDiagnostics.Agent.exe",
            "moduleui/RemotePCDiagnostics.ModuleUiHost.exe",
            "wwwroot/index.html",
        };
        foreach (var stem in new[] { "RemotePCDiagnostics.MemTest", "RemotePCDiagnostics.ModuleHost", "RemotePCDiagnostics.Agent", "moduleui/RemotePCDiagnostics.ModuleUiHost" })
        {
            // A framework-dependent or multi-file apphost cannot start without both files.
            // Single-file bundles embed them and do not leave a sibling dll.
            if (File.Exists(Path.Combine(baseDirectory, stem + ".dll")))
            {
                required.Add(stem + ".runtimeconfig.json");
                required.Add(stem + ".deps.json");
            }
        }
        return required;
    }

    public static IReadOnlyList<string> AgentHelperArguments(int parentPid, string pipeName) =>
        ["--mode=helper", $"--parent-pid={parentPid.ToString(CultureInfo.InvariantCulture)}", $"--pipe={pipeName}"];

    public static PackageProbeResult DescribeMemTest(int? exitCode, bool timedOut, string? output)
    {
        var expected = $"exit code 0 and a final line 'MT DONE {MemTestBytes.ToString(CultureInfo.InvariantCulture)} <passes> 0' with passes > 0";
        if (timedOut)
            return PackageProbeResult.Fail($"Expected {expected} within 15 seconds. Found: still running. Output: {Tail(output)}.");

        var done = (output ?? "").Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(MemTestMessage.Parse)
            .OfType<MemTestMessage.Done>()
            .LastOrDefault();
        if (exitCode == 0 && done is { Bytes: MemTestBytes, Passes: > 0, Errors: 0 })
            return PackageProbeResult.Pass($"Expected {expected}. Found: exit 0, {done.Format()}.");

        var found = done is null
            ? $"exit {ExitText(exitCode)}, no MT DONE line. Output: {Tail(output)}."
            : $"exit {ExitText(exitCode)}, {done.Format()}.";
        return PackageProbeResult.Fail($"Expected {expected}. Found: {found}");
    }

    public static PackageProbeResult DescribeAgentSelfCheck(int? exitCode, bool timedOut, string? stdout, string? stderr)
    {
        const string expected = "RemotePCDiagnostics.Agent.exe --self-check exits 0 and prints 'self-check OK'";
        var found = $"exit {ExitText(exitCode)}. stdout: {Tail(stdout)}. stderr: {Tail(stderr)}.";
        if (timedOut)
            return PackageProbeResult.Fail($"Expected {expected} within 10 seconds. Found: still running. {found}");
        var ok = exitCode == 0 && (stdout ?? "").Contains("self-check OK", StringComparison.Ordinal);
        return ok
            ? PackageProbeResult.Pass($"Expected {expected}. Found: {found}")
            : PackageProbeResult.Fail($"Expected {expected}. Found: {found}");
    }

    private static int LogProbe(string check, PackageProbeResult result, Action<string> log)
    {
        var detail = string.IsNullOrWhiteSpace(result.Detail)
            ? "No detail was reported (expected versus found was not recorded)."
            : result.Detail.Trim();
        log($"Package check '{check}' {(result.Ok ? "passed" : "failed")}. {detail}");
        return result.Ok ? 0 : 1;
    }

    private static string ExitText(int? exitCode) => exitCode?.ToString(CultureInfo.InvariantCulture) ?? "unknown";

    private static string Tail(string? text, int max = 1500)
    {
        if (string.IsNullOrWhiteSpace(text)) return "(empty)";
        var flat = text.Trim().ReplaceLineEndings(" | ");
        return flat.Length <= max ? flat : flat[^max..];
    }

    private sealed class LiveProbes : IPackageProbes
    {
        public PackageProbeResult MemTest(string baseDirectory)
        {
            var exe = Path.Combine(baseDirectory, "RemotePCDiagnostics.MemTest.exe");
            try
            {
                var run = RunCaptured(exe,
                    ["--bytes", MemTestBytes.ToString(CultureInfo.InvariantCulture), "--seconds", MemTestSeconds.ToString(CultureInfo.InvariantCulture)],
                    baseDirectory, 15_000);
                return DescribeMemTest(run.ExitCode, run.TimedOut, run.StdOut);
            }
            catch (Exception ex)
            {
                return PackageProbeResult.Fail($"Expected MemTest to start at '{exe}'. Found: {ex.GetType().Name}: {OneLine(ex.Message)}.");
            }
        }

        public PackageProbeResult AgentSelfCheck(string baseDirectory)
        {
            var exe = Path.Combine(baseDirectory, "RemotePCDiagnostics.Agent.exe");
            try
            {
                var run = RunCaptured(exe, ["--self-check"], baseDirectory, 10_000);
                return DescribeAgentSelfCheck(run.ExitCode, run.TimedOut, run.StdOut, run.StdErr);
            }
            catch (Exception ex)
            {
                return PackageProbeResult.Fail($"Expected RemotePCDiagnostics.Agent.exe --self-check to start at '{exe}'. Found: {ex.GetType().Name}: {OneLine(ex.Message)}.");
            }
        }

        public PackageProbeResult AgentAdminPipe(string baseDirectory)
        {
            var exe = Path.Combine(baseDirectory, "RemotePCDiagnostics.Agent.exe");
            var pipeName = "rpd-verify-" + Guid.NewGuid().ToString("N");
            var args = AgentHelperArguments(Environment.ProcessId, pipeName);
            var command = "RemotePCDiagnostics.Agent.exe " + string.Join(' ', args);
            var expected = $"'{command}' accepts an AdminPipeProtocol ping (op=ping, ok=true, helperPid equals the Agent process) from Host and then exits 0";
            Process? proc = null;
            Task<string>? stdoutTask = null;
            Task<string>? stderrTask = null;
            try
            {
                var psi = new ProcessStartInfo(exe)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = baseDirectory,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                foreach (var arg in args) psi.ArgumentList.Add(arg);
                proc = Process.Start(psi);
                if (proc is null)
                    return PackageProbeResult.Fail($"Expected {expected}. Found: Process.Start returned null.");

                stdoutTask = proc.StandardOutput.ReadToEndAsync();
                stderrTask = proc.StandardError.ReadToEndAsync();
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                var connectTask = Task.Run(() => AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(20), connectCts.Token));
                var deadline = Environment.TickCount64 + 20_000;
                while (!connectTask.IsCompleted && Environment.TickCount64 < deadline)
                {
                    if (proc.HasExited) break;
                    Thread.Sleep(50);
                }

                if (!connectTask.IsCompletedSuccessfully)
                {
                    var fault = connectTask.IsFaulted
                        ? OneLine(connectTask.Exception?.GetBaseException().Message ?? "connect failed")
                        : null;
                    var exitedEarly = proc.HasExited;
                    try { connectCts.Cancel(); } catch { }
                    TryStop(proc);
                    try { connectTask.Wait(2_000); } catch { }
                    var error = fault
                        ?? (exitedEarly ? "Agent exited before answering the ping" : "no ping response within 20 seconds");
                    return PackageProbeResult.Fail($"Expected {expected}. Found: {error}. Agent exit={ExitOf(proc)}. stdout: {Tail(Finish(stdoutTask))}. stderr: {Tail(Finish(stderrTask))}.");
                }

                using (var client = connectTask.GetAwaiter().GetResult())
                {
                    if (!client.IsConnected || client.HelperPid != proc.Id)
                    {
                        return PackageProbeResult.Fail($"Expected {expected}. Found: connected={client.IsConnected}, helperPid={client.HelperPid}, agentPid={proc.Id}.");
                    }
                }

                if (!proc.WaitForExit(10_000))
                {
                    TryStop(proc);
                    return PackageProbeResult.Fail($"Expected {expected}. Found: ping succeeded (helperPid={proc.Id}) but the Agent helper was still running 10 seconds after the pipe closed. stderr: {Tail(Finish(stderrTask))}.");
                }

                var stderr = Finish(stderrTask);
                var stdout = Finish(stdoutTask);
                if (proc.ExitCode != 0)
                    return PackageProbeResult.Fail($"Expected {expected}. Found: ping succeeded but Agent exited {proc.ExitCode.ToString(CultureInfo.InvariantCulture)}. stdout: {Tail(stdout)}. stderr: {Tail(stderr)}.");
                return PackageProbeResult.Pass($"Expected {expected}. Found: ping ok=true, helperPid={proc.Id.ToString(CultureInfo.InvariantCulture)}, exit 0.");
            }
            catch (Exception ex)
            {
                return PackageProbeResult.Fail($"Expected {expected}. Found: {ex.GetType().Name}: {OneLine(ex.Message)}. stderr: {Tail(Finish(stderrTask))}.");
            }
            finally
            {
                if (proc is { HasExited: false }) TryStop(proc);
            }
        }

        private static Captured RunCaptured(string exe, IReadOnlyList<string> args, string workingDirectory, int timeoutMs)
        {
            var psi = new ProcessStartInfo(exe)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (var arg in args) psi.ArgumentList.Add(arg);
            using var proc = Process.Start(psi) ?? throw new InvalidOperationException($"Process.Start returned null for '{exe}'.");
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(timeoutMs))
            {
                TryStop(proc);
                return new Captured(proc.HasExited ? proc.ExitCode : null, true, Finish(stdoutTask), Finish(stderrTask));
            }
            proc.WaitForExit();
            return new Captured(proc.ExitCode, false, Finish(stdoutTask), Finish(stderrTask));
        }

        private static void TryStop(Process proc)
        {
            try
            {
                if (!proc.HasExited) proc.Kill(entireProcessTree: true);
            }
            catch { }
            try { if (!proc.HasExited) proc.WaitForExit(5_000); } catch { }
        }

        private static string Finish(Task<string>? read)
        {
            if (read is null) return "";
            try { return read.Wait(5_000) ? read.Result : ""; }
            catch { return ""; }
        }

        private static string ExitOf(Process proc)
        {
            try { return proc.HasExited ? proc.ExitCode.ToString(CultureInfo.InvariantCulture) : "still running"; }
            catch { return "unknown"; }
        }

        private readonly record struct Captured(int? ExitCode, bool TimedOut, string StdOut, string StdErr);
    }

    private static string OneLine(string text) => text.ReplaceLineEndings(" ").Trim();
}

public interface IPackageProbes
{
    PackageProbeResult MemTest(string baseDirectory);
    PackageProbeResult AgentSelfCheck(string baseDirectory);
    PackageProbeResult AgentAdminPipe(string baseDirectory);
}

public sealed record PackageProbeResult(bool Ok, string Detail)
{
    public static PackageProbeResult Pass(string detail) => new(true, detail);
    public static PackageProbeResult Fail(string detail) => new(false, detail);
}
