using System.ServiceProcess;
using PeakSWC.RemoteWebView.Agent;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

public static class Program
{
    public const int ExitOk = 0;
    public const int ExitError = 1;
    public const int ExitBadArguments = 2;

    public static async Task<int> Main(string[] args)
    {
        var parsed = AgentCommandLine.Parse(args);
        if (parsed.Error is not null)
        {
            Console.Error.WriteLine(parsed.Error);
            Console.Error.WriteLine();
            Console.Error.Write(AgentCommandLine.Usage);
            return ExitBadArguments;
        }

        switch (parsed.Command)
        {
            case AgentCommand.Help:
                Console.Write(AgentCommandLine.Usage);
                return ExitOk;

            case AgentCommand.Status:
                return AgentServiceInstaller.RunStatus();

            case AgentCommand.Install:
                return AgentServiceInstaller.RunInstall(parsed, args);

            case AgentCommand.Uninstall:
                return AgentServiceInstaller.RunUninstall(parsed, args);

            case AgentCommand.Consent:
                return Win32Session.ShowConsentMessageBox(parsed.Requester, parsed.TimeoutSeconds);

            case AgentCommand.Run:
                if (parsed.SelfCheck)
                    return RunSelfCheck();
                return await RunAgentAsync().ConfigureAwait(false);

            default:
                Console.Write(AgentCommandLine.Usage);
                return ExitBadArguments;
        }
    }

    /// <summary>
    /// Fast smoke verification exercised by CI (<c>RemotePCDiagnostics.Agent.exe --self-check</c> or <c>run --self-check</c>):
    /// verifies AOT/single-file JSON serialization, Protobuf descriptors (<c>LaunchCommand.Group</c>), and <c>LaunchRules</c>.
    /// </summary>
    private static int RunSelfCheck()
    {
        var sampleId = Guid.Parse("7e57c0de-0000-4000-8000-000000000099");
        var cfg = AgentConfig.ForInstall(
            existing: null,
            new AgentArgs(AgentCommand.Install, Server: "https://relay.example:34544", Key: "rpd_live_test", Consent: ConsentCeiling.Unattended),
            sampleId);
        var roundTrip = AgentConfig.Parse(cfg.ToJson())
            ?? throw new InvalidOperationException("AgentConfig JSON round-trip failed.");

        var cmd = new LaunchCommand
        {
            RequestId = "req-self-check",
            SessionId = sampleId.ToString("D"),
            ServerUrl = roundTrip.Server,
            Group = "Acme-MSP",
            RequireConsent = false,
        };
        var line = LaunchRules.AppCommandLine(@"C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Host.exe", cmd.ServerUrl, sampleId, cmd.Group);
        if (!line.Contains("-g=acme-msp", StringComparison.Ordinal))
            throw new InvalidOperationException($"Expected -g=acme-msp in command line, got: {line}");

        Console.WriteLine($"RemotePCDiagnostics.Agent self-check OK ({AgentPaths.GetAgentVersion()})");
        return ExitOk;
    }

    private static async Task<int> RunAgentAsync()
    {
        var config = AgentPaths.TryLoadConfig(out var configError);
        if (config is null)
        {
            var msg = configError ?? $"Agent is not configured ({AgentPaths.ConfigPath()} missing). Run 'RemotePCDiagnostics.Agent.exe install' first.";
            Console.Error.WriteLine(msg);
            return ExitError;
        }

        if (Win32Session.IsStartedByServiceControlManager())
        {
            ServiceBase.Run(new AgentWindowsService(config));
            return ExitOk;
        }

        using var cts = new CancellationTokenSource();
        ConsoleCancelEventHandler onCancel = (_, e) =>
        {
            e.Cancel = true;
            try { cts.Cancel(); } catch { }
        };
        Console.CancelKeyPress += onCancel;

        try
        {
            await AgentRunLoop.RunAsync(config, Console.WriteLine, cts.Token).ConfigureAwait(false);
            return ExitOk;
        }
        finally
        {
            Console.CancelKeyPress -= onCancel;
        }
    }
}
