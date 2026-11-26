using System.Runtime.Versioning;
using System.ServiceProcess;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Audio;

/// <summary>
/// Starting and restarting the two Windows Audio services, for the Agent's <c>audio_services</c> script. Only these two services and
/// only these verbs: <see cref="ServiceProtection"/> still stops the generic Services page from stopping or restarting the Endpoint
/// Builder, and only the Sound check's fix restarts it, after its probe found Windows Audio not answering.
/// </summary>
public static class AudioServices
{
    public const string AudioSrv = "Audiosrv", EndpointBuilder = "AudioEndpointBuilder";
    /// <summary>In start order: Windows Audio needs the Endpoint Builder.</summary>
    public static readonly IReadOnlyList<string> Names = [EndpointBuilder, AudioSrv];

    public const string Start = "start", Restart = "restart", RestartAll = "restart_all";
    public static bool IsVerb(string? v) => v is Start or Restart or RestartAll;

    public static readonly TimeSpan Wait = TimeSpan.FromSeconds(15);

    public static string Label(string name) => name.Equals(AudioSrv, StringComparison.OrdinalIgnoreCase) ? "Windows Audio" : "Windows Audio Endpoint Builder";

    /// <summary>What the steps need from Windows (the Agent's ServiceController, or a fake in tests).</summary>
    public interface IHost
    {
        ServiceState State(string name);
        bool IsDisabled(string name);
        void StartService(string name);
        /// <summary>Stops the service and the services that depend on it.</summary>
        void Stop(string name);
        bool WaitFor(string name, ServiceState state, TimeSpan timeout);
    }

    /// <summary>Runs one verb. Null when it worked; otherwise why not.</summary>
    public static string? Run(string verb, IHost host)
    {
        if (!IsVerb(verb)) return "That isn't something this app does to Windows Audio.";
        if (verb == Restart && StopOne(AudioSrv, host) is { } stop) return stop;
        if (verb == RestartAll)
        {
            // Stopping the Endpoint Builder stops Windows Audio with it.
            if (StopOne(EndpointBuilder, host) is { } stopAll) return stopAll;
            if (host.State(AudioSrv) != ServiceState.Stopped && !host.WaitFor(AudioSrv, ServiceState.Stopped, Wait))
                return "Windows Audio didn't stop within 15 seconds.";
        }
        foreach (var name in Names)
        {
            var state = host.State(name);
            if (state == ServiceState.NotFound) return $"{Label(name)} isn't installed on this PC.";
            if (state == ServiceState.Running) continue;
            if (host.IsDisabled(name)) return $"{Label(name)} is disabled. Set it to Automatic first.";
            if (state == ServiceState.Stopped) host.StartService(name);
            if (!host.WaitFor(name, ServiceState.Running, Wait)) return $"{Label(name)} didn't start within 15 seconds.";
        }
        return null;
    }

    private static string? StopOne(string name, IHost host)
    {
        var state = host.State(name);
        if (state == ServiceState.NotFound) return $"{Label(name)} isn't installed on this PC.";
        if (state == ServiceState.Stopped) return null;
        if (state != ServiceState.StopPending) host.Stop(name);
        return host.WaitFor(name, ServiceState.Stopped, Wait) ? null : $"{Label(name)} didn't stop within 15 seconds. Restart the PC.";
    }

    /// <summary>The Agent's host: ServiceController, with administrator rights.</summary>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsHost : IHost
    {
        public ServiceState State(string name)
        {
            try
            {
                using var sc = new ServiceController(name);
                return sc.Status switch
                {
                    ServiceControllerStatus.Running => ServiceState.Running,
                    ServiceControllerStatus.Stopped => ServiceState.Stopped,
                    ServiceControllerStatus.StartPending => ServiceState.StartPending,
                    ServiceControllerStatus.StopPending => ServiceState.StopPending,
                    _ => ServiceState.Unknown,
                };
            }
            catch (InvalidOperationException) { return ServiceState.NotFound; }
        }

        public bool IsDisabled(string name)
        {
            using var sc = new ServiceController(name);
            return sc.StartType == ServiceStartMode.Disabled;
        }

        public void StartService(string name) { using var sc = new ServiceController(name); sc.Start(); }
        public void Stop(string name) { using var sc = new ServiceController(name); sc.Stop(stopDependentServices: true); }

        public bool WaitFor(string name, ServiceState state, TimeSpan timeout)
        {
            using var sc = new ServiceController(name);
            try
            {
                sc.WaitForStatus(state == ServiceState.Running ? ServiceControllerStatus.Running : ServiceControllerStatus.Stopped, timeout);
                return true;
            }
            catch (System.ServiceProcess.TimeoutException) { return false; }
        }
    }
}
