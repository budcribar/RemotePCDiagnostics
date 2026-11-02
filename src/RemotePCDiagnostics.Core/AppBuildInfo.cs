using System.Reflection;

namespace RemotePCDiagnostics.Core;

/// <summary>Build identity shared by the UI, diagnostic events and text logs.</summary>
public static class AppBuildInfo
{
    public static string Version { get; } = typeof(AppBuildInfo).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
    public static string Commit => Version.Contains('+') ? Version[(Version.IndexOf('+') + 1)..] : "unavailable";
    public static string Release => Version.Split('-', '+')[0];
    public static string LogStamp => $"RemotePCDiagnostics {Version}";
}
