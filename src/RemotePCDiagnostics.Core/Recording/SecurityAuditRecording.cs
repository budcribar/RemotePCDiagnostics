using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>
/// How a recording keeps one security audit run as the Agent makes it (<see cref="SecurityAuditModule.ElevatedRunner"/>): HardeningKitty's
/// PowerShell output (the PC profile) as a process answer under a fixed argument, since the real arguments name a temp report file, and
/// the report itself as a file answer.
/// </summary>
public static class SecurityAuditRecording
{
    public const string Program = "powershell.exe";
    public const string Argument = "<security audit>";
    public const string ReportName = "security audit report";

    public static IReadOnlyList<string> Arguments => [Argument];

    public static IEnumerable<RecordedCall> Calls(SecurityAuditRun run) =>
        [RecordedCall.FromProcess(Program, Arguments, run.Process), RecordedCall.FromFile(ReportName, run.ReportCsv)];
}
