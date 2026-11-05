namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Protected system files check: <c>sfc /verifyonly</c> (read-only).</summary>
public sealed class SfcVerifyOnlyModule(SystemCommandRunner commands) : WindowsIntegrityModule(commands)
{
    public const string ModuleName = ModuleSlugs.SfcVerifyOnly;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.SfcVerifyOnly;
    public override string DisplayName => "Protected system files (SFC)";

    protected override string ToolExe => "sfc.exe";
    protected override string[] Arguments => ["/verifyonly"];

    protected override (DiagnosticStatus Status, string Summary) Interpret(string output, RemotePCDiagnostics.Core.Osquery.ProcessResult? result)
    {
        var status = Classify(Contains(output, "found integrity violations"), Contains(output, "did not find any integrity violations"), result);
        return (status, status switch
        {
            DiagnosticStatus.Ok => "No corruption detected",
            DiagnosticStatus.Warning => "SFC found integrity violations in protected system files.",
            _ => "Integrity scan could not confirm a result"
        });
    }
}
