namespace RemotePCDiagnostics.Core.Areas;

public interface ICopilotHandoff
{
    Task<bool> TrySendAsync(string prompt);
}
