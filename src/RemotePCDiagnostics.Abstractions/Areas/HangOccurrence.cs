namespace RemotePCDiagnostics.Core.Areas;

public sealed record HangOccurrence(DateTimeOffset Time, string App, string Path, string Package, string Type, string ReportId);
