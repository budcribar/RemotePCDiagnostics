namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>Locates the bundled osqueryi.exe. Stub: no queries are executed yet.</summary>
public sealed class OsqueryRunner
{
    public static readonly string RelativePath = Path.Combine("tools", "osquery", "osqueryi.exe");

    public OsqueryRunner(string? baseDirectory = null)
    {
        ResolvedPath = Path.Combine(baseDirectory ?? AppContext.BaseDirectory, RelativePath);
    }

    public string ResolvedPath { get; }
    public bool Exists => File.Exists(ResolvedPath);

    public ModuleAvailability CheckAvailability() => Exists
        ? ModuleAvailability.Available
        : ModuleAvailability.Unavailable($"osqueryi.exe not found at '{ResolvedPath}'. Bundle it under {RelativePath}.");

    // TODO: RunQueryAsync(sql) -> start osqueryi.exe --json "<sql>", parse JSON. Not implemented in the scaffold.
}
