namespace RemotePCDiagnostics.Core.Osquery;

public sealed class OsqueryOptions
{
    /// <summary>Explicit path to osqueryi(.exe). When null, uses RPD_OSQUERYI_PATH or tools/osquery under the base directory.</summary>
    public string? ExecutablePath { get; set; }
    public TimeSpan QueryTimeout { get; set; } = TimeSpan.FromSeconds(30);
    /// <summary>Optional diagnostic sink (the Host wires this to App.Log / RPD_LOG_FILE). Never rendered in the UI.</summary>
    public Action<string>? Log { get; set; }
}

/// <summary>Result of one osquery SQL query: rows on success, otherwise an error message.</summary>
public sealed record OsqueryQueryResult(string Sql, IReadOnlyList<IReadOnlyDictionary<string, string>>? Rows, string? Error,
    int? ExitCode = null, string RawStdErr = "", string RawStdOutHead = "", long ElapsedMs = 0)
{
    public const int StdOutHeadLength = 2048;
    public bool Success => Error is null;
    public int RowCount => Rows?.Count ?? 0;

    public string ToLogLine() =>
        $"osquery \"{Sql}\" {(Success ? "ok" : "FAILED")} rows={RowCount} exit={ExitCode?.ToString() ?? "-"} ms={ElapsedMs}" +
        (Error is null ? "" : $" error=\"{Error}\"") +
        (RawStdErr.Length == 0 ? "" : $" stderr=\"{RawStdErr.Trim()}\"") +
        $" stdout_head=\"{RawStdOutHead.Replace("\r", "").Replace("\n", " ")}\"";
}

/// <summary>Locates the bundled osqueryi.exe and runs queries with <c>osqueryi --json "&lt;sql&gt;"</c>.</summary>
public sealed class OsqueryRunner
{
    public static readonly string RelativePath = Path.Combine("tools", "osquery", "osqueryi.exe");
    public const string PathEnvironmentVariable = "RPD_OSQUERYI_PATH";

    private readonly IProcessLauncher _launcher;
    private readonly Func<string, bool> _fileExists;

    public OsqueryRunner(string? baseDirectory = null, OsqueryOptions? options = null, IProcessLauncher? launcher = null, Func<string, bool>? fileExists = null)
    {
        Options = options ?? new OsqueryOptions();
        var configured = Options.ExecutablePath ?? Environment.GetEnvironmentVariable(PathEnvironmentVariable);
        ResolvedPath = !string.IsNullOrWhiteSpace(configured)
            ? Path.GetFullPath(configured)
            : Path.Combine(baseDirectory ?? AppContext.BaseDirectory, RelativePath);
        _launcher = launcher ?? new SystemProcessLauncher();
        _fileExists = fileExists ?? File.Exists;
    }

    public OsqueryOptions Options { get; }
    public string ResolvedPath { get; }
    public bool Exists => _fileExists(ResolvedPath);

    public string NotFoundMessage =>
        $"osqueryi.exe not found at '{ResolvedPath}'. Bundle it under {RelativePath} next to the app " +
        $"(copy osqueryi.exe from an osquery release into src/RemotePCDiagnostics.Host/tools/osquery), or set {PathEnvironmentVariable}.";

    public ModuleAvailability CheckAvailability() => Exists
        ? ModuleAvailability.Available
        : ModuleAvailability.Unavailable(NotFoundMessage);

    /// <summary>
    /// Arguments for one query. <c>--disable_extensions</c> stops osqueryi from creating the extension-manager
    /// named pipe (\\.\pipe\shell.em), which can collide/fail when another osquery shell or daemon is running.
    /// osqueryi already uses an ephemeral in-memory database, so no database_path is needed.
    /// </summary>
    public static IReadOnlyList<string> BuildArguments(string sql) => ["--disable_extensions", "--json", sql];

    /// <summary>Runs one query. Never throws for process/JSON failures (returns Error); throws only on cancellation.</summary>
    public async Task<OsqueryQueryResult> RunQueryAsync(string sql, CancellationToken cancellationToken = default)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await RunQueryCoreAsync(sql, cancellationToken).ConfigureAwait(false);
        result = result with { ElapsedMs = sw.ElapsedMilliseconds };
        try { Options.Log?.Invoke(result.ToLogLine()); } catch { /* logging must never break a query */ }
        return result;
    }

    private async Task<OsqueryQueryResult> RunQueryCoreAsync(string sql, CancellationToken cancellationToken)
    {
        if (!Exists) return new(sql, null, NotFoundMessage);
        ProcessResult pr;
        try
        {
            pr = await _launcher.RunAsync(ResolvedPath, BuildArguments(sql), Options.QueryTimeout, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return new(sql, null, $"Failed to start osqueryi: {ex.Message}");
        }

        var head = pr.StdOut.Length > OsqueryQueryResult.StdOutHeadLength ? pr.StdOut[..OsqueryQueryResult.StdOutHeadLength] : pr.StdOut;
        if (pr.TimedOut) return new(sql, null, $"Query timed out after {Options.QueryTimeout.TotalSeconds:0}s.", null, pr.StdErr, head);
        if (pr.ExitCode != 0)
            return new(sql, null, $"osqueryi exited with code {pr.ExitCode}: {FirstLine(pr.StdErr) ?? FirstLine(pr.StdOut) ?? "no output"}", pr.ExitCode, pr.StdErr, head);
        try
        {
            return new(sql, OsqueryJson.ParseRows(pr.StdOut), null, pr.ExitCode, pr.StdErr, head);
        }
        catch (FormatException ex)
        {
            var err = FirstLine(pr.StdErr);
            return new(sql, null, ex.Message + (err is null ? "" : $" (stderr: {err})"), pr.ExitCode, pr.StdErr, head);
        }
    }

    private static string? FirstLine(string? s)
    {
        var line = s?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        return string.IsNullOrEmpty(line) ? null : line;
    }
}
