using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Legacy;

/// <summary>
/// Uptime and processes from osquery <c>uptime</c> and <c>processes</c>; memory, commit charge and Fast Startup from the FastStartupState
/// PowerShell script when commands are scripted (tests, the recorder), otherwise read in this process (<see cref="FastStartupReader"/>).
/// All of it works as a standard user.
/// </summary>
/// <param name="processorCount">The logical processors CPU % is a share of (default: this PC's).</param>
public sealed class OsqueryResourceHogsSource(OsqueryRunner runner, SystemCommandRunner? commands = null, Func<int>? processorCount = null) : IResourceHogsSource
{
    public const string UptimeSql = ResourceUsage.UptimeSql;
    public const string ProcessesSql = ResourceUsage.ProcessesSql;

    public static string FastStartupScript { get; } = Load("FastStartupState");

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => LegacyAvailability.Of(runner, LegacyAvailability.ToolMissingMessage);

    public async Task<SystemUptimeInfo?> ReadUptimeAsync(CancellationToken ct)
    {
        var q = await runner.RunQueryAsync(UptimeSql, ct).ConfigureAwait(false);
        return q.Success && q.Rows!.Count > 0 ? SystemUptimeInfo.FromRow(q.Rows[0]) : null;
    }

    public async Task<IReadOnlyList<ProcessResourceRow>?> ReadProcessesAsync(CancellationToken ct)
    {
        var q = await runner.RunQueryAsync(ProcessesSql, ct).ConfigureAwait(false);
        return q.Success ? q.Rows!.Select(ProcessResourceRow.FromRow).ToList() : null;
    }

    public Task<int> ReadLogicalProcessorsAsync(CancellationToken ct) => Task.FromResult(Math.Max(1, (processorCount ?? (() => Environment.ProcessorCount))()));

    public async Task<MemoryRead> ReadMemoryAsync(CancellationToken ct)
    {
        if (commands is { IsScripted: true })
        {
            var pr = await commands.RunPowerShellAsync(FastStartupScript, ct).ConfigureAwait(false);
            return pr is { ExitCode: 0 } && !string.IsNullOrWhiteSpace(pr.StdOut) ? Parse(pr.StdOut) : new(null, null);
        }
        var (fs, totalBytes, freeBytes) = FastStartupReader.Read();
        var (commitUsed, commitLimit, installed, pfUsed, pfSize) = FastStartupReader.ReadCommit();
        var memory = totalBytes is > 0 && freeBytes is >= 0
            ? new MemoryUse(totalBytes.Value, freeBytes.Value)
            {
                CommitUsedBytes = commitUsed, CommitLimitBytes = commitLimit, InstalledBytes = installed,
                PagefileUsedBytes = pfUsed, PagefileSizeBytes = pfSize,
            }
            : null;
        return new(memory, fs);
    }

    /// <summary>The FastStartupState script's JSON object.</summary>
    public static MemoryRead Parse(string stdout)
    {
        try
        {
            var row = OsqueryJson.ParseRows("[" + stdout.Trim().TrimStart('[').TrimEnd(']') + "]").FirstOrDefault();
            var fastStartup = row?.Str("FastStartup") switch { "1" => true, "0" => false, _ => (bool?)null };
            if (row?.Long("TotalBytes") is not long total || total <= 0 || row.Long("FreeBytes") is not long free || free < 0) return new(null, fastStartup);
            var limit = row.Long("CommitLimitBytes");
            var commitFree = row.Long("CommitFreeBytes");
            return new(new MemoryUse(total, free)
            {
                CommitLimitBytes = limit is > 0 ? limit : null,
                CommitUsedBytes = limit is > 0 && commitFree is >= 0 ? Math.Max(0, limit.Value - commitFree.Value) : null,
                InstalledBytes = row.Long("InstalledBytes") is > 0 and var inst ? inst : null,
                PagefileUsedBytes = row.Long("PagefileUsedBytes") is >= 0 and var pu ? pu : null,
                PagefileSizeBytes = row.Long("PagefileSizeBytes") is >= 0 and var ps ? ps : null,
            }, fastStartup);
        }
        catch (FormatException) { return new(null, null); }
    }

    private static string Load(string name)
    {
        using var stream = typeof(OsqueryResourceHogsSource).Assembly.GetManifestResourceStream($"Legacy/{name}.ps1")
            ?? throw new InvalidOperationException($"No embedded script named {name}.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim().TrimStart('﻿');
    }
}
