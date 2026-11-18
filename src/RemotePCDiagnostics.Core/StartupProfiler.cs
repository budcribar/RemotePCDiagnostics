using System.Diagnostics;

namespace RemotePCDiagnostics.Core;

/// <summary>
/// High-resolution startup profiler tracking milestones from process start to first interactive render.
/// Enabled via RPD_BENCHMARK_STARTUP=1 or command line flag --benchmark-startup.
/// </summary>
public static class StartupProfiler
{
    private static readonly long StartTimestamp = Stopwatch.GetTimestamp();
    private static readonly List<(string Name, double ElapsedMs, double DeltaMs)> Milestones = [];
    private static readonly object Lock = new();
    private static long _lastTimestamp = StartTimestamp;
    private static bool _completed;

    public static bool IsEnabled { get; set; } =
        string.Equals(Environment.GetEnvironmentVariable("RPD_BENCHMARK_STARTUP"), "1", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Environment.GetEnvironmentVariable("RPD_BENCHMARK_EXIT"), "1", StringComparison.OrdinalIgnoreCase);

    public static bool ShouldAutoExit =>
        string.Equals(Environment.GetEnvironmentVariable("RPD_BENCHMARK_EXIT"), "1", StringComparison.OrdinalIgnoreCase);

    public static Action<string>? LogAction { get; set; }

    public static void Mark(string milestone)
    {
        var now = Stopwatch.GetTimestamp();
        lock (Lock)
        {
            var elapsedMs = Stopwatch.GetElapsedTime(StartTimestamp, now).TotalMilliseconds;
            var deltaMs = Stopwatch.GetElapsedTime(_lastTimestamp, now).TotalMilliseconds;
            _lastTimestamp = now;
            Milestones.Add((milestone, elapsedMs, deltaMs));

            if (IsEnabled)
            {
                var msg = $"[StartupProfile] +{elapsedMs:F1} ms (+{deltaMs:F1} ms) -> {milestone}";
                Console.WriteLine(msg);
                LogAction?.Invoke(msg);
            }

            if (milestone is "DashboardFirstRender" or "DashboardReady")
            {
                if (!_completed)
                {
                    _completed = true;
                    PrintSummary();
                    if (ShouldAutoExit)
                    {
                        Task.Run(async () =>
                        {
                            await Task.Delay(250).ConfigureAwait(false);
                            Environment.Exit(0);
                        });
                    }
                }
            }
        }
    }

    public static void PrintSummary()
    {
        lock (Lock)
        {
            var total = Milestones.Count > 0 ? Milestones[^1].ElapsedMs : 0;
            var lines = new List<string>
            {
                "==================================================",
                $"=== RPCD STARTUP PROFILE SUMMARY: {total:F1} ms ===",
                "=================================================="
            };

            foreach (var (name, elapsedMs, deltaMs) in Milestones)
            {
                lines.Add($"  [+{elapsedMs,7:F1} ms | delta {deltaMs,6:F1} ms] {name}");
            }
            lines.Add("==================================================");

            var summaryText = string.Join(Environment.NewLine, lines);
            Console.WriteLine(summaryText);
            LogAction?.Invoke(summaryText);
        }
    }

    public static IReadOnlyList<(string Name, double ElapsedMs, double DeltaMs)> GetMilestones()
    {
        lock (Lock) return [.. Milestones];
    }
}
