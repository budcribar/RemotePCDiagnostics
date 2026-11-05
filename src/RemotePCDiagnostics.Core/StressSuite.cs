namespace RemotePCDiagnostics.Core;

public static class StressSuite
{
    public static TimeSpan PerTestDuration(StressSuiteMode mode) => StressSuiteDurations.PerTest(mode);

    public static string RunLabel(StressSuiteMode mode) => mode == StressSuiteMode.Extended ? "extended run" : "short run";
}
