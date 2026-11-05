namespace RemotePCDiagnostics.Core;

public static class StressSuite
{
    /// <summary>Strict run order (module names).</summary>
    public static readonly string[] Order = [ModuleSlugs.CpuStress, ModuleSlugs.MemoryTest, ModuleSlugs.DiskSpeed, ModuleSlugs.GpuStress, ModuleSlugs.NetworkTest];

    public static TimeSpan PerTestDuration(StressSuiteMode mode) => StressSuiteDurations.PerTest(mode);

    public static string RunLabel(StressSuiteMode mode) => mode == StressSuiteMode.Extended ? "extended run" : "short run";
}
