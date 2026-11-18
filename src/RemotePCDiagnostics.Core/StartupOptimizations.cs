namespace RemotePCDiagnostics.Core;

/// <summary>
/// Feature flags for evaluating startup optimizations.
/// Each optimization can be toggled individually (RPD_OPT_&lt;NAME&gt;=1) or all together (RPD_OPT_ALL=1).
/// </summary>
public static class StartupOptimizations
{
    private static bool IsEnvTrue(string varName) =>
        string.Equals(Environment.GetEnvironmentVariable(varName), "1", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Environment.GetEnvironmentVariable("RPD_OPT_ALL"), "1", StringComparison.OrdinalIgnoreCase);

    /// <summary>Opt 1: Delay AutoRun background diagnostic tasks until after the first UI render.</summary>
    public static bool DeferAutoRun => IsEnvTrue("RPD_OPT_DEFER_AUTORUN");

    /// <summary>Opt 2: Load bundled module assemblies on demand rather than eagerly loading all 26 DLLs into separate ALCs at launch.</summary>
    public static bool LazyBundledModules => IsEnvTrue("RPD_OPT_LAZY_MODULES");

    /// <summary>Opt 3: Use pre-known descriptors for built-in modules to avoid reading PE assembly manifests at startup.</summary>
    public static bool StaticDescriptors => IsEnvTrue("RPD_OPT_STATIC_DESCRIPTORS");

    /// <summary>Opt 4: Run event log startup migrations in the background or fast-check marker file without synchronous event queries.</summary>
    public static bool DeferMigrations => IsEnvTrue("RPD_OPT_DEFER_MIGRATIONS");

    /// <summary>Opt 5: Fast-path SecureProtectedState if ACLs were already verified for this installation.</summary>
    public static bool FastProtectedState => IsEnvTrue("RPD_OPT_FAST_STATE_CHECK");

    /// <summary>Opt 6: Defer post-reboot, workflow, and benchmark resume file queries until after UI settles.</summary>
    public static bool DeferResumes => IsEnvTrue("RPD_OPT_DEFER_RESUMES");

    /// <summary>Opt 7: Add performance-tuning browser arguments to WebView2 (--disable-background-networking, etc.).</summary>
    public static bool WebViewFlags => IsEnvTrue("RPD_OPT_WEBVIEW_FLAGS");

    /// <summary>Opt 8: Memoize and guard Dashboard initial render computations (avoid redundant LINQ queries before data arrives).</summary>
    public static bool DashboardMemoize => IsEnvTrue("RPD_OPT_DASHBOARD_MEMOIZE");

    /// <summary>Opt 9: Defer WMI retrim event queries until Drive Health module is requested.</summary>
    public static bool DeferRetrim => IsEnvTrue("RPD_OPT_DEFER_RETRIM");

    /// <summary>Opt 10: Parallelize bundled module DLL discovery and manifest reading when eager loading is used.</summary>
    public static bool ParallelPluginScan => IsEnvTrue("RPD_OPT_PARALLEL_PLUGINS");
}
