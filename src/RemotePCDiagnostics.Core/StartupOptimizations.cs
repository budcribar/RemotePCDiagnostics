namespace RemotePCDiagnostics.Core;

/// <summary>
/// Feature flags for evaluating startup optimizations.
/// Each optimization can be toggled individually (RPD_OPT_&lt;NAME&gt;=1) or all together (RPD_OPT_ALL=1).
/// </summary>
public static class StartupOptimizations
{
    private static bool IsEnabled(string varName, bool defaultValue = true)
    {
        var val = Environment.GetEnvironmentVariable(varName);
        if (string.Equals(val, "0", StringComparison.OrdinalIgnoreCase) || string.Equals(val, "false", StringComparison.OrdinalIgnoreCase))
            return false;
        if (string.Equals(val, "1", StringComparison.OrdinalIgnoreCase) || string.Equals(val, "true", StringComparison.OrdinalIgnoreCase))
            return true;
        return defaultValue;
    }

    /// <summary>Opt 1: Delay AutoRun background diagnostic tasks until after the first UI render.</summary>
    public static bool DeferAutoRun => IsEnabled("RPD_OPT_DEFER_AUTORUN", true);

    /// <summary>Opt 2: Load bundled module assemblies on demand rather than eagerly loading all 26 DLLs into separate ALCs at launch.</summary>
    public static bool LazyBundledModules => IsEnabled("RPD_OPT_LAZY_MODULES", false);

    /// <summary>Opt 3: Use pre-known descriptors for built-in modules to avoid reading PE assembly manifests at startup.</summary>
    public static bool StaticDescriptors => IsEnabled("RPD_OPT_STATIC_DESCRIPTORS", false);

    /// <summary>Opt 4: Run event log startup migrations in the background or fast-check marker file without synchronous event queries.</summary>
    public static bool DeferMigrations => IsEnabled("RPD_OPT_DEFER_MIGRATIONS", true);

    /// <summary>Opt 5: Fast-path SecureProtectedState if ACLs were already verified for this installation.</summary>
    public static bool FastProtectedState => IsEnabled("RPD_OPT_FAST_STATE_CHECK", true);

    /// <summary>Opt 6: Defer post-reboot, workflow, and benchmark resume file queries until after UI settles.</summary>
    public static bool DeferResumes => IsEnabled("RPD_OPT_DEFER_RESUMES", true);

    /// <summary>Opt 7: Add performance-tuning browser arguments to WebView2 (--disable-background-networking, etc.).</summary>
    public static bool WebViewFlags => IsEnabled("RPD_OPT_WEBVIEW_FLAGS", true);

    /// <summary>Opt 8: Memoize and guard Dashboard initial render computations (avoid redundant LINQ queries before data arrives).</summary>
    public static bool DashboardMemoize => IsEnabled("RPD_OPT_DASHBOARD_MEMOIZE", true);

    /// <summary>Opt 9: Defer WMI retrim event queries until Drive Health module is requested.</summary>
    public static bool DeferRetrim => IsEnabled("RPD_OPT_DEFER_RETRIM", true);

    /// <summary>Opt 10: Parallelize bundled module DLL discovery and manifest reading when eager loading is used.</summary>
    public static bool ParallelPluginScan => IsEnabled("RPD_OPT_PARALLEL_PLUGINS", true);
}
