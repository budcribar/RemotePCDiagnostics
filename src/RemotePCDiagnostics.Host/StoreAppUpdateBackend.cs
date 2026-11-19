using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Extensions.Logging;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Logging;
using Windows.Services.Store;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Microsoft Store (MSIX) update backend using <see cref="StoreContext"/>. Checks whether the Store has a newer
/// package available and triggers silent download/install (falling back to the native Store prompt when silent
/// updates are disallowed by metered-network or Store settings).
/// </summary>
internal sealed class StoreAppUpdateBackend : IStoreUpdateBackend
{
    private const int AppModelErrorNoPackage = 15700;

    private readonly ILogger? _log;
    private readonly Lazy<bool> _isPackaged;

    public StoreAppUpdateBackend(ILogger? log = null)
    {
        _log = log;
        _isPackaged = new Lazy<bool>(DetectPackagedApp);
    }

    public bool IsPackagedStoreApp => _isPackaged.Value;

    public async Task<StoreUpdateCheckResult> CheckForUpdateAsync(CancellationToken ct = default)
    {
        if (!IsPackagedStoreApp)
            return new StoreUpdateCheckResult(false, false);

        var context = CreateStoreContext();
        var updates = await context.GetAppAndOptionalStorePackageUpdatesAsync().AsTask(ct).ConfigureAwait(false);
        return new StoreUpdateCheckResult(
            UpdateAvailable: updates.Count > 0,
            CanInstallSilently: context.CanSilentlyDownloadStorePackageUpdates,
            LatestVersion: updates.Count > 0 ? "Microsoft Store update" : null);
    }

    public async Task<AppUpdateResult> DownloadAndInstallAsync(Action<AppUpdateProgress>? progress = null, CancellationToken ct = default)
    {
        if (!IsPackagedStoreApp)
            return new AppUpdateResult(false, Error: "This installation is not managed by the Microsoft Store.");

        try
        {
            var context = CreateStoreContext();
            var updates = await context.GetAppAndOptionalStorePackageUpdatesAsync().AsTask(ct).ConfigureAwait(false);
            if (updates.Count == 0)
                return new AppUpdateResult(false, Error: "Remote PC Diagnostics is already up to date in the Microsoft Store.");

            progress?.Invoke(new AppUpdateProgress("downloading", 0, "Downloading update from Microsoft Store..."));

            var operation = context.CanSilentlyDownloadStorePackageUpdates
                ? context.TrySilentDownloadAndInstallStorePackageUpdatesAsync(updates)
                : context.RequestDownloadAndInstallStorePackageUpdatesAsync(updates);

            operation.Progress = (_, status) =>
            {
                var percent = status.TotalDownloadProgress > 0
                    ? (int)Math.Clamp(Math.Round(status.TotalDownloadProgress * 100.0), 0, 100)
                    : (int?)null;
                var stage = status.PackageUpdateState == StorePackageUpdateState.Deploying ? "installing" : "downloading";
                var msg = stage == "installing"
                    ? "Installing Microsoft Store update..."
                    : percent is int p ? $"Downloading from Microsoft Store ({p}%)..." : "Downloading from Microsoft Store...";
                progress?.Invoke(new AppUpdateProgress(stage, percent, msg));
            };

            var result = await operation.AsTask(ct).ConfigureAwait(false);
            return result.OverallState switch
            {
                StorePackageUpdateState.Completed => new AppUpdateResult(true, Restarting: true, Message: "Microsoft Store update installed."),
                StorePackageUpdateState.Canceled => new AppUpdateResult(false, Error: "Microsoft Store update was canceled."),
                StorePackageUpdateState.ErrorLowBattery => new AppUpdateResult(false, Error: "Battery is too low to install the Microsoft Store update."),
                StorePackageUpdateState.ErrorWiFiRecommended or StorePackageUpdateState.ErrorWiFiRequired =>
                    new AppUpdateResult(false, Error: "Microsoft Store requires an unmetered Wi-Fi connection to download this update."),
                _ => new AppUpdateResult(false, Error: $"Microsoft Store update failed ({result.OverallState})."),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.Warn($"[store-update] Store update failed: {ex.Message}");
            return new AppUpdateResult(false, Error: ex.Message);
        }
    }

    private static StoreContext CreateStoreContext()
    {
        var context = StoreContext.GetDefault();
        var hwnd = TryGetMainWindowHandle();
        if (hwnd != nint.Zero)
            WinRT.Interop.InitializeWithWindow.Initialize(context, hwnd);
        return context;
    }

    private static nint TryGetMainWindowHandle()
    {
        try
        {
            var app = Application.Current;
            if (app is null)
                return nint.Zero;
            return app.Dispatcher.Invoke(() =>
            {
                var main = app.MainWindow;
                return main is null ? nint.Zero : new WindowInteropHelper(main).Handle;
            });
        }
        catch
        {
            return nint.Zero;
        }
    }

    private static bool DetectPackagedApp()
    {
        if (!OperatingSystem.IsWindows())
            return false;
        try
        {
            uint length = 0;
            var rc = GetCurrentPackageFullName(ref length, null);
            return rc != AppModelErrorNoPackage && length > 0;
        }
        catch
        {
            return false;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int GetCurrentPackageFullName(ref uint packageFullNameLength, char[]? packageFullName);
}
