using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Core.Benchmarks;

public enum HardwareSyncOutcome
{
    Skipped,
    Unchanged,
    Uploaded,
    Failed,
}

/// <summary>
/// Uploads this PC's hardware specification snapshot once on first Agent connect, and again only if the hardware changes
/// (detected via SHA-256 of the serialized <see cref="BenchmarkHardware"/> stored in <c>hardware-sent.sha256</c>).
/// </summary>
public static class HardwareSyncService
{
    public const string StampFileName = "hardware-sent.sha256";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string ComputeHash(BenchmarkHardware hardware)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(hardware, Json));
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    public static async Task<HardwareSyncOutcome> SyncIfChangedAsync(
        Uri relayUri,
        string apiKey,
        string machineId,
        string machineName,
        string stateFolder,
        Func<BenchmarkHardware>? readHardware = null,
        Func<Uri, string, string, string, BenchmarkHardware, CancellationToken, Task<bool>>? upload = null,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var trimmedKey = apiKey?.Trim() ?? "";
        if (!trimmedKey.StartsWith(ShopRelayClient.ApiKeyPrefix, StringComparison.Ordinal) || trimmedKey.Length <= ShopRelayClient.ApiKeyPrefix.Length)
            return HardwareSyncOutcome.Skipped;
        if (string.IsNullOrWhiteSpace(machineId))
            return HardwareSyncOutcome.Skipped;

        BenchmarkHardware hw;
        try
        {
            if (readHardware is not null)
                hw = readHardware();
            else if (OperatingSystem.IsWindows())
                hw = HardwareIdentityProbe.ReadWindows();
            else
                return HardwareSyncOutcome.Skipped;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log?.Invoke($"Hardware snapshot read failed: {ex.Message}");
            return HardwareSyncOutcome.Failed;
        }

        // Don't upload an empty snapshot.
        if (string.IsNullOrWhiteSpace(hw.Processor) && string.IsNullOrWhiteSpace(hw.Model) && hw.MemoryGb is null)
            return HardwareSyncOutcome.Skipped;

        var hash = ComputeHash(hw);
        var stampPath = Path.Combine(stateFolder, StampFileName);
        try
        {
            if (File.Exists(stampPath) && string.Equals((await File.ReadAllTextAsync(stampPath, ct).ConfigureAwait(false)).Trim(), hash, StringComparison.OrdinalIgnoreCase))
                return HardwareSyncOutcome.Unchanged;
        }
        catch (Exception) when (!ct.IsCancellationRequested) { }

        bool ok;
        try
        {
            if (upload is not null)
            {
                ok = await upload(relayUri, trimmedKey, machineId, machineName, hw, ct).ConfigureAwait(false);
            }
            else
            {
                var client = new ShopRelayClient();
                ok = await client.UploadHardwareAsync(relayUri, trimmedKey, machineId, machineName, hw, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            log?.Invoke($"Hardware snapshot upload failed: {ex.Message}");
            return HardwareSyncOutcome.Failed;
        }

        if (!ok)
            return HardwareSyncOutcome.Failed;

        try
        {
            Directory.CreateDirectory(stateFolder);
            await File.WriteAllTextAsync(stampPath, hash, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log?.Invoke($"Could not write hardware sync stamp: {ex.Message}");
        }

        log?.Invoke($"Synced hardware specs for {machineName} ({hw.Manufacturer} {hw.Model}).");
        return HardwareSyncOutcome.Uploaded;
    }
}
