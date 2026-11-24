using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios;

internal static class BiosIdentityFactory
{
    public const string SentinelSerialNumber = "SECRET-SN-DO-NOT-LOG-99887766";

    public static BiosSystemIdentity Hp(
        string manufacturer = "HP",
        string model = "HP EliteBook 840 G8",
        string boardProduct = "880D",
        string biosVersion = "T76 Ver. 01.12.00",
        string osVersion = "Microsoft Windows 11 Pro 10.0.22631",
        string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: manufacturer,
            Model: model,
            SystemSku: "2F8G1AV",
            BoardManufacturer: manufacturer,
            BoardProduct: boardProduct,
            BoardVersion: "KBC Version 12.34",
            SerialNumber: serialNumber,
            OsVersion: osVersion,
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("HP", biosVersion, new DateOnly(2023, 6, 1), "20230601", "3.3", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity Dell(
        string manufacturer = "Dell Inc.",
        string model = "Latitude 7430",
        string systemSku = "0B1A",
        string biosVersion = "1.14.0",
        string osVersion = "Microsoft Windows 11 Pro 10.0.22631",
        string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: manufacturer,
            Model: model,
            SystemSku: systemSku,
            BoardManufacturer: manufacturer,
            BoardProduct: "0ABCDE",
            BoardVersion: "A00",
            SerialNumber: serialNumber,
            OsVersion: osVersion,
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("Dell Inc.", biosVersion, new DateOnly(2023, 8, 15), "20230815", "3.4", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity Lenovo(
        string manufacturer = "LENOVO",
        string model = "20XW003GUS",
        string systemSku = "LENOVO_MT_20XW_BU_Think_FM_ThinkPad X1 Carbon Gen 9",
        string biosVersion = "N32ET89W (1.65 )",
        string osVersion = "Microsoft Windows 11 Pro 10.0.22631",
        string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: manufacturer,
            Model: model,
            SystemSku: systemSku,
            BoardManufacturer: manufacturer,
            BoardProduct: "20XW003GUS",
            BoardVersion: "SDK0T76463 WIN",
            SerialNumber: serialNumber,
            OsVersion: osVersion,
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("LENOVO", biosVersion, new DateOnly(2023, 11, 2), "20231102", "3.2", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity Asus(
        string manufacturer = "ASUSTeK COMPUTER INC.",
        string model = "ROG STRIX Z690-E GAMING WIFI",
        string boardProduct = "ROG STRIX Z690-E GAMING WIFI",
        string biosVersion = "2802",
        string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: manufacturer,
            Model: model,
            SystemSku: "SKU",
            BoardManufacturer: manufacturer,
            BoardProduct: boardProduct,
            BoardVersion: "Rev 1.xx",
            SerialNumber: serialNumber,
            OsVersion: "Microsoft Windows 11 Pro 10.0.22631",
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("American Megatrends Inc.", biosVersion, new DateOnly(2023, 9, 1), "20230901", "3.4", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity Acer(
        string manufacturer = "Acer",
        string model = "Swift SF314-512",
        string boardProduct = "TGL_TL",
        string biosVersion = "V1.10",
        string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: manufacturer,
            Model: model,
            SystemSku: "",
            BoardManufacturer: "TGL",
            BoardProduct: boardProduct,
            BoardVersion: "V1.10",
            SerialNumber: serialNumber,
            OsVersion: "Microsoft Windows 11 Home 10.0.22631",
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("Insyde Corp.", biosVersion, new DateOnly(2023, 7, 10), "20230710", "3.3", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity Msi(
        string manufacturer = "Micro-Star International Co., Ltd.",
        string model = "MS-7D25",
        string boardProduct = "PRO Z690-A WIFI (MS-7D25)",
        string biosVersion = "A.E0",
        string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: manufacturer,
            Model: model,
            SystemSku: "Default string",
            BoardManufacturer: manufacturer,
            BoardProduct: boardProduct,
            BoardVersion: "1.0",
            SerialNumber: serialNumber,
            OsVersion: "Microsoft Windows 11 Pro 10.0.22631",
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("American Megatrends International, LLC.", biosVersion, new DateOnly(2023, 10, 5), "20231005", "3.4", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity MicrosoftSurface(
        string model = "Surface Laptop 5",
        string boardProduct = "Surface Laptop 5",
        string biosVersion = "11.101.143",
        string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: "Microsoft Corporation",
            Model: model,
            SystemSku: "Surface_Laptop_5_1950",
            BoardManufacturer: "Microsoft Corporation",
            BoardProduct: boardProduct,
            BoardVersion: "1.0",
            SerialNumber: serialNumber,
            OsVersion: "Microsoft Windows 11 Pro 10.0.22631",
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("Microsoft Corporation", biosVersion, new DateOnly(2023, 8, 20), "20230820", "3.3", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity HyperVVm(string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: "Microsoft Corporation",
            Model: "Virtual Machine",
            SystemSku: "None",
            BoardManufacturer: "Microsoft Corporation",
            BoardProduct: "Virtual Machine",
            BoardVersion: "Hyper-V UEFI Release v4.1",
            SerialNumber: serialNumber,
            OsVersion: "Microsoft Windows 11 Pro 10.0.22631",
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("Microsoft Corporation", "Hyper-V UEFI Release v4.1", new DateOnly(2023, 5, 1), "20230501", "3.1", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity Framework(
        string model = "Laptop 13 (AMD Ryzen 7040Series)",
        string boardProduct = "FRANMDCP07",
        string biosVersion = "03.03",
        string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: "Framework",
            Model: model,
            SystemSku: "FRANMDCP07",
            BoardManufacturer: "Framework",
            BoardProduct: boardProduct,
            BoardVersion: "A7",
            SerialNumber: serialNumber,
            OsVersion: "Microsoft Windows 11 Pro 10.0.22631",
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("INSYDE Corp.", biosVersion, new DateOnly(2023, 10, 17), "20231017", "3.4", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity GenericUefi(string manufacturer = "Contoso Hardware", string serialNumber = SentinelSerialNumber) =>
        new(
            Manufacturer: manufacturer,
            Model: "Workstation X1",
            SystemSku: "WX1",
            BoardManufacturer: manufacturer,
            BoardProduct: "WX1-MB",
            BoardVersion: "1.0",
            SerialNumber: serialNumber,
            OsVersion: "Microsoft Windows 11 Pro 10.0.22631",
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("AMI", "1.0.0", new DateOnly(2023, 1, 1), "20230101", "3.2", BiosFirmwareMode.Uefi));

    public static BiosSystemIdentity Legacy(string manufacturer = "Contoso Hardware", string serialNumber = SentinelSerialNumber) =>
        GenericUefi(manufacturer, serialNumber) with
        {
            CurrentBios = new BiosCurrentInfo("AMI", "1.0.0", new DateOnly(2020, 1, 1), "20200101", "2.7", BiosFirmwareMode.Legacy),
        };

    public static BiosSystemIdentity Unknown() => BiosSystemIdentity.Empty;

    public static BiosSystemIdentity MaliciousSmbios() =>
        new(
            Manufacturer: "HP; calc.exe && whoami",
            Model: "../../etc/passwd; $(id)",
            SystemSku: "880D & del /f /q C:\\*",
            BoardManufacturer: "HP",
            BoardProduct: "880D; powershell -c calc",
            BoardVersion: "1.0",
            SerialNumber: SentinelSerialNumber,
            OsVersion: "Windows 11",
            Architecture: "x64",
            CurrentBios: new BiosCurrentInfo("HP", "1.0", FirmwareMode: BiosFirmwareMode.Uefi));

    public static BiosSafetySnapshot SafeSnapshot() =>
        new(
            OnAcPower: true,
            HasBattery: true,
            BatteryPercent: 95,
            BitLockerActive: false,
            BitLockerSuspended: false,
            HasElevation: true,
            PendingReboot: false);

    public static BiosInstallRequest CreateInstallRequest(
        BiosSystemIdentity? system = null,
        string? downloadUrl = "https://ftp.hp.com/pub/softpaq/sp150000.exe",
        string? sha256 = null,
        string targetVersion = "01.15.00",
        bool suspendBitLocker = true,
        bool allowReboot = false,
        bool verifyHash = true,
        string? stagingDirectory = null)
    {
        var id = system ?? Hp();
        var target = BiosLatestInfo.UpdateAvailable(
            providerId: "hp",
            latestVersion: targetVersion,
            downloadUrl: downloadUrl,
            sha256: sha256);

        return new BiosInstallRequest(
            System: id,
            Current: id.CurrentBios,
            Target: target,
            Approved: true,
            ApprovedBy: "operator@contoso.com",
            SuspendBitLocker: suspendBitLocker,
            AllowReboot: allowReboot,
            VerifyHash: verifyHash,
            StagingDirectory: stagingDirectory);
    }
}

internal sealed record RecordedHttpRequest(
    HttpMethod Method,
    Uri? RequestUri,
    IReadOnlyDictionary<string, string> Headers);

internal sealed class FakeBiosHttpHandler : HttpMessageHandler
{
    private readonly Lock _lock = new();
    private readonly List<RecordedHttpRequest> _requests = [];
    private readonly List<(Func<HttpRequestMessage, bool> Predicate, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Handler)> _routes = [];

    public IReadOnlyList<RecordedHttpRequest> Requests
    {
        get
        {
            lock (_lock)
                return [.. _requests];
        }
    }

    public FakeBiosHttpHandler MapPredicate(
        Func<HttpRequestMessage, bool> predicate,
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
    {
        _routes.Add((predicate, handler));
        return this;
    }

    public FakeBiosHttpHandler Map(string exactUrl, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) =>
        MapPredicate(req => string.Equals(req.RequestUri?.AbsoluteUri, exactUrl, StringComparison.OrdinalIgnoreCase), handler);

    public FakeBiosHttpHandler MapPrefix(string urlPrefix, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) =>
        MapPredicate(req => req.RequestUri?.AbsoluteUri.StartsWith(urlPrefix, StringComparison.OrdinalIgnoreCase) == true, handler);

    public FakeBiosHttpHandler MapText(string exactUrl, string content, string mediaType = "text/plain", HttpStatusCode status = HttpStatusCode.OK) =>
        Map(exactUrl, (_, _) => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = new StringContent(content, Encoding.UTF8, mediaType),
        }));

    public FakeBiosHttpHandler MapJson(string exactUrl, string json, HttpStatusCode status = HttpStatusCode.OK) =>
        MapText(exactUrl, json, "application/json", status);

    public FakeBiosHttpHandler MapBytes(string exactUrl, byte[] bytes, HttpStatusCode status = HttpStatusCode.OK, bool includeContentLength = true) =>
        Map(exactUrl, (_, _) =>
        {
            HttpContent content = includeContentLength
                ? new ByteArrayContent(bytes)
                : new UnknownLengthStreamContent(bytes);
            return Task.FromResult(new HttpResponseMessage(status) { Content = content });
        });

    public FakeBiosHttpHandler MapRedirect(string exactUrl, string? location, HttpStatusCode status = HttpStatusCode.Redirect) =>
        Map(exactUrl, (_, _) =>
        {
            var msg = new HttpResponseMessage(status);
            if (location is not null)
                msg.Headers.TryAddWithoutValidation("Location", location);
            return Task.FromResult(msg);
        });

    public FakeBiosHttpHandler MapStatus(string exactUrl, HttpStatusCode status, string? body = null) =>
        Map(exactUrl, (_, _) => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = body is null ? new ByteArrayContent([]) : new StringContent(body, Encoding.UTF8, "text/plain"),
        }));

    public FakeBiosHttpHandler MapException(string exactUrl, Func<Exception> exceptionFactory) =>
        Map(exactUrl, (_, _) => Task.FromException<HttpResponseMessage>(exceptionFactory()));

    public HttpClient CreateClient(TimeSpan? timeout = null) =>
        BiosProviderHttp.CreateClient(this, timeout ?? TimeSpan.FromSeconds(10));

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in request.Headers)
            headers[h.Key] = string.Join(", ", h.Value);

        lock (_lock)
            _requests.Add(new RecordedHttpRequest(request.Method, request.RequestUri, headers));

        foreach (var (predicate, handler) in _routes)
        {
            if (predicate(request))
                return handler(request, cancellationToken);
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    private sealed class UnknownLengthStreamContent(byte[] data) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(data, 0, data.Length);

        protected override bool TryComputeLength(out long length)
        {
            length = -1;
            return false;
        }
    }
}

internal sealed record RecordedProcessCall(
    string FileName,
    string BaseName,
    IReadOnlyList<string> Arguments,
    TimeSpan Timeout,
    string? WorkingDirectory);

internal sealed class RecordingProcessLauncher : IProcessLauncher
{
    private readonly Lock _lock = new();
    private readonly List<RecordedProcessCall> _calls = [];
    private readonly Func<RecordedProcessCall, CancellationToken, Task<ProcessResult>> _handler;

    public RecordingProcessLauncher(Func<RecordedProcessCall, CancellationToken, Task<ProcessResult>>? handler = null)
    {
        _handler = handler ?? ((_, _) => Task.FromResult(new ProcessResult(0, "", "")));
    }

    public RecordingProcessLauncher(Func<RecordedProcessCall, ProcessResult> handler)
        : this((call, _) => Task.FromResult(handler(call)))
    {
    }

    public IReadOnlyList<RecordedProcessCall> Calls
    {
        get
        {
            lock (_lock)
                return [.. _calls];
        }
    }

    public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
        RunCoreAsync(fileName, arguments, timeout, cancellationToken, workingDirectory: null);

    public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken, string? workingDirectory) =>
        RunCoreAsync(fileName, arguments, timeout, cancellationToken, workingDirectory);

    public static SystemCommandRunner CreateCommandRunner(
        RecordingProcessLauncher launcher,
        ILogger? log = null,
        TimeSpan? timeout = null,
        bool isProcessElevated = true,
        IElevatedCommandBridge? elevatedBridge = null) =>
        new(
            launcher: launcher,
            log: log,
            timeout: timeout,
            elevatedBridge: elevatedBridge,
            isProcessElevated: () => isProcessElevated);

    private Task<ProcessResult> RunCoreAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct,
        string? workingDirectory)
    {
        var baseName = fileName.Replace('\\', '/').Split('/')[^1];
        var call = new RecordedProcessCall(fileName, baseName, [.. arguments], timeout, workingDirectory);
        lock (_lock)
            _calls.Add(call);

        if (SimulateVendorUnpack)
            FakeVendorUnpack.Apply(arguments);
        return _handler(call, ct);
    }

    /// <summary>When true, an HP SoftPaq or Lenovo package run with its unpack arguments leaves its inner flasher behind, as the real ones do.</summary>
    public bool SimulateVendorUnpack { get; set; } = false;
}

/// <summary>
/// What a real HP SoftPaq (<c>-e -f&lt;dir&gt;</c>) or Lenovo Inno package (<c>/EXTRACT=YES /DIR=&lt;dir&gt;</c>) leaves when asked to unpack:
/// its inner BIOS flasher. The Agent runs that flasher, never the package a second time.
/// </summary>
internal static class FakeVendorUnpack
{
    public static void Apply(IReadOnlyList<string> arguments)
    {
        string? dir = null, flasher = null;
        if (arguments.Contains("-e"))
        {
            dir = arguments.FirstOrDefault(a => a.StartsWith("-f", StringComparison.OrdinalIgnoreCase))?[2..];
            flasher = "HpFirmwareUpdRec64.exe";
        }
        else if (arguments.Contains("/EXTRACT=YES", StringComparer.OrdinalIgnoreCase))
        {
            dir = arguments.FirstOrDefault(a => a.StartsWith("/DIR=", StringComparison.OrdinalIgnoreCase))?[5..];
            flasher = "WINUPTP64.exe";
        }
        if (dir is null || flasher is null || !Directory.Exists(dir))
            return;
        var path = Path.Combine(dir, flasher);
        if (!File.Exists(path))
            File.WriteAllText(path, "fake-inner-flasher");
    }
}

internal sealed class TempStagingDir : IDisposable
{
    public string Path { get; }

    public TempStagingDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"rpd-bios-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path);
    }

    public string FilePath(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Path))
                Directory.Delete(Path, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}

internal sealed record TestPayload(byte[] Bytes, string Sha256)
{
    public long Length => Bytes.LongLength;

    public static TestPayload FromBytes(byte[] bytes)
    {
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return new TestPayload(bytes, hash);
    }

    public static TestPayload FromString(string text) => FromBytes(Encoding.UTF8.GetBytes(text));

    public static TestPayload Random(int length, int seed = 42)
    {
        var rng = new Random(seed);
        var bytes = new byte[length];
        rng.NextBytes(bytes);
        return FromBytes(bytes);
    }

    public static byte[] CreateGzip(byte[] uncompressed)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            gz.Write(uncompressed, 0, uncompressed.Length);
        return ms.ToArray();
    }
}

internal sealed class CapturedLog
{
    private readonly Lock _lock = new();
    private readonly List<string> _lines = [];

    public ILogger Logger { get; }

    public CapturedLog()
    {
        Logger = new LineLogger(line =>
        {
            lock (_lock)
                _lines.Add(line);
        });
    }

    public IReadOnlyList<string> Lines
    {
        get
        {
            lock (_lock)
                return [.. _lines];
        }
    }

    public string AllText => string.Join("\n", Lines);

    public bool Contains(string fragment) =>
        AllText.Contains(fragment, StringComparison.OrdinalIgnoreCase);

    public void AssertDoesNotContainSecret(string secret = BiosIdentityFactory.SentinelSerialNumber)
    {
        Assert.DoesNotContain(secret, AllText, StringComparison.OrdinalIgnoreCase);
    }
}

internal sealed class SyncProgress<T> : IProgress<T>
{
    private readonly Lock _lock = new();
    private readonly List<T> _reports = [];
    private readonly Action<T>? _callback;

    public SyncProgress(Action<T>? callback = null) => _callback = callback;

    public IReadOnlyList<T> Reports
    {
        get
        {
            lock (_lock)
                return [.. _reports];
        }
    }

    public void Report(T value)
    {
        lock (_lock)
            _reports.Add(value);
        _callback?.Invoke(value);
    }
}

internal sealed class FakeSignatureVerifier : IBiosSignatureVerifier
{
    private readonly Lock _lock = new();
    private readonly List<string> _verifiedPaths = [];
    private readonly List<(string CatalogPath, string MemberFilePath, IReadOnlyCollection<string> AllowedSigners)> _catalogMemberChecks = [];
    private readonly Func<string, CancellationToken, Task<bool>> _impl;
    private readonly Func<string, string, IReadOnlyCollection<string>, CancellationToken, Task<bool>>? _catalogMemberImpl;

    public FakeSignatureVerifier(bool result = true)
        : this((_, _) => Task.FromResult(result))
    {
    }

    public FakeSignatureVerifier(
        Func<string, CancellationToken, Task<bool>> impl,
        Func<string, string, IReadOnlyCollection<string>, CancellationToken, Task<bool>>? catalogMemberImpl = null)
    {
        _impl = impl;
        _catalogMemberImpl = catalogMemberImpl;
    }

    public IReadOnlyList<string> VerifiedPaths
    {
        get
        {
            lock (_lock)
                return [.. _verifiedPaths];
        }
    }

    public IReadOnlyList<(string CatalogPath, string MemberFilePath, IReadOnlyCollection<string> AllowedSigners)> CatalogMemberChecks
    {
        get
        {
            lock (_lock)
                return [.. _catalogMemberChecks];
        }
    }

    public int CallCount => VerifiedPaths.Count;

    public Task<bool> VerifyAuthenticodeAsync(string filePath, CancellationToken ct = default)
    {
        lock (_lock)
            _verifiedPaths.Add(filePath);
        return _impl(filePath, ct);
    }

    /// <summary>The signer allowlist passed with each pinned verification, in call order.</summary>
    public List<IReadOnlyCollection<string>> AllowedSignerSets { get; } = [];

    public Task<bool> VerifyAuthenticodeAsync(string filePath, IReadOnlyCollection<string> allowedSignerOrganizations, CancellationToken ct = default)
    {
        lock (_lock)
            AllowedSignerSets.Add(allowedSignerOrganizations);
        return VerifyAuthenticodeAsync(filePath, ct);
    }

    public Task<bool> VerifyCatalogMemberAsync(
        string catalogPath,
        string memberFilePath,
        IReadOnlyCollection<string> allowedSignerOrganizations,
        CancellationToken ct = default)
    {
        lock (_lock)
            _catalogMemberChecks.Add((catalogPath, memberFilePath, allowedSignerOrganizations));

        if (_catalogMemberImpl is not null)
            return _catalogMemberImpl(catalogPath, memberFilePath, allowedSignerOrganizations, ct);

        return VerifyAuthenticodeAsync(catalogPath, allowedSignerOrganizations, ct);
    }
}

internal sealed class FakeWindowsUpdateClient : IBiosWindowsUpdateClient
{
    private readonly Lock _lock = new();
    private readonly List<Guid> _installedUpdateIds = [];

    public Func<CancellationToken, Task<IReadOnlyList<BiosWuaFirmwareUpdate>>> SearchHandler { get; set; } =
        _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>([]);

    public Func<Guid, CancellationToken, Task<BiosWuaInstallOutcome>> InstallHandler { get; set; } =
        (id, _) => Task.FromResult(new BiosWuaInstallOutcome(true, 2, true, $"Installed {id}"));

    public IReadOnlyList<Guid> InstalledUpdateIds
    {
        get
        {
            lock (_lock)
                return [.. _installedUpdateIds];
        }
    }

    public Task<IReadOnlyList<BiosWuaFirmwareUpdate>> SearchPendingFirmwareUpdatesAsync(CancellationToken ct = default) =>
        SearchHandler(ct);

    /// <summary>The online search; null searches the same way as the cache (<see cref="SearchHandler"/>).</summary>
    public Func<CancellationToken, Task<IReadOnlyList<BiosWuaFirmwareUpdate>>>? OnlineSearchHandler { get; set; }

    /// <summary>When Windows Update last finished a scan; null = Windows doesn't say.</summary>
    public DateTimeOffset? LastScanUtc { get; set; }

    public List<bool> SearchModes { get; } = [];

    public Task<IReadOnlyList<BiosWuaFirmwareUpdate>> SearchPendingFirmwareUpdatesAsync(bool online, CancellationToken ct)
    {
        lock (_lock)
            SearchModes.Add(online);
        return online && OnlineSearchHandler is { } h ? h(ct) : SearchHandler(ct);
    }

    public Task<DateTimeOffset?> GetLastSuccessfulScanUtcAsync(CancellationToken ct = default) => Task.FromResult(LastScanUtc);

    public Task<BiosWuaInstallOutcome> InstallUpdateAsync(Guid updateId, CancellationToken ct = default)
    {
        lock (_lock)
            _installedUpdateIds.Add(updateId);
        return InstallHandler(updateId, ct);
    }
}

internal static class TestCabBuilder
{
    public static byte[] CreateUncompressed(
        IReadOnlyDictionary<string, byte[]> files,
        ushort headerReserve = 0,
        byte folderReserve = 0,
        byte dataReserve = 0,
        int maxBlockSize = 32768) =>
        BuildCab(files, typeCompress: 0, headerReserve, folderReserve, dataReserve, maxBlockSize);

    public static byte[] CreateMsZip(
        IReadOnlyDictionary<string, byte[]> files,
        ushort headerReserve = 0,
        byte folderReserve = 0,
        byte dataReserve = 0,
        int maxBlockSize = 32768) =>
        BuildCab(files, typeCompress: 1, headerReserve, folderReserve, dataReserve, maxBlockSize);

    public static byte[] CreateWithUnsupportedCompression(string fileName, byte[] payload, ushort typeCompress = 3) =>
        BuildCab(new Dictionary<string, byte[]> { [fileName] = payload }, typeCompress, 0, 0, 0, 32768);

    /// <summary>
    /// Builds a valid MS-CAB archive with <c>TYPE_LZX</c> (window size 21, <c>0x1503</c>) encoding each CFDATA block
    /// as a spec-compliant LZX uncompressed block (block type 3) so pure-C# LZX decompression can be unit-tested.
    /// </summary>
    public static byte[] CreateLzxUncompressed(IReadOnlyDictionary<string, byte[]> files, int maxBlockSize = 32768) =>
        BuildCab(files, typeCompress: 0x1503, 0, 0, 0, maxBlockSize);

    private static byte[] BuildCab(
        IReadOnlyDictionary<string, byte[]> files,
        ushort typeCompress,
        ushort headerReserve,
        byte folderReserve,
        byte dataReserve,
        int maxBlockSize)
    {
        var orderedFiles = files.ToList();
        using var folderStream = new MemoryStream();
        var fileOffsets = new List<(string Name, uint Offset, uint Size)>(orderedFiles.Count);

        foreach (var (name, content) in orderedFiles)
        {
            var offset = (uint)folderStream.Position;
            folderStream.Write(content, 0, content.Length);
            fileOffsets.Add((name, offset, (uint)content.Length));
        }

        var folderBytes = folderStream.ToArray();
        var blocks = new List<(byte[] Compressed, ushort UncompLen)>();
        var pos = 0;
        var isFirstBlock = true;
        do
        {
            var chunkLen = Math.Min(maxBlockSize, folderBytes.Length - pos);
            var chunk = new byte[chunkLen];
            if (chunkLen > 0)
                Buffer.BlockCopy(folderBytes, pos, chunk, 0, chunkLen);

            byte[] blockPayload;
            if (typeCompress == 1)
            {
                using var deflateMs = new MemoryStream();
                deflateMs.WriteByte((byte)'C');
                deflateMs.WriteByte((byte)'K');
                using (var deflate = new DeflateStream(deflateMs, CompressionLevel.Optimal, leaveOpen: true))
                    deflate.Write(chunk, 0, chunk.Length);
                blockPayload = deflateMs.ToArray();
            }
            else if (typeCompress == 0x1503)
            {
                blockPayload = EncodeLzxUncompressedBlock(chunk, isFirstBlock);
            }
            else
            {
                blockPayload = chunk;
            }

            blocks.Add((blockPayload, (ushort)chunkLen));
            pos += chunkLen;
            isFirstBlock = false;
        }
        while (pos < folderBytes.Length);

        var hasReserve = headerReserve > 0 || folderReserve > 0 || dataReserve > 0;
        ushort flags = hasReserve ? (ushort)0x0004 : (ushort)0;

        using var cfFilesMs = new MemoryStream();
        foreach (var (name, offset, size) in fileOffsets)
        {
            WriteUInt32(cfFilesMs, size);
            WriteUInt32(cfFilesMs, offset);
            WriteUInt16(cfFilesMs, 0); // iFolder
            WriteUInt16(cfFilesMs, 0); // date
            WriteUInt16(cfFilesMs, 0); // time
            WriteUInt16(cfFilesMs, 0x0080); // ATTRIB_NAME_IS_UTF
            var nameBytes = Encoding.UTF8.GetBytes(name);
            cfFilesMs.Write(nameBytes, 0, nameBytes.Length);
            cfFilesMs.WriteByte(0);
        }
        var cfFilesBytes = cfFilesMs.ToArray();

        using var cfDataMs = new MemoryStream();
        foreach (var (compressed, uncompLen) in blocks)
        {
            WriteUInt32(cfDataMs, 0); // csum
            WriteUInt16(cfDataMs, (ushort)compressed.Length);
            WriteUInt16(cfDataMs, uncompLen);
            if (dataReserve > 0)
                cfDataMs.Write(new byte[dataReserve], 0, dataReserve);
            cfDataMs.Write(compressed, 0, compressed.Length);
        }
        var cfDataBytes = cfDataMs.ToArray();

        var headerSize = 36 + (hasReserve ? 4 + headerReserve : 0);
        var folderSize = 8 + folderReserve;
        var coffFiles = (uint)(headerSize + folderSize);
        var coffCabStart = coffFiles + (uint)cfFilesBytes.Length;
        var cbCabinet = coffCabStart + (uint)cfDataBytes.Length;

        using var cab = new MemoryStream((int)cbCabinet);
        cab.Write("MSCF"u8);
        WriteUInt32(cab, 0); // reserved1
        WriteUInt32(cab, cbCabinet);
        WriteUInt32(cab, 0); // reserved2
        WriteUInt32(cab, coffFiles);
        WriteUInt32(cab, 0); // reserved3
        cab.WriteByte(3); // versionMinor
        cab.WriteByte(1); // versionMajor
        WriteUInt16(cab, 1); // cFolders
        WriteUInt16(cab, (ushort)fileOffsets.Count); // cFiles
        WriteUInt16(cab, flags);
        WriteUInt16(cab, 1); // setID
        WriteUInt16(cab, 0); // iCabinet

        if (hasReserve)
        {
            WriteUInt16(cab, headerReserve);
            cab.WriteByte(folderReserve);
            cab.WriteByte(dataReserve);
            if (headerReserve > 0)
                cab.Write(new byte[headerReserve], 0, headerReserve);
        }

        // CFFOLDER
        WriteUInt32(cab, coffCabStart);
        WriteUInt16(cab, (ushort)blocks.Count);
        WriteUInt16(cab, typeCompress);
        if (folderReserve > 0)
            cab.Write(new byte[folderReserve], 0, folderReserve);

        cab.Write(cfFilesBytes, 0, cfFilesBytes.Length);
        cab.Write(cfDataBytes, 0, cfDataBytes.Length);

        return cab.ToArray();
    }

    private static byte[] EncodeLzxUncompressedBlock(byte[] chunk, bool isFirstBlock)
    {
        using var ms = new MemoryStream();
        uint bitBuf = 0;
        var bitCount = 0;

        void WriteBits(uint value, int count)
        {
            bitBuf = (bitBuf << count) | (value & ((1u << count) - 1));
            bitCount += count;
            while (bitCount >= 16)
            {
                bitCount -= 16;
                var word = (ushort)((bitBuf >> bitCount) & 0xFFFF);
                WriteUInt16(ms, word);
            }
        }

        if (isFirstBlock)
            WriteBits(0, 1); // intelFlag = 0
        WriteBits(3, 3); // BlockTypeUncompressed
        WriteBits((uint)((chunk.Length >> 8) & 0xFFFF), 16);
        WriteBits((uint)(chunk.Length & 0xFF), 8);

        if (bitCount > 0)
            WriteBits(0, 16 - bitCount);

        WriteUInt32(ms, 1); // R0
        WriteUInt32(ms, 1); // R1
        WriteUInt32(ms, 1); // R2
        ms.Write(chunk, 0, chunk.Length);
        if ((chunk.Length & 1) != 0)
            ms.WriteByte(0);

        return ms.ToArray();
    }

    private static void WriteUInt16(Stream s, ushort v)
    {
        Span<byte> buf = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buf, v);
        s.Write(buf);
    }

    private static void WriteUInt32(Stream s, uint v)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, v);
        s.Write(buf);
    }
}
