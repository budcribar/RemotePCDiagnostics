using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>Raw x86 port access used for the ACPI embedded controller (Host: PawnIO LpcACPIEC module).</summary>
public interface IEcPortIo : IDisposable
{
    byte ReadPort(byte port);
    void WritePort(byte port, byte value);
}

/// <summary>Cross-process EC lock (Host: the shared "Global\Access_EC" mutex). Enter and Exit happen on the same thread.</summary>
public interface IEcLock
{
    bool TryEnter(TimeSpan timeout);
    void Exit();
}

/// <summary>Model-gated, read-only fan readings from the laptop's embedded controller. Never throws.</summary>
public interface IEcFanSource : IDisposable
{
    /// <summary>Plausible fan readings (may be empty). Polls the EC at most once per poll interval; otherwise returns the cached result.</summary>
    IReadOnlyList<SensorReading> Read();
    /// <summary>While on (CPU stress test), every raw EC sample is written to the log.</summary>
    void SetStressLogging(bool on);
}

/// <summary>Used when no EC source applies (non-Windows, tests).</summary>
public sealed class NoEcFanSource : IEcFanSource
{
    public IReadOnlyList<SensorReading> Read() => [];
    public void SetStressLogging(bool on) { }
    public void Dispose() { }
}

/// <summary>
/// Standard ACPI EC "read" transaction (ACPI spec 12.3.1) over ports 0x66 (command/status) and 0x62 (data).
/// Read-only by construction: the only port writes it can issue are the read command 0x80 to 0x66 and an
/// allowlisted EC address to 0x62. Any other address throws before a port is touched. Returns null on timeout.
/// </summary>
public sealed class AcpiEcReader(IEcPortIo io, TimeSpan? stepTimeout = null, int maxPolls = 5000)
{
    public const byte DataPort = 0x62, CommandPort = 0x66, ReadCommand = 0x80;
    private const byte Obf = 0x01, Ibf = 0x02;

    /// <summary>Lenovo IdeaPad 1 15ALC7 (82R4) DSDT, Device EC0, OperationRegion ERAX:
    /// 0x06 FANS, 0xFE FA2S, 0xAB flags (bit4 FAN1, bit5 FAN2, bit6 FAOK), 0xAD (low nibble SPDN, high nibble FNUM).</summary>
    public static readonly IReadOnlySet<byte> AllowedAddresses = new HashSet<byte> { 0x06, 0xFE, 0xAB, 0xAD };

    private readonly TimeSpan _step = stepTimeout ?? TimeSpan.FromMilliseconds(20);

    public byte? TryRead(byte address)
    {
        if (!AllowedAddresses.Contains(address)) throw new ArgumentOutOfRangeException(nameof(address), $"EC address 0x{address:X2} is not on the read allowlist.");
        if ((Status() & Obf) != 0) io.ReadPort(DataPort); // drain a stale byte (read only)
        if (!Wait(s => (s & Ibf) == 0)) return null;
        Write(CommandPort, ReadCommand);
        if (!Wait(s => (s & Ibf) == 0)) return null;
        Write(DataPort, address);
        if (!Wait(s => (s & Obf) != 0)) return null;
        return io.ReadPort(DataPort);
    }

    private byte Status() => io.ReadPort(CommandPort);

    private void Write(byte port, byte value)
    {
        var ok = (port == CommandPort && value == ReadCommand) || (port == DataPort && AllowedAddresses.Contains(value));
        if (!ok) throw new InvalidOperationException($"Blocked EC port write 0x{value:X2} -> 0x{port:X2}.");
        io.WritePort(port, value);
    }

    private bool Wait(Func<byte, bool> ready)
    {
        var sw = Stopwatch.StartNew();
        for (var i = 0; i < maxPolls; i++)
        {
            if (ready(Status())) return true;
            if (sw.Elapsed > _step) return false;
            Thread.SpinWait(20);
        }
        return false;
    }
}

/// <summary>Per-fan plausibility: raw byte = RPM/100. 0xFF/out-of-range never shown; 0 is shown only after a non-zero reading this session.</summary>
public sealed class EcFanPlausibility
{
    /// <summary>Highest raw value treated as real (8000 RPM); laptop fans run well below this.</summary>
    public const byte MaxPlausibleRaw = 80;
    private byte? _first;
    public bool SeenNonZero { get; private set; }
    public bool SeenChange { get; private set; }

    /// <summary>Records a raw sample and returns the RPM to show, or null to keep the fan hidden.</summary>
    public double? Accept(byte raw)
    {
        if (raw > MaxPlausibleRaw) return null;
        if (_first is null) _first = raw; else if (_first != raw) SeenChange = true;
        if (raw > 0) SeenNonZero = true;
        return raw > 0 || SeenNonZero ? raw * 100.0 : null;
    }
}

/// <summary>
/// EC fan diagnostic for ONE model: Lenovo IdeaPad 1 15ALC7 (Win32_ComputerSystemProduct.Name "82R4").
/// Hypothesis (unverified on hardware): EC RAM 0x06 = CPU fan RPM/100 and 0xFE = second fan RPM/100.
/// </summary>
public sealed class EcFanMonitor : IEcFanSource
{
    public const string SupportedModel = "82R4";
    public const string HardwareName = "Laptop controller";
    public const string CpuFanName = "CPU fan (from laptop controller)";
    public const string Fan2Name = "Fan 2 (from laptop controller)";
    public static readonly TimeSpan MinPollInterval = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan BackoffTime = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan SummaryInterval = TimeSpan.FromSeconds(30);
    public const int HistoryLength = 15;

    private readonly Func<string?> _model;
    private readonly Func<(bool Available, string Detail)> _pawnIo;
    private readonly Func<IEcPortIo> _ioFactory;
    private readonly IEcLock _lock;
    private readonly Action<string>? _log;
    private readonly Func<DateTimeOffset> _now;
    private readonly TimeSpan _interval;
    private readonly TimeSpan _lockTimeout;
    private readonly TimeSpan? _stepTimeout;
    private readonly object _gate = new();

    private bool _initDone, _enabled, _firstSampleLogged, _stressLogging, _disposed;
    private IEcPortIo? _io;
    private DateTimeOffset? _lastPoll, _lastSummary;
    private DateTimeOffset _backoffUntil = DateTimeOffset.MinValue;
    private int _consecutiveFailures;
    private IReadOnlyList<SensorReading> _cached = [];
    private readonly EcFanPlausibility _fan1 = new(), _fan2 = new();
    private readonly RawStats _raw1 = new(), _raw2 = new();
    private double? _min1, _max1, _min2, _max2;

    public EcFanMonitor(Func<string?> model, Func<(bool Available, string Detail)> pawnIo, Func<IEcPortIo> ioFactory, IEcLock ecLock,
        Action<string>? log = null, Func<DateTimeOffset>? now = null, TimeSpan? pollInterval = null, TimeSpan? lockTimeout = null, TimeSpan? stepTimeout = null)
    {
        _model = model; _pawnIo = pawnIo; _ioFactory = ioFactory; _lock = ecLock; _log = log;
        _now = now ?? (() => DateTimeOffset.Now);
        var p = pollInterval ?? TimeSpan.FromSeconds(2);
        _interval = p < MinPollInterval ? MinPollInterval : p;
        _lockTimeout = lockTimeout ?? TimeSpan.FromMilliseconds(100);
        _stepTimeout = stepTimeout;
    }

    public bool IsEnabled { get { lock (_gate) return _enabled; } }
    public bool IsBackingOff { get { lock (_gate) return _now() < _backoffUntil; } }
    public TimeSpan PollInterval => _interval;

    public void SetStressLogging(bool on)
    {
        lock (_gate)
        {
            if (_stressLogging == on) return;
            _stressLogging = on;
            if (_enabled) Log($"Fan diagnostic: CPU stress test {(on ? "started, logging every EC fan sample" : "ended")}; {Summary()}");
        }
    }

    public IReadOnlyList<SensorReading> Read()
    {
        try
        {
            lock (_gate)
            {
                if (_disposed) return [];
                if (!_initDone) Init();
                if (!_enabled) return [];
                var now = _now();
                if (now < _backoffUntil) return _cached;
                if (_lastPoll is { } last && now - last < _interval) return _cached;
                _lastPoll = now;
                Poll(now);
                return _cached;
            }
        }
        catch (Exception ex) { Log($"Fan diagnostic: unexpected error, EC fan reading turned off: {ex}"); Disable(); return []; }
    }

    private void Init()
    {
        _initDone = true;
        string? model;
        try { model = _model()?.Trim(); } catch (Exception ex) { Log($"Fan diagnostic: model check failed: {ex.Message}"); return; }
        if (!string.Equals(model, SupportedModel, StringComparison.OrdinalIgnoreCase)) return; // other models: stay silent and off
        (bool Available, string Detail) pawn;
        try { pawn = _pawnIo(); } catch (Exception ex) { pawn = (false, ex.Message); }
        Log($"Fan diagnostic: model={model} (Lenovo IdeaPad 1 15ALC7); PawnIO {(pawn.Available ? "available" : "not available")}: {pawn.Detail}");
        if (!pawn.Available) return;
        try { _io = _ioFactory(); }
        catch (Exception ex) { Log($"Fan diagnostic: PawnIO LpcACPIEC module could not be loaded, EC fan reading off: {ex.GetType().Name}: {ex.Message}"); return; }
        _enabled = true;
        Log($"Fan diagnostic: PawnIO LpcACPIEC module loaded; reading EC addresses {string.Join(", ", AcpiEcReader.AllowedAddresses.Select(a => $"0x{a:X2}"))} (read command 0x80 only) every {_interval.TotalSeconds:0.#}s");
    }

    private void Poll(DateTimeOffset now)
    {
        byte? f1 = null, f2 = null, flags = null, nums = null;
        string? failure = null;
        bool entered;
        try { entered = _lock.TryEnter(_lockTimeout); }
        catch (Exception ex) { entered = false; failure = $"EC mutex error: {ex.Message}"; }
        if (!entered) failure ??= "EC mutex busy (Global\\Access_EC)";
        else
        {
            try
            {
                var r = new AcpiEcReader(_io!, _stepTimeout);
                f1 = r.TryRead(0x06);
                f2 = f1 is null ? null : r.TryRead(0xFE);
                if (f2 is not null) { flags = r.TryRead(0xAB); nums = r.TryRead(0xAD); }
                if (f1 is null || f2 is null) failure = "EC protocol timeout";
            }
            catch (Exception ex) { failure = $"EC read error: {ex.GetType().Name}: {ex.Message}"; }
            finally { try { _lock.Exit(); } catch (Exception ex) { Log($"Fan diagnostic: EC mutex release failed: {ex.Message}"); } }
        }

        if (failure is not null)
        {
            _consecutiveFailures++;
            Log($"Fan diagnostic: sample skipped ({failure}); consecutive failures={_consecutiveFailures}");
            if (_consecutiveFailures >= 2)
            {
                _backoffUntil = now + BackoffTime;
                _consecutiveFailures = 0;
                Log($"Fan diagnostic: backing off EC reads for {BackoffTime.TotalSeconds:0}s");
            }
            return;
        }
        _consecutiveFailures = 0;
        byte b1 = f1!.Value, b2 = f2!.Value;
        _raw1.Add(b1); _raw2.Add(b2);
        if (!_firstSampleLogged)
        {
            _firstSampleLogged = true;
            Log($"Fan diagnostic: first EC sample raw 0x06(FANS)=0x{b1:X2} ({b1}) 0xFE(FA2S)=0x{b2:X2} ({b2}) {FlagText(flags, nums)}");
        }
        if (_stressLogging) Log($"Fan diagnostic (stress): 0x06=0x{b1:X2} 0xFE=0x{b2:X2} {FlagText(flags, nums)}");
        if (_lastSummary is null) _lastSummary = now;
        else if (now - _lastSummary >= SummaryInterval) { _lastSummary = now; Log($"Fan diagnostic summary: {Summary()} {FlagText(flags, nums)}"); }

        var list = new List<SensorReading>(2);
        if (_fan1.Accept(b1) is { } rpm1) { _min1 = Math.Min(_min1 ?? rpm1, rpm1); _max1 = Math.Max(_max1 ?? rpm1, rpm1); list.Add(new(HardwareName, HardwareKind.Controller, CpuFanName, SensorKind.Fan, rpm1, _min1, _max1, "RPM")); }
        if (_fan2.Accept(b2) is { } rpm2) { _min2 = Math.Min(_min2 ?? rpm2, rpm2); _max2 = Math.Max(_max2 ?? rpm2, rpm2); list.Add(new(HardwareName, HardwareKind.Controller, Fan2Name, SensorKind.Fan, rpm2, _min2, _max2, "RPM")); }
        _cached = list;
    }

    private string Summary() => $"0x06 {_raw1} | 0xFE {_raw2} | shown: cpuFan={(_cached.Any(r => r.SensorName == CpuFanName) ? "yes" : "no")} fan2={(_cached.Any(r => r.SensorName == Fan2Name) ? "yes" : "no")}";

    private static string FlagText(byte? flags, byte? nums) =>
        $"0xAB=0x{flags?.ToString("X2") ?? "??"}" + (flags is { } f ? $" (FAN1={(f >> 4) & 1} FAN2={(f >> 5) & 1} FAOK={(f >> 6) & 1})" : "") +
        $" 0xAD=0x{nums?.ToString("X2") ?? "??"}" + (nums is { } n ? $" (SPDN={n & 0xF} FNUM={n >> 4})" : "");

    private void Disable() { lock (_gate) { _enabled = false; _cached = []; CloseIo(); } }

    private void CloseIo()
    {
        try { _io?.Dispose(); } catch (Exception ex) { Log($"Fan diagnostic: closing PawnIO module failed: {ex.Message}"); }
        _io = null;
    }

    private void Log(string m) { try { _log?.Invoke(m); } catch { } }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            if (_enabled) Log($"Fan diagnostic: closing; {Summary()}");
            _enabled = false;
            CloseIo();
        }
    }

    /// <summary>Raw byte statistics for the log: session min/max/number of changes plus the last 15 samples run-length compressed.</summary>
    public sealed class RawStats
    {
        private readonly Queue<byte> _recent = new();
        private byte? _last;
        public int Count { get; private set; }
        public int Changes { get; private set; }
        public byte Min { get; private set; } = byte.MaxValue;
        public byte Max { get; private set; }

        public void Add(byte b)
        {
            Count++;
            if (_last is { } l && l != b) Changes++;
            _last = b;
            if (b < Min) Min = b;
            if (b > Max) Max = b;
            _recent.Enqueue(b);
            while (_recent.Count > HistoryLength) _recent.Dequeue();
        }

        /// <summary>e.g. "1Ex3,1F,20x11".</summary>
        public string Recent()
        {
            var parts = new List<string>();
            byte? cur = null; var n = 0;
            foreach (var b in _recent)
            {
                if (b == cur) { n++; continue; }
                if (cur is { } c) parts.Add(n > 1 ? $"{c:X2}x{n}" : $"{c:X2}");
                cur = b; n = 1;
            }
            if (cur is { } c2) parts.Add(n > 1 ? $"{c2:X2}x{n}" : $"{c2:X2}");
            return string.Join(",", parts);
        }

        public override string ToString() => Count == 0 ? "no samples" : $"samples={Count} min=0x{Min:X2} max=0x{Max:X2} changes={Changes} last{HistoryLength}=[{Recent()}]";
    }
}
