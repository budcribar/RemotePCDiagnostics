using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.GpuMemory;
using RemotePCDiagnostics.Core.Stress;
using SharpGen.Runtime;
using Vortice.D3DCompiler;
using Vortice.Direct3D;
using Vortice.Direct3D11;
using Vortice.DXGI;

namespace RemotePCDiagnostics.Host.Gpu;

/// <summary>
/// The graphics memory test's chips through Direct3D 11 (feature level 11_0+, cs_5_0): hardware DXGI adapters (never WARP), their memory
/// budgets from DXGI 1.4 (<c>QueryVideoMemoryInfo</c>, local segment), and the <see cref="GpuMemoryKernel"/> compute shader. Offscreen
/// only: no swap chain or window, so it works with no one at the screen and in a remote session.
/// </summary>
public sealed class D3D11GpuMemorySource(ILogger? log = null) : IGpuMemorySource
{
    /// <summary>Below this much dedicated memory a GPU is integrated: its video memory is the PC's own (Intel, AMD APU, Qualcomm).</summary>
    public const long IntegratedBelow = 1024L * 1024 * 1024;

    public IReadOnlyList<GpuMemoryAdapter> ListAdapters() => Enumerate().Select(x => x.Info).ToList();

    private List<(GpuMemoryAdapter Info, uint Index)> Enumerate()
    {
        var found = new List<(GpuMemoryAdapter, uint, string)>();
        if (!OperatingSystem.IsWindows()) return [];
        if (DXGI.CreateDXGIFactory1(out IDXGIFactory1? factory).Failure || factory is null) return [];
        using (factory)
        {
            for (uint i = 0; factory.EnumAdapters1(i, out IDXGIAdapter1? adapter).Success && adapter is not null; i++)
            {
                using (adapter)
                {
                    var d = adapter.Description1;
                    if ((d.Flags & AdapterFlags.Software) != 0 || d.VendorId == GpuAdapterInfo.MicrosoftVendorId) continue;
                    long? budget = null, usage = null;
                    try
                    {
                        using var a3 = adapter.QueryInterfaceOrNull<IDXGIAdapter3>();
                        if (a3 is not null)
                        {
                            var info = a3.QueryVideoMemoryInfo(0, MemorySegmentGroup.Local);
                            budget = (long)info.Budget;
                            usage = (long)info.CurrentUsage;
                        }
                    }
                    catch (Exception ex) { log.Warn($"GPU memory: memory budget of '{d.Description}' unreadable: {ex.Message}"); }
                    var dedicated = (long)d.DedicatedVideoMemory;
                    var shared = (long)d.SharedSystemMemory;
                    var integrated = dedicated < IntegratedBelow;
                    var pci = GpuAdapterInfo.PciId((uint)d.VendorId, (uint)d.DeviceId, (uint)d.SubsystemId, (uint)d.Revision);
                    log.Info($"GPU memory: adapter {i} '{d.Description}' {pci} dedicated={dedicated} shared={shared} budget={budget} usage={usage} integrated={integrated}");
                    found.Add((new GpuMemoryAdapter(pci, d.Description, (uint)d.VendorId, dedicated, shared, integrated, budget, usage), i, pci));
                }
            }
        }
        // A second identical card gets "#2", as the GPU stress test names them.
        var seen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        return found.Select(f =>
        {
            var n = seen[f.Item3] = seen.GetValueOrDefault(f.Item3) + 1;
            return (n == 1 ? f.Item1 : f.Item1 with { Id = $"{f.Item3}#{n}" }, f.Item2);
        }).ToList();
    }

    public IGpuMemoryDevice Open(string adapterId)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Direct3D needs Windows.");
        var match = Enumerate().FirstOrDefault(x => string.Equals(x.Info.Id, adapterId, StringComparison.OrdinalIgnoreCase));
        if (match.Info is null) throw new InvalidOperationException($"The graphics adapter {adapterId} is gone.");
        DXGI.CreateDXGIFactory1(out IDXGIFactory1? factory).CheckError();
        using (factory!)
        {
            factory!.EnumAdapters1(match.Index, out IDXGIAdapter1? adapter).CheckError();
            using (adapter!) return new D3D11GpuMemoryDevice(adapter!, match.Info, log);
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct GpuMemoryParams
{
    public uint Pattern, Seed, Flags, Base, Words, Stride, Pad0, Pad1;
}

internal sealed class D3D11GpuMemoryDevice : IGpuMemoryDevice
{
    private static readonly FeatureLevel[] Levels = [FeatureLevel.Level_12_1, FeatureLevel.Level_12_0, FeatureLevel.Level_11_1, FeatureLevel.Level_11_0];
    private readonly ID3D11Device _device;
    private readonly ID3D11DeviceContext _context;
    private readonly ID3D11ComputeShader _shader;
    private readonly ID3D11Buffer _errors, _errorsStaging, _params;
    private readonly ID3D11UnorderedAccessView _errorsUav;
    private readonly List<(ID3D11Buffer Buffer, ID3D11UnorderedAccessView Uav, long Bytes)> _blocks = [];
    private readonly uint[] _zeros = new uint[GpuMemoryKernel.ErrorBufferLength];
    private readonly uint[] _readback = new uint[GpuMemoryKernel.ErrorBufferLength];
    private readonly ILogger? _log;

    public GpuMemoryAdapter Adapter { get; }
    public IReadOnlyList<long> Blocks => _blocks.Select(b => b.Bytes).ToList();

    public D3D11GpuMemoryDevice(IDXGIAdapter1 adapter, GpuMemoryAdapter info, ILogger? log)
    {
        Adapter = info; _log = log;
        D3D11.D3D11CreateDevice(adapter, DriverType.Unknown, DeviceCreationFlags.None, Levels, out _device!, out var level, out _context!).CheckError();
        log.Info($"GPU memory: D3D11 device created on '{info.Name}', feature level {level}");
        try
        {
            var bytecode = Compiler.Compile(GpuMemoryKernel.Hlsl, "main", "GpuMemoryKernel.hlsl", "cs_5_0");
            _shader = _device.CreateComputeShader(bytecode.Span);
            uint errBytes = GpuMemoryKernel.ErrorBufferLength * sizeof(uint);
            _errors = _device.CreateBuffer(new BufferDescription(errBytes, BindFlags.UnorderedAccess, ResourceUsage.Default, CpuAccessFlags.None, ResourceOptionFlags.BufferStructured, sizeof(uint)));
            _errorsStaging = _device.CreateBuffer(new BufferDescription(errBytes, BindFlags.None, ResourceUsage.Staging, CpuAccessFlags.Read, ResourceOptionFlags.None, 0));
            _params = _device.CreateBuffer(new BufferDescription(32, BindFlags.ConstantBuffer, ResourceUsage.Default, CpuAccessFlags.None, ResourceOptionFlags.None, 0));
            _errorsUav = Uav(_errors, GpuMemoryKernel.ErrorBufferLength);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    private ID3D11UnorderedAccessView Uav(ID3D11Buffer buffer, long elements) => _device.CreateUnorderedAccessView(buffer, new UnorderedAccessViewDescription
    {
        Format = Format.Unknown,
        ViewDimension = UnorderedAccessViewDimension.Buffer,
        Buffer = new BufferUnorderedAccessView { FirstElement = 0, NumElements = (uint)elements },
    });

    public bool TryAllocateBlock(long bytes)
    {
        ID3D11Buffer? buffer = null;
        try
        {
            buffer = _device.CreateBuffer(new BufferDescription((uint)bytes, BindFlags.UnorderedAccess, ResourceUsage.Default, CpuAccessFlags.None, ResourceOptionFlags.BufferStructured, sizeof(uint)));
            var uav = Uav(buffer, bytes / sizeof(uint));
            _blocks.Add((buffer, uav, bytes));
            return true;
        }
        catch (SharpGenException ex) when (IsDeviceLost(ex.ResultCode.Code) || _device.DeviceRemovedReason.Failure)
        {
            buffer?.Dispose();
            throw Lost(ex);
        }
        catch (SharpGenException ex)
        {
            // E_OUTOFMEMORY and friends: the chip has nothing more to give; the test uses what it has.
            buffer?.Dispose();
            _log.Info($"GPU memory: no more memory after {_blocks.Count} blocks: HRESULT 0x{ex.ResultCode.Code:X8}");
            return false;
        }
    }

    public GpuBlockResult Run(int block, GpuMemoryOp op, GpuMemoryPattern pattern, uint seed, bool inverted, uint baseWord)
    {
        var (_, uav, bytes) = _blocks[block];
        var words = bytes / sizeof(uint);
        var (groups, stride) = GpuMemoryKernel.Dispatch(words);
        try
        {
            var p = new GpuMemoryParams
            {
                Pattern = (uint)pattern, Seed = seed, Flags = GpuMemoryKernel.Flags(op, inverted), Base = baseWord, Words = (uint)words, Stride = stride,
            };
            _context.UpdateSubresource(in p, _params);
            _context.UpdateSubresource(_zeros, _errors);
            _context.CSSetShader(_shader);
            _context.CSSetConstantBuffer(0, _params);
            _context.CSSetUnorderedAccessViews(0, [uav, _errorsUav]);
            _context.Dispatch(groups, 1, 1);
            _context.CSSetUnorderedAccessViews(0, [null!, null!]);
            _context.CopyResource(_errorsStaging, _errors);
            var map = _context.Map(_errorsStaging, 0, MapMode.Read, Vortice.Direct3D11.MapFlags.None); // waits for the GPU
            try { Marshal.Copy(map.DataPointer, _readbackInts, 0, _readbackInts.Length); }
            finally { _context.Unmap(_errorsStaging, 0); }
            Buffer.BlockCopy(_readbackInts, 0, _readback, 0, _readback.Length * sizeof(uint));
            var removed = _device.DeviceRemovedReason;
            if (removed.Failure) throw new GpuDeviceLostException($"device removed, reason {Reason(removed.Code)}");
            return GpuMemoryKernel.Decode(_readback);
        }
        catch (SharpGenException ex) when (IsDeviceLost(ex.ResultCode.Code) || _device.DeviceRemovedReason.Failure)
        {
            throw Lost(ex);
        }
    }

    private readonly int[] _readbackInts = new int[GpuMemoryKernel.ErrorBufferLength];

    private GpuDeviceLostException Lost(SharpGenException ex) =>
        new($"HRESULT {Reason(ex.ResultCode.Code)}, removed reason {Reason(_device.DeviceRemovedReason.Code)}", ex);

    /// <summary>DXGI_ERROR_DEVICE_REMOVED / HUNG / RESET / DRIVER_INTERNAL_ERROR.</summary>
    private static bool IsDeviceLost(int hr) => unchecked((uint)hr) is 0x887A0005 or 0x887A0006 or 0x887A0007 or 0x887A0020;

    public static string Reason(int hr) => unchecked((uint)hr) switch
    {
        0 => "none",
        0x887A0005 => "DXGI_ERROR_DEVICE_REMOVED (0x887A0005)",
        0x887A0006 => "DXGI_ERROR_DEVICE_HUNG (0x887A0006)",
        0x887A0007 => "DXGI_ERROR_DEVICE_RESET (0x887A0007)",
        0x887A0020 => "DXGI_ERROR_DRIVER_INTERNAL_ERROR (0x887A0020)",
        var u => $"0x{u:X8}",
    };

    public void Dispose()
    {
        _log.Info($"GPU memory: releasing {_blocks.Count} blocks on '{Adapter.Name}'");
        try { _context?.ClearState(); } catch { }
        foreach (var (buffer, uav, _) in _blocks) { uav.Dispose(); buffer.Dispose(); }
        _blocks.Clear();
        _errorsUav?.Dispose(); _params?.Dispose(); _errorsStaging?.Dispose(); _errors?.Dispose(); _shader?.Dispose();
        _context?.Dispose(); _device?.Dispose();
    }
}
