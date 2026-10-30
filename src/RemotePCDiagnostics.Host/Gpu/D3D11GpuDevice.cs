using System.Diagnostics;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Stress;
using SharpGen.Runtime;
using Vortice.D3DCompiler;
using Vortice.Direct3D;
using Vortice.Direct3D11;
using Vortice.DXGI;

namespace RemotePCDiagnostics.Host.Gpu;

/// <summary>
/// Opens the first hardware DXGI adapter (integrated or discrete) as a Direct3D 11 device (feature level 11_0+, cs_5_0)
/// and runs <see cref="GpuStressKernel"/>. Software adapters (WARP / Microsoft Basic Render Driver) are skipped and
/// reported as <see cref="GpuOpenStatus.SoftwareOnly"/>, never opened.
/// </summary>
public sealed class D3D11GpuDeviceFactory(Action<string>? log = null, int threadCount = 1 << 18) : IGpuDeviceFactory
{
    public GpuOpenResult Open()
    {
        if (!OperatingSystem.IsWindows()) return new GpuOpenResult(GpuOpenStatus.NoGpu, Detail: "not Windows");
        if (DXGI.CreateDXGIFactory1(out IDXGIFactory1? factory).Failure || factory is null)
            return new GpuOpenResult(GpuOpenStatus.NoGpu, Detail: "CreateDXGIFactory1 failed");
        using (factory)
        {
            bool sawSoftware = false;
            var failures = new List<string>();
            for (uint i = 0; factory.EnumAdapters1(i, out IDXGIAdapter1? adapter).Success && adapter is not null; i++)
            {
                using (adapter)
                {
                    var d = adapter.Description1;
                    var soft = (d.Flags & AdapterFlags.Software) != 0 || d.VendorId == GpuAdapterInfo.MicrosoftVendorId;
                    log?.Invoke($"GPU stress: adapter {i} '{d.Description}' vendor=0x{d.VendorId:X4} device=0x{d.DeviceId:X4} vram={d.DedicatedVideoMemory} flags={d.Flags} software={soft}");
                    if (soft) { sawSoftware = true; continue; }
                    try
                    {
                        var info = new GpuAdapterInfo(d.Description, GpuAdapterKind.Hardware, (long)d.DedicatedVideoMemory, d.VendorId);
                        return GpuOpenResult.Ok(new D3D11GpuDevice(adapter, info, threadCount, log));
                    }
                    catch (Exception ex)
                    {
                        failures.Add($"{d.Description}: {ex.Message}");
                        log?.Invoke($"GPU stress: could not open '{d.Description}': {ex}");
                    }
                }
            }
            if (failures.Count > 0) return new GpuOpenResult(GpuOpenStatus.Failed, Detail: string.Join("; ", failures));
            return new GpuOpenResult(sawSoftware ? GpuOpenStatus.SoftwareOnly : GpuOpenStatus.NoGpu);
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct GpuStressParams { public uint Seed; public uint Iterations; public uint Pad0; public uint Pad1; }

internal sealed class D3D11GpuDevice : IGpuComputeDevice
{
    private static readonly FeatureLevel[] Levels = [FeatureLevel.Level_12_1, FeatureLevel.Level_12_0, FeatureLevel.Level_11_1, FeatureLevel.Level_11_0];
    private readonly ID3D11Device _device;
    private readonly ID3D11DeviceContext _context;
    private readonly ID3D11ComputeShader _shader;
    private readonly ID3D11Buffer _output, _staging, _params;
    private readonly ID3D11UnorderedAccessView _uav;
    private readonly Action<string>? _log;

    public GpuAdapterInfo Adapter { get; }
    public int ThreadCount { get; }

    public D3D11GpuDevice(IDXGIAdapter1 adapter, GpuAdapterInfo info, int threadCount, Action<string>? log)
    {
        Adapter = info; _log = log;
        ThreadCount = Math.Max(GpuStressKernel.GroupSize, threadCount / GpuStressKernel.GroupSize * GpuStressKernel.GroupSize);
        // Adapter given => driver type must be Unknown.
        D3D11.D3D11CreateDevice(adapter, DriverType.Unknown, DeviceCreationFlags.None, Levels, out _device!, out var level, out _context!).CheckError();
        log?.Invoke($"GPU stress: D3D11 device created, feature level {level}");

        var bytecode = Compiler.Compile(GpuStressKernel.Hlsl, "main", "GpuStressKernel.hlsl", "cs_5_0");
        _shader = _device.CreateComputeShader(bytecode.Span);

        uint bytes = (uint)(ThreadCount * sizeof(uint));
        _output = _device.CreateBuffer(new BufferDescription(bytes, BindFlags.UnorderedAccess, ResourceUsage.Default, CpuAccessFlags.None, ResourceOptionFlags.BufferStructured, sizeof(uint)));
        _staging = _device.CreateBuffer(new BufferDescription(bytes, BindFlags.None, ResourceUsage.Staging, CpuAccessFlags.Read, ResourceOptionFlags.None, 0));
        _params = _device.CreateBuffer(new BufferDescription(16, BindFlags.ConstantBuffer, ResourceUsage.Default, CpuAccessFlags.None, ResourceOptionFlags.None, 0));
        _uav = _device.CreateUnorderedAccessView(_output, new UnorderedAccessViewDescription
        {
            Format = Format.Unknown,
            ViewDimension = UnorderedAccessViewDimension.Buffer,
            Buffer = new BufferUnorderedAccessView { FirstElement = 0, NumElements = (uint)ThreadCount },
        });
    }

    public GpuBatchResult RunBatch(uint seed, uint iterations)
    {
        try
        {
            var sw = Stopwatch.StartNew();
            var p = new GpuStressParams { Seed = seed, Iterations = iterations };
            _context.UpdateSubresource(in p, _params);
            _context.CSSetShader(_shader);
            _context.CSSetConstantBuffer(0, _params);
            _context.CSSetUnorderedAccessView(0, _uav);
            _context.Dispatch((uint)(ThreadCount / GpuStressKernel.GroupSize), 1, 1);
            _context.CopyResource(_staging, _output);
            var map = _context.Map(_staging, 0, MapMode.Read, Vortice.Direct3D11.MapFlags.None); // waits for the GPU
            var raw = new int[ThreadCount];
            try { Marshal.Copy(map.DataPointer, raw, 0, ThreadCount); }
            finally { _context.Unmap(_staging, 0); }
            sw.Stop();
            var result = new uint[ThreadCount];
            Buffer.BlockCopy(raw, 0, result, 0, ThreadCount * sizeof(uint));
            ThrowIfRemoved();
            return new GpuBatchResult(result, sw.Elapsed);
        }
        catch (SharpGenException ex) when (IsDeviceLost(ex.ResultCode.Code) || _device.DeviceRemovedReason.Failure)
        {
            throw new GpuDeviceLostException($"HRESULT 0x{ex.ResultCode.Code:X8}, removed reason 0x{_device.DeviceRemovedReason.Code:X8}", ex);
        }
    }

    private void ThrowIfRemoved()
    {
        var r = _device.DeviceRemovedReason;
        if (r.Failure) throw new GpuDeviceLostException($"device removed, reason 0x{r.Code:X8}");
    }

    // DXGI_ERROR_DEVICE_REMOVED / HUNG / RESET / DRIVER_INTERNAL_ERROR.
    private static bool IsDeviceLost(int hr) => unchecked((uint)hr) is 0x887A0005 or 0x887A0006 or 0x887A0007 or 0x887A0020;

    public void Dispose()
    {
        _log?.Invoke("GPU stress: releasing D3D11 device");
        _context.ClearState();
        _uav.Dispose(); _params.Dispose(); _staging.Dispose(); _output.Dispose(); _shader.Dispose();
        _context.Dispose(); _device.Dispose();
    }
}
