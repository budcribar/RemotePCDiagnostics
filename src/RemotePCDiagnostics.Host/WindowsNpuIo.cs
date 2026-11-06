using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Npu;
using Vortice.Direct3D;
using Vortice.Direct3D12;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// NPU access on Windows: PnP devices from WMI (Win32_PnPEntity / Win32_PnPSignedDriver), NPU adapters from DXCore (dxcore.dll, Windows 10 2004+),
/// and a short Direct3D 12 workload on the DXCore adapter (matrix multiply compute shader on "core compute" NPUs, a copy round-trip on ML-only NPUs).
/// No network, no files written, no dialogs. All failures are thrown as <see cref="NpuDeviceException"/> or logged and skipped.
/// </summary>
public sealed class WindowsNpuIo(ILogger? log = null) : INpuIo
{
    private void Log(string m) => log.Info(m);
    private void LogWarn(string m) => log.Warn(m);

    public IReadOnlyList<NpuDevice> ListDevices()
    {
        List<PnpRow> pnp = [];
        List<DxCoreAdapterRow> dx = [];
        try { pnp = QueryPnp(); } catch (Exception ex) { LogWarn($"NpuTest: WMI query failed: {ex.Message}"); }
        try { dx = DxCore.ListAdapters(); } catch (Exception ex) { LogWarn($"NpuTest: DXCore enumeration failed: {ex.Message}"); }
        Log($"NpuTest: PnP candidates={pnp.Count(NpuDetection.IsNpuCandidate)} DXCore adapters={dx.Count} ({string.Join(", ", dx.Select(a => $"{a.Description} npu={a.IsNpuHardwareType} gfx={a.SupportsGraphics} core={a.SupportsCoreCompute} ml={a.SupportsGenericMl}"))})");
        return NpuDetection.Merge(pnp, dx);
    }

    private static List<PnpRow> QueryPnp()
    {
        var opts = new EnumerationOptions { Timeout = TimeSpan.FromSeconds(10), ReturnImmediately = false };
        var rows = new List<PnpRow>();
        using (var q = new ManagementObjectSearcher(new ManagementScope(@"root\cimv2"),
            new ObjectQuery("SELECT DeviceID, Name, PNPClass, ClassGuid, Manufacturer, Status, ConfigManagerErrorCode, HardwareID FROM Win32_PnPEntity"), opts))
        {
            foreach (ManagementObject o in q.Get())
                using (o)
                {
                    var r = new PnpRow(o["DeviceID"] as string, o["Name"] as string, o["PNPClass"] as string, o["ClassGuid"] as string, o["Manufacturer"] as string,
                        o["Status"] as string, o["ConfigManagerErrorCode"] is { } c ? Convert.ToInt32(c) : null, null, o["HardwareID"] as string[]);
                    if (NpuDetection.IsNpuCandidate(r)) rows.Add(r);
                }
        }
        for (var i = 0; i < rows.Count; i++)
        {
            if (rows[i].DeviceId is not { } id) continue;
            using var d = new ManagementObjectSearcher(new ManagementScope(@"root\cimv2"),
                new ObjectQuery($"SELECT DriverVersion FROM Win32_PnPSignedDriver WHERE DeviceID = '{id.Replace("\\", "\\\\").Replace("'", "\\'")}'"), opts);
            foreach (ManagementObject o in d.Get()) using (o) { if (o["DriverVersion"] is string v) rows[i] = rows[i] with { DriverVersion = v }; }
        }
        return rows;
    }

    public Task<NpuWorkloadResult> RunWorkloadAsync(NpuDevice device, NpuWorkloadRequest request, CancellationToken ct)
    {
        if (device.AdapterLuid is not { } luid) throw new NpuDeviceException("No DirectX adapter for this NPU.");
        // Dedicated thread: a hung driver call can't block the thread pool, and the Core watchdog can abandon it.
        var tcs = new TaskCompletionSource<NpuWorkloadResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var t = new Thread(() =>
        {
            try { tcs.TrySetResult(Run(luid, device, request, ct)); }
            catch (OperationCanceledException oce) { tcs.TrySetCanceled(oce.CancellationToken); }
            catch (NpuDeviceException ex) { tcs.TrySetException(ex); }
            catch (Exception ex) { tcs.TrySetException(new NpuDeviceException(ex.Message, ex)); }
        }) { IsBackground = true, Name = "NpuTest" };
        t.Start();
        return tcs.Task;
    }

    private NpuWorkloadResult Run(long luid, NpuDevice device, NpuWorkloadRequest req, CancellationToken ct)
    {
        var n = Math.Clamp(req.MatrixSize, 16, NpuTestLimits.MaxMatrixSize) / 16 * 16;
        using var adapter = DxCore.OpenAdapter(luid) ?? throw new NpuDeviceException("The NPU adapter disappeared.");
        var core = device.Compute == NpuComputeLevel.CoreCompute;
        var level = core ? FeatureLevel.Level_1_0_CORE : FeatureLevel.Level_1_0_GENERIC;
        var hr = D3D12.D3D12CreateDevice(adapter.Pointer, level, out ID3D12Device? d3d);
        if (hr.Failure && core)
        {
            LogWarn($"NpuTest: core device failed (0x{hr.Code:X8}), retrying generic");
            core = false; level = FeatureLevel.Level_1_0_GENERIC;
            hr = D3D12.D3D12CreateDevice(adapter.Pointer, level, out d3d);
        }
        if (hr.Failure) throw new NpuDeviceException($"Couldn't open the NPU with Direct3D 12 (0x{hr.Code:X8}).");
        using var dev = d3d!;
        Log($"NpuTest: D3D12 device on '{adapter.Description}' level={level}");
        return core ? MatMul(dev, adapter.Description, n, req, ct) : CopyRoundTrip(dev, adapter.Description, req, ct);
    }

    private const string Shader = """
        StructuredBuffer<float> A : register(t0);
        StructuredBuffer<float> B : register(t1);
        RWStructuredBuffer<float> C : register(u0);
        cbuffer P : register(b0) { uint N; };
        [numthreads(16, 16, 1)]
        void main(uint3 id : SV_DispatchThreadID)
        {
            if (id.x >= N || id.y >= N) return;
            float s = 0;
            for (uint k = 0; k < N; k++) s += A[id.y * N + k] * B[k * N + id.x];
            C[id.y * N + id.x] = s;
        }
        """;

    private NpuWorkloadResult MatMul(ID3D12Device dev, string adapterName, int n, NpuWorkloadRequest req, CancellationToken ct)
    {
        var bytes = (ulong)n * (ulong)n * sizeof(float);
        var blob = Vortice.D3DCompiler.Compiler.Compile(Shader, "main", "npu_matmul.hlsl", "cs_5_1", Vortice.D3DCompiler.ShaderFlags.OptimizationLevel3);
        var cs = blob.ToArray();
        var rootDesc = new RootSignatureDescription1(RootSignatureFlags.None,
        [
            new RootParameter1(RootParameterType.ShaderResourceView, new RootDescriptor1(0, 0), ShaderVisibility.All),
            new RootParameter1(RootParameterType.ShaderResourceView, new RootDescriptor1(1, 0), ShaderVisibility.All),
            new RootParameter1(RootParameterType.UnorderedAccessView, new RootDescriptor1(0, 0), ShaderVisibility.All),
            new RootParameter1(new RootConstants(0, 0, 1), ShaderVisibility.All),
        ]);
        using var root = dev.CreateRootSignature(rootDesc);
        using var pso = dev.CreateComputePipelineState(new ComputePipelineStateDescription { RootSignature = root, ComputeShader = cs });
        using var a = Buffer(dev, HeapType.Upload, bytes, ResourceStates.GenericRead);
        using var b = Buffer(dev, HeapType.Upload, bytes, ResourceStates.GenericRead);
        using var c = Buffer(dev, HeapType.Default, bytes, ResourceStates.UnorderedAccess, ResourceFlags.AllowUnorderedAccess);
        using var rb = Buffer(dev, HeapType.Readback, bytes, ResourceStates.CopyDest);
        Upload(a, req.A, n * n); Upload(b, req.B, n * n);
        using var queue = dev.CreateCommandQueue(new CommandQueueDescription(CommandListType.Compute));
        using var alloc = dev.CreateCommandAllocator(CommandListType.Compute);
        using var fence = dev.CreateFence(0);
        using var ev = new AutoResetEvent(false);

        ID3D12GraphicsCommandList Record(bool readback)
        {
            var list = dev.CreateCommandList<ID3D12GraphicsCommandList>(0, CommandListType.Compute, alloc, pso);
            list.SetComputeRootSignature(root);
            list.SetComputeRootShaderResourceView(0, a.GPUVirtualAddress);
            list.SetComputeRootShaderResourceView(1, b.GPUVirtualAddress);
            list.SetComputeRootUnorderedAccessView(2, c.GPUVirtualAddress);
            list.SetComputeRoot32BitConstant(3, (uint)n, 0);
            list.Dispatch((uint)(n / 16), (uint)(n / 16), 1);
            if (readback)
            {
                list.ResourceBarrierTransition(c, ResourceStates.UnorderedAccess, ResourceStates.CopySource);
                list.CopyResource(rb, c);
                list.ResourceBarrierTransition(c, ResourceStates.CopySource, ResourceStates.UnorderedAccess);
            }
            else list.ResourceBarrierUnorderedAccessView(c);
            list.Close();
            return list;
        }

        ulong value = 0;
        var deadline = Stopwatch.StartNew();
        var limit = req.Budget + NpuTestLimits.WatchdogGrace;
        using var first = Record(true);
        var sw = Stopwatch.StartNew();
        queue.ExecuteCommandList(first);
        Wait(dev, queue, fence, ++value, ev, deadline, limit, ct);
        var firstMs = sw.Elapsed.TotalMilliseconds;
        var output = new float[n * n];
        Download(rb, output);

        // Repeats: one command list with a batch of dispatches, executed until the budget is used up.
        using var repeat = Record(false);
        var iters = 0;
        sw.Restart();
        while (sw.Elapsed < req.Budget && iters < req.MaxIterations)
        {
            ct.ThrowIfCancellationRequested();
            queue.ExecuteCommandList(repeat);
            Wait(dev, queue, fence, ++value, ev, deadline, limit, ct);
            iters++;
        }
        var avg = iters == 0 ? firstMs : sw.Elapsed.TotalMilliseconds / iters;
        return new NpuWorkloadResult(NpuWorkloadKind.MatMulComputeShader, output, firstMs, avg, Math.Max(iters, 1), adapterName, "Direct3D 12 compute shader (feature level 1_0_CORE)");
    }

    /// <summary>ML-only NPUs (feature level 1_0_GENERIC) run no shaders; a buffer copy on their compute queue proves the driver accepts and completes work.</summary>
    private NpuWorkloadResult CopyRoundTrip(ID3D12Device dev, string adapterName, NpuWorkloadRequest req, CancellationToken ct)
    {
        var count = req.A.Length;
        var bytes = (ulong)count * sizeof(float);
        using var src = Buffer(dev, HeapType.Upload, bytes, ResourceStates.GenericRead);
        using var dst = Buffer(dev, HeapType.Readback, bytes, ResourceStates.CopyDest);
        Upload(src, req.A, count);
        using var queue = dev.CreateCommandQueue(new CommandQueueDescription(CommandListType.Compute));
        using var alloc = dev.CreateCommandAllocator(CommandListType.Compute);
        using var fence = dev.CreateFence(0);
        using var ev = new AutoResetEvent(false);
        using var list = dev.CreateCommandList<ID3D12GraphicsCommandList>(0, CommandListType.Compute, alloc, null);
        list.CopyBufferRegion(dst, 0, src, 0, bytes);
        list.Close();
        ulong value = 0;
        var deadline = Stopwatch.StartNew();
        var limit = req.Budget + NpuTestLimits.WatchdogGrace;
        var sw = Stopwatch.StartNew();
        queue.ExecuteCommandList(list);
        Wait(dev, queue, fence, ++value, ev, deadline, limit, ct);
        var firstMs = sw.Elapsed.TotalMilliseconds;
        var back = new float[count];
        Download(dst, back);
        if (!back.AsSpan().SequenceEqual(req.A)) throw new NpuDeviceException("A buffer copy on the NPU returned different data.");
        var iters = 0;
        sw.Restart();
        while (sw.Elapsed < req.Budget && iters < req.MaxIterations)
        {
            ct.ThrowIfCancellationRequested();
            queue.ExecuteCommandList(list);
            Wait(dev, queue, fence, ++value, ev, deadline, limit, ct);
            iters++;
        }
        var avg = iters == 0 ? firstMs : sw.Elapsed.TotalMilliseconds / iters;
        return new NpuWorkloadResult(NpuWorkloadKind.QueueRoundTrip, null, firstMs, avg, Math.Max(iters, 1), adapterName,
            "Direct3D 12 feature level 1_0_GENERIC: buffer copy verified, no compute shaders");
    }

    private static ID3D12Resource Buffer(ID3D12Device dev, HeapType heap, ulong bytes, ResourceStates state, ResourceFlags flags = ResourceFlags.None) =>
        dev.CreateCommittedResource(new HeapProperties(heap), HeapFlags.None, ResourceDescription.Buffer(bytes, flags), state);

    // ID3D12Resource::Map (vtable slot 8) without unsafe code: IUnknown(3) + ID3D12Object(4) + ID3D12DeviceChild(1).
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int MapFn(IntPtr self, uint subresource, IntPtr readRange, out IntPtr data);

    private static IntPtr Map(ID3D12Resource r)
    {
        var fn = Marshal.GetDelegateForFunctionPointer<MapFn>(Marshal.ReadIntPtr(Marshal.ReadIntPtr(r.NativePointer), 8 * IntPtr.Size));
        var hr = fn(r.NativePointer, 0, IntPtr.Zero, out var p);
        if (hr < 0 || p == IntPtr.Zero) throw new NpuDeviceException($"Couldn't map an NPU buffer (0x{hr:X8}).");
        return p;
    }

    private static void Upload(ID3D12Resource r, float[] data, int count)
    {
        var p = Map(r);
        try { Marshal.Copy(data, 0, p, count); } finally { r.Unmap(0); }
    }

    private static void Download(ID3D12Resource r, float[] into)
    {
        var p = Map(r);
        try { Marshal.Copy(p, into, 0, into.Length); } finally { r.Unmap(0, new Vortice.Direct3D12.Range(0, 0)); }
    }

    private static void Wait(ID3D12Device dev, ID3D12CommandQueue q, ID3D12Fence f, ulong value, AutoResetEvent ev, Stopwatch since, TimeSpan limit, CancellationToken ct)
    {
        q.Signal(f, value).CheckError();
        if (f.CompletedValue >= value) return;
        f.SetEventOnCompletion(value, ev.SafeWaitHandle.DangerousGetHandle()).CheckError();
        while (!ev.WaitOne(100))
        {
            if (f.CompletedValue >= value) return;
            ct.ThrowIfCancellationRequested();
            if (dev.DeviceRemovedReason is { Failure: true } why) throw new NpuDeviceException($"The NPU device was removed or reset (0x{why.Code:X8}).");
            if (since.Elapsed > limit) throw new TimeoutException("The NPU didn't complete the work in time.");
        }
    }
}

/// <summary>Minimal DXCore COM interop (no package): IDXCoreAdapterFactory → IDXCoreAdapterList → IDXCoreAdapter.</summary>
internal static class DxCore
{
    private static readonly Guid IID_Factory = new("78ee5945-c36e-4b13-a669-005dd11c0f06");
    private static readonly Guid IID_List = new("526c7776-40e9-459b-b711-f32ad76dfc28");
    private static readonly Guid IID_Adapter = new("f0db4c7f-fe5a-42a2-bd62-f2a6cf6fc83e");
    // Adapter attributes (dxcore_interface.h).
    private static readonly Guid D3D12_GENERIC_ML = new("b71b0d41-1088-422f-a27c-0250b7d3a988");
    private static readonly Guid D3D12_CORE_COMPUTE = new("248e2800-a793-4724-abaa-23a6de1be090");
    private static readonly Guid D3D12_GRAPHICS = new("0c9ece4d-2f6e-4f01-8c96-e89e331b47b1");
    private static readonly Guid HARDWARE_TYPE_NPU = new("d46140c4-add7-451b-9e56-06fe8c3b58ed");
    // DXCoreAdapterProperty
    private const uint InstanceLuid = 0, DriverVersion = 1, DriverDescription = 2, HardwareID = 3, IsHardware = 11;

    [DllImport("dxcore.dll", ExactSpelling = true)]
    private static extern int DXCoreCreateAdapterFactory(in Guid riid, out IntPtr factory);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int CreateAdapterListFn(IntPtr self, uint n, [In] Guid[] attrs, in Guid riid, out IntPtr list);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int GetAdapterFn(IntPtr self, uint index, in Guid riid, out IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate uint GetCountFn(IntPtr self);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] [return: MarshalAs(UnmanagedType.U1)] private delegate bool IsAttributeFn(IntPtr self, in Guid attr);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int GetPropertyFn(IntPtr self, uint prop, nuint size, IntPtr buffer);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] private delegate int GetPropertySizeFn(IntPtr self, uint prop, out nuint size);

    private static T Slot<T>(IntPtr com, int index) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(Marshal.ReadIntPtr(Marshal.ReadIntPtr(com), index * IntPtr.Size));

    internal sealed class Adapter(IntPtr p, string description) : IDisposable
    {
        public IntPtr Pointer { get; private set; } = p;
        public string Description { get; } = description;
        public void Dispose() { if (Pointer != IntPtr.Zero) { Marshal.Release(Pointer); Pointer = IntPtr.Zero; } }
    }

    /// <summary>All ML-capable adapters (NPUs and GPUs); <see cref="NpuDetection.IsNpuAdapter"/> picks the NPUs.</summary>
    public static List<DxCoreAdapterRow> ListAdapters()
    {
        var rows = new List<DxCoreAdapterRow>();
        foreach (var (p, row) in Enumerate()) { Marshal.Release(p); rows.Add(row); }
        return rows;
    }

    public static Adapter? OpenAdapter(long luid)
    {
        Adapter? found = null;
        foreach (var (p, row) in Enumerate())
        {
            if (found is null && row.Luid == luid) found = new Adapter(p, row.Description);
            else Marshal.Release(p);
        }
        return found;
    }

    private static List<(IntPtr, DxCoreAdapterRow)> Enumerate()
    {
        var result = new List<(IntPtr, DxCoreAdapterRow)>();
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) return result;
        if (DXCoreCreateAdapterFactory(IID_Factory, out var factory) < 0 || factory == IntPtr.Zero) return result;
        try
        {
            if (Slot<CreateAdapterListFn>(factory, 3)(factory, 1, [D3D12_GENERIC_ML], IID_List, out var list) < 0 || list == IntPtr.Zero) return result;
            try
            {
                var count = Slot<GetCountFn>(list, 4)(list);
                for (uint i = 0; i < count; i++)
                {
                    if (Slot<GetAdapterFn>(list, 3)(list, i, IID_Adapter, out var a) < 0 || a == IntPtr.Zero) continue;
                    try { result.Add((a, Read(a))); }
                    catch { Marshal.Release(a); }
                }
            }
            finally { Marshal.Release(list); }
        }
        finally { Marshal.Release(factory); }
        return result;
    }

    private static DxCoreAdapterRow Read(IntPtr a)
    {
        var isAttr = Slot<IsAttributeFn>(a, 4);
        var get = Slot<GetPropertyFn>(a, 6);
        var size = Slot<GetPropertySizeFn>(a, 7);
        long luid = Prop<long>(get, a, InstanceLuid);
        ulong ver = Prop<ulong>(get, a, DriverVersion);
        var hw = new uint[4];
        var h = GCHandle.Alloc(hw, GCHandleType.Pinned);
        try { _ = get(a, HardwareID, 16, h.AddrOfPinnedObject()); } finally { h.Free(); }
        var desc = "";
        if (size(a, DriverDescription, out var n) >= 0 && n > 0 && n < 4096)
        {
            var buf = Marshal.AllocHGlobal((int)n);
            try { if (get(a, DriverDescription, n, buf) >= 0) desc = Marshal.PtrToStringAnsi(buf) ?? ""; } finally { Marshal.FreeHGlobal(buf); }
        }
        var isHw = Prop<byte>(get, a, IsHardware) != 0;
        return new DxCoreAdapterRow(luid, desc, hw[0], hw[1], ver, isAttr(a, HARDWARE_TYPE_NPU), isAttr(a, D3D12_GRAPHICS), isAttr(a, D3D12_CORE_COMPUTE),
            isAttr(a, D3D12_GENERIC_ML), isHw);
    }

    private static T Prop<T>(GetPropertyFn get, IntPtr a, uint prop) where T : unmanaged
    {
        var size = Marshal.SizeOf<T>();
        var buf = Marshal.AllocHGlobal(size);
        try { return get(a, prop, (nuint)size, buf) >= 0 ? Marshal.PtrToStructure<T>(buf) : default; }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
