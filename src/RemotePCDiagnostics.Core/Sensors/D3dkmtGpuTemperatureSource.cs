using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>
/// GPU temperature from the WDDM kernel thunk, the same data Task Manager shows:
/// D3DKMTQueryAdapterInfo(KMTQAITYPE_ADAPTERPERFDATA) → D3DKMT_ADAPTER_PERFDATA.Temperature (deci-°C).
/// Needs Windows 10 2004+/11 and a WDDM 2.7+ driver that fills in the value (the AMD/Intel/NVIDIA drivers do
/// when Task Manager shows a GPU temperature). Every native call is guarded; adapters are always closed.
/// </summary>
public sealed class D3dkmtGpuTemperatureSource : IGpuTemperatureSource
{
    public string Name => "D3DKMT adapter perf data (Task Manager)";

    private const int KMTQAITYPE_ADAPTERREGISTRYINFO = 8;
    private const int KMTQAITYPE_ADAPTERPERFDATA = 62;

    [StructLayout(LayoutKind.Sequential)]
    private struct AdapterInfo { public uint hAdapter; public uint LuidLow; public int LuidHigh; public uint NumOfSources; public int bPrecisePresentRegionsPreferred; }

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumAdapters2 { public uint NumAdapters; public IntPtr pAdapters; }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryAdapterInfo { public uint hAdapter; public int Type; public IntPtr pPrivateDriverData; public uint PrivateDriverDataSize; }

    [StructLayout(LayoutKind.Sequential)]
    private struct AdapterPerfData
    {
        public uint PhysicalAdapterIndex;
        public ulong MemoryFrequency, MaxMemoryFrequency, MaxMemoryFrequencyOC, MemoryBandwidth, PCIEBandwidth;
        public uint FanRPM, Power, Temperature;
        public byte PowerStateOverride;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CloseAdapter { public uint hAdapter; }

    [DllImport("gdi32.dll")] private static extern int D3DKMTEnumAdapters2(ref EnumAdapters2 p);
    [DllImport("gdi32.dll")] private static extern int D3DKMTQueryAdapterInfo(ref QueryAdapterInfo p);
    [DllImport("gdi32.dll")] private static extern int D3DKMTCloseAdapter(ref CloseAdapter p);

    public IReadOnlyList<GpuTemperatureSample> Read()
    {
        var result = new List<GpuTemperatureSample>();
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) return result;
        var e = new EnumAdapters2();
        if (D3DKMTEnumAdapters2(ref e) != 0 || e.NumAdapters == 0) return result;
        var size = Marshal.SizeOf<AdapterInfo>();
        var buf = Marshal.AllocHGlobal(size * (int)e.NumAdapters);
        try
        {
            e.pAdapters = buf;
            if (D3DKMTEnumAdapters2(ref e) != 0) return result;
            for (var i = 0; i < e.NumAdapters; i++)
            {
                var a = Marshal.PtrToStructure<AdapterInfo>(buf + i * size);
                try
                {
                    var name = TryName(a.hAdapter) ?? $"Adapter {i}";
                    if (name.Contains("Basic Render", StringComparison.OrdinalIgnoreCase)) continue; // software adapter
                    result.Add(new GpuTemperatureSample(name, TryTemperature(a.hAdapter)));
                }
                catch { /* one adapter failing should not hide the rest */ }
                finally { var c = new CloseAdapter { hAdapter = a.hAdapter }; try { D3DKMTCloseAdapter(ref c); } catch { } }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return result;
    }

    private static double? TryTemperature(uint h)
    {
        var size = Marshal.SizeOf<AdapterPerfData>();
        var p = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(new AdapterPerfData { PhysicalAdapterIndex = 0 }, p, false);
            var q = new QueryAdapterInfo { hAdapter = h, Type = KMTQAITYPE_ADAPTERPERFDATA, pPrivateDriverData = p, PrivateDriverDataSize = (uint)size };
            if (D3DKMTQueryAdapterInfo(ref q) != 0) return null;
            var t = Marshal.PtrToStructure<AdapterPerfData>(p).Temperature;
            return t == 0 ? null : t / 10.0;
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    private static string? TryName(uint h)
    {
        const int size = 4 * 260 * 2; // D3DKMT_ADAPTERREGISTRYINFO: 4 × WCHAR[MAX_PATH]
        var p = Marshal.AllocHGlobal(size);
        try
        {
            var q = new QueryAdapterInfo { hAdapter = h, Type = KMTQAITYPE_ADAPTERREGISTRYINFO, pPrivateDriverData = p, PrivateDriverDataSize = size };
            if (D3DKMTQueryAdapterInfo(ref q) != 0) return null;
            var s = Marshal.PtrToStringUni(p, 260).Split('\0')[0].Trim();
            return s.Length == 0 ? null : s;
        }
        finally { Marshal.FreeHGlobal(p); }
    }
}
