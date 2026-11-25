using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Reads third-party and Windows Defender antivirus states from the documented Windows Security Center COM API
/// (<c>WSCProductList</c> / <c>IWscProduct</c>). Desktop Windows only; gracefully returns <see cref="AntivirusInventoryStatus.Unavailable"/>
/// when COM activation fails (e.g. Windows Server or non-Windows), and preserves partial results on enumeration errors.
/// </summary>
public sealed class WindowsAntivirusProductSource(ILogger? log = null) : IAntivirusProductSource
{
    private const uint WscSecurityProviderAntivirus = 0x4;

    public Task<AntivirusInventoryResult> ReadAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(AntivirusInventoryResult.Unavailable("Not Windows"));

        return Task.Run(() => ReadCom(ct), ct);
    }

    private AntivirusInventoryResult ReadCom(CancellationToken ct)
    {
        object? comObj = null;
        try
        {
            var clsid = new Guid("17072F7B-9ABE-4A74-A261-1EB76B55107A"); // CLSID_WSCProductList
            var type = Type.GetTypeFromCLSID(clsid, throwOnError: false);
            if (type is null)
                return AntivirusInventoryResult.Unavailable("WSCProductList CLSID unavailable");

            comObj = Activator.CreateInstance(type);
            if (comObj is not IWscProductList list)
                return AntivirusInventoryResult.Unavailable("IWSCProductList interface unavailable");

            var initHr = list.Initialize(WscSecurityProviderAntivirus);
            if (initHr != 0)
            {
                log.Info($"[wsc] IWSCProductList.Initialize failed: 0x{unchecked((uint)initHr):X8}");
                return AntivirusInventoryResult.Unavailable($"WSC Initialize failed (0x{unchecked((uint)initHr):X8})");
            }

            var countHr = list.get_Count(out var count);
            if (countHr != 0 || count < 0)
            {
                log.Info($"[wsc] IWSCProductList.get_Count failed: 0x{unchecked((uint)countHr):X8}");
                return AntivirusInventoryResult.Unavailable($"WSC get_Count failed (0x{unchecked((uint)countHr):X8})");
            }

            var products = new List<AntivirusProductInfo>(count);
            var incomplete = false;
            for (uint i = 0; i < (uint)count; i++)
            {
                ct.ThrowIfCancellationRequested();
                IWscProduct? item = null;
                try
                {
                    var itemHr = list.get_Item(i, out item);
                    if (itemHr != 0 || item is null)
                    {
                        incomplete = true;
                        continue;
                    }

                    var nameHr = item.get_ProductName(out var name);
                    if (nameHr != 0 || string.IsNullOrWhiteSpace(name))
                    {
                        incomplete = true;
                        continue;
                    }

                    var state = item.get_ProductState(out var rawState) == 0
                        ? MapState(rawState)
                        : AntivirusProductState.Unknown;

                    var sig = item.get_SignatureStatus(out var rawSig) == 0
                        ? MapSignatureStatus(rawSig)
                        : AntivirusSignatureStatus.Unknown;

                    products.Add(new AntivirusProductInfo(name.Trim(), state, sig, "wsc"));
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    log.Info($"[wsc] item {i} read failed: {ex.Message}");
                    incomplete = true;
                }
                finally
                {
                    if (item is not null && Marshal.IsComObject(item))
                        Marshal.ReleaseComObject(item);
                }
            }

            return new AntivirusInventoryResult(
                incomplete ? AntivirusInventoryStatus.Incomplete : AntivirusInventoryStatus.Ok,
                products);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Info("[wsc] WSCProductList failed: " + ex.Message);
            return AntivirusInventoryResult.Unavailable(ex.Message);
        }
        finally
        {
            if (comObj is not null && Marshal.IsComObject(comObj))
                Marshal.ReleaseComObject(comObj);
        }
    }

    internal static AntivirusProductState MapState(int raw) => raw switch
    {
        0 => AntivirusProductState.On,      // WSC_SECURITY_PRODUCT_STATE_ON
        1 => AntivirusProductState.Off,     // WSC_SECURITY_PRODUCT_STATE_OFF
        2 => AntivirusProductState.Snoozed, // WSC_SECURITY_PRODUCT_STATE_SNOOZED
        3 => AntivirusProductState.Expired, // WSC_SECURITY_PRODUCT_STATE_EXPIRED
        _ => AntivirusProductState.Unknown,
    };

    internal static AntivirusSignatureStatus MapSignatureStatus(int raw) => raw switch
    {
        0 => AntivirusSignatureStatus.UpToDate,  // WSC_SECURITY_PRODUCT_UP_TO_DATE
        1 => AntivirusSignatureStatus.OutOfDate, // WSC_SECURITY_PRODUCT_OUT_OF_DATE
        _ => AntivirusSignatureStatus.Unknown,
    };

    [ComImport]
    [Guid("722A338C-6E8E-4E72-AC27-1417FB0C81C2")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IWscProductList
    {
        [PreserveSig] int Initialize(uint provider);
        [PreserveSig] int get_Count(out int pVal);
        [PreserveSig] int get_Item(uint index, out IWscProduct pVal);
    }

    [ComImport]
    [Guid("8C38232E-3A45-4A27-92B0-1A16A975F669")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface IWscProduct
    {
        [PreserveSig] int get_ProductName([MarshalAs(UnmanagedType.BStr)] out string pVal);
        [PreserveSig] int get_ProductState(out int pVal);
        [PreserveSig] int get_SignatureStatus(out int pVal);
        [PreserveSig] int get_RemediationPath([MarshalAs(UnmanagedType.BStr)] out string pVal);
        [PreserveSig] int get_ProductStateTimestamp([MarshalAs(UnmanagedType.BStr)] out string pVal);
        [PreserveSig] int get_ProductGuid([MarshalAs(UnmanagedType.BStr)] out string pVal);
        [PreserveSig] int get_ProductIsDefault([MarshalAs(UnmanagedType.VariantBool)] out bool pVal);
    }
}
