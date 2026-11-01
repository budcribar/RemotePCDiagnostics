namespace RemotePCDiagnostics.Core.Memory;

/// <summary>
/// Hibernation file state, for "Shrink hiberfil.sys" (<c>powercfg /h /type reduced</c>). A full file holds the whole of RAM for
/// Hibernate (about 40% of RAM on disk); Fast Startup only saves the Windows kernel and drivers, so a reduced file (about 20%) is enough.
/// </summary>
/// <param name="Enabled">Hibernation is on (hiberfil.sys exists). False: nothing to shrink.</param>
/// <param name="Reduced">True = already the reduced type; false = full; null = couldn't tell.</param>
/// <param name="CustomSize">A custom size (powercfg /h /size) is set: Windows refuses /type reduced then.</param>
/// <param name="FileBytes">Current size of hiberfil.sys, if readable.</param>
/// <param name="FastStartup">Fast Startup on: the only reason to keep a reduced file instead of turning hibernation off.</param>
/// <param name="HasBattery">A laptop/tablet (has a system battery); null = unknown, treated like a laptop.</param>
public sealed record HibernateInfo(bool Enabled, bool? Reduced, bool CustomSize, long? FileBytes, bool? FastStartup, bool? HasBattery)
{
    public bool OfferReduce => Enabled && Reduced == false && !CustomSize && FastStartup == true && FileBytes is > 0;

    /// <summary>Reduced is about half the full size.</summary>
    public long? EstimatedSavingBytes => FileBytes / 2;

    /// <summary>Desktops: ticked. Laptops (or unknown): opt-in, because at critical battery Windows shuts down instead of hibernating.</summary>
    public bool DefaultOn => HasBattery == false;
}

public static class Hibernation
{
    /// <summary>HKLM\SYSTEM\CurrentControlSet\Control\Power.</summary>
    public const string PowerKey = @"SYSTEM\CurrentControlSet\Control\Power";

    /// <summary>
    /// Reduced or full from the registry (HiberFileType: 1 = reduced, 2 = full) or, when that value is missing,
    /// from the file size: a reduced file is about 20% of RAM, a full one about 40%.
    /// </summary>
    public static bool? IsReduced(int? hiberFileType, long? fileBytes, long totalRamBytes) => hiberFileType switch
    {
        1 => true,
        2 => false,
        _ when fileBytes is > 0 and var b && totalRamBytes > 0 => b < totalRamBytes * 0.3,
        _ => null,
    };

    /// <summary>HiberFileSizePercent other than 0 / the 40% default means someone set a custom size.</summary>
    public static bool IsCustomSize(int? hiberFileSizePercent) => hiberFileSizePercent is > 0 and not 40;
}
