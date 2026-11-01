using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>
/// #18: Office 16.x privacy policy state for this account, read from the registry by the Host.
/// </summary>
/// <param name="Installed">Office 16.x Word, Excel or PowerPoint is installed (same detection as the start screen fix, #23).</param>
/// <param name="ControllerConnectedServicesEnabled">
/// HKCU\Software\Policies\Microsoft\Office\16.0\Common\Privacy\ControllerConnectedServicesEnabled, the policy
/// "Allow the use of additional optional connected experiences in Office" (1 = enabled, 2 = disabled); null = not configured.
/// </param>
/// <param name="DisconnectedState">
/// Same key, DisconnectedState: the policy "Allow the use of connected experiences in Office" (2 = all connected experiences off,
/// which already includes the optional ones). Only read, never written.
/// </param>
public sealed record OfficePrivacyInfo(bool Installed, int? ControllerConnectedServicesEnabled, int? DisconnectedState);

/// <summary>When to offer turning off Office's optional connected experiences (#18), and the one value that writes.</summary>
public static class OfficePrivacy
{
    /// <summary>Policy value: disabled.</summary>
    public const int Disabled = 2;

    /// <summary>The policy key (HKCU); <see cref="RegistryAllowlist.OfficeOptionalConnectedExperiences"/> is the only value written under it.</summary>
    public const string PolicyKey = @"Software\Policies\Microsoft\Office\16.0\Common\Privacy";

    /// <summary>The value read (not written) to tell that all connected experiences are already off.</summary>
    public const string DisconnectedStateName = "DisconnectedState";

    public static RegistrySetting Setting => RegistryAllowlist.OfficeOptionalConnectedExperiences;

    /// <summary>
    /// Offered when Office 16 is installed and the optional-experiences policy isn't configured yet. Not offered when it's
    /// already 2, when it's set to anything else (someone, usually the organization, chose it: we don't override that),
    /// or when all connected experiences are already off (DisconnectedState = 2). Unknown (null) state: not offered.
    /// </summary>
    public static bool Offer(MemorySnapshot s) =>
        s.OfficePrivacy is { Installed: true, ControllerConnectedServicesEnabled: null } p && p.DisconnectedState != Disabled;
}
