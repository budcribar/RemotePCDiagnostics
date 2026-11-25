using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Parsed <see cref="Changes.ChangeKind.PowerSetting"/> journal target: <c>schemeGuid|subgroupGuid|settingGuid|AC</c>.</summary>
public sealed record PowerSettingTarget(Guid SchemeGuid, Guid SubgroupGuid, Guid SettingGuid, string PowerSource)
{
    public string Encode() => $"{SchemeGuid:D}|{SubgroupGuid:D}|{SettingGuid:D}|{PowerSource}";

    public bool IsAllowedProcessorAcMax =>
        SubgroupGuid == WindowsPowerPolicyReader.SubProcessorGuid
        && SettingGuid == WindowsPowerPolicyReader.ProcThrottleMaxGuid
        && string.Equals(PowerSource, "AC", StringComparison.OrdinalIgnoreCase);

    public static PowerSettingTarget ForProcessorAcMax(Guid schemeGuid) =>
        new(schemeGuid, WindowsPowerPolicyReader.SubProcessorGuid, WindowsPowerPolicyReader.ProcThrottleMaxGuid, "AC");

    public static bool TryParse(string? text, out PowerSettingTarget target)
    {
        target = null!;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var parts = text.Split('|');
        if (parts.Length != 4) return false;
        if (!Guid.TryParse(parts[0], out var scheme)) return false;
        if (!Guid.TryParse(parts[1], out var subgroup)) return false;
        if (!Guid.TryParse(parts[2], out var setting)) return false;
        var src = parts[3].Trim().ToUpperInvariant();
        if (src != "AC") return false;
        target = new PowerSettingTarget(scheme, subgroup, setting, src);
        return target.IsAllowedProcessorAcMax;
    }
}

public sealed record PowerSettingWriteOutcome(
    bool Success,
    string Message,
    bool AccessDenied = false,
    bool PolicyLocked = false,
    bool ActivationFailed = false,
    bool PartialChange = false,
    int? ObservedValueAfter = null,
    PowerSettingTarget? Target = null,
    int? PreviousValue = null);

/// <summary>
/// Reads and writes the allowlisted AC Maximum processor state (<c>PROCTHROTTLEMAX</c>) setting with policy checks,
/// activation-only-if-still-active, rollback on activation failure, and Agent fallback on verified permission denied.
/// </summary>
public interface IPowerSettingController
{
    Guid? ReadActiveSchemeGuid();
    bool? IsAcMaxProcessorStateEditable();
    int? ReadAcMaxProcessorState(Guid schemeGuid);
    Task<PowerSettingWriteOutcome> WriteAcMaxProcessorStateAsync(Guid schemeGuid, int newValue, bool activateIfActive, CancellationToken ct);
}

public sealed class WindowsPowerSettingController(
    Session.IElevatedCommandBridge? agent = null,
    ILogger? log = null,
    Func<Guid?>? readActiveScheme = null,
    Func<bool?>? isEditable = null,
    Func<Guid, int?>? readValue = null,
    Func<Guid, int, uint>? writeValue = null,
    Func<Guid, uint>? setActiveScheme = null) : IPowerSettingController
{
    public Guid? ReadActiveSchemeGuid() => readActiveScheme is not null ? readActiveScheme() : WindowsPowerPolicyReader.ReadActiveSchemeGuid(log);

    public bool? IsAcMaxProcessorStateEditable() => isEditable is not null ? isEditable() : WindowsPowerPolicyReader.IsAcMaxProcessorStateEditable(log);

    public int? ReadAcMaxProcessorState(Guid schemeGuid) => readValue is not null ? readValue(schemeGuid) : WindowsPowerPolicyReader.ReadAcMaxProcessorStatePercent(schemeGuid, log);

    private uint WriteValue(Guid schemeGuid, int value) => writeValue is not null ? writeValue(schemeGuid, value) : WindowsPowerPolicyReader.WriteAcMaxProcessorStatePercent(schemeGuid, value, log);

    private uint ActivateScheme(Guid schemeGuid) => setActiveScheme is not null ? setActiveScheme(schemeGuid) : WindowsPowerPolicyReader.SetActiveScheme(schemeGuid, log);

    public async Task<PowerSettingWriteOutcome> WriteAcMaxProcessorStateAsync(Guid schemeGuid, int newValue, bool activateIfActive, CancellationToken ct)
    {
        if (newValue is < 0 or > 100)
            return new(false, "Processor state must be between 0 and 100%.");

        var target = PowerSettingTarget.ForProcessorAcMax(schemeGuid);
        if (IsAcMaxProcessorStateEditable() == false)
            return new(false, "Maximum processor state is locked by Group Policy and cannot be changed.", PolicyLocked: true, Target: target);

        var oldValue = ReadAcMaxProcessorState(schemeGuid);
        if (oldValue is null)
            return new(false, "Maximum processor state is not available on the active power scheme.", Target: target);

        var writeErr = WriteValue(schemeGuid, newValue);
        if (writeErr == WindowsPowerPolicyReader.ErrorAccessDenied)
        {
            if (agent is { IsConnected: true })
            {
                var agentRes = await agent.SetPowerSettingAsync(target.Encode(), newValue, activateIfActive, ct).ConfigureAwait(false);
                if (agentRes.Success)
                    return new(true, agentRes.Message, Target: target, PreviousValue: oldValue);
                return new(false, agentRes.Message, AccessDenied: true, Target: target, PreviousValue: oldValue);
            }
            return new(false, "Windows denied permission to edit the active power scheme. " + Session.ElevationService.AdminRepairHint,
                AccessDenied: true, Target: target, PreviousValue: oldValue);
        }
        if (writeErr != 0)
            return new(false, $"Couldn't update maximum processor state (Windows error {writeErr}).", Target: target, PreviousValue: oldValue);

        if (activateIfActive && ReadActiveSchemeGuid() == schemeGuid)
        {
            var actErr = ActivateScheme(schemeGuid);
            if (actErr != 0)
            {
                var rollbackErr = WriteValue(schemeGuid, oldValue.Value);
                var observed = ReadAcMaxProcessorState(schemeGuid);
                if (rollbackErr == 0 && observed == oldValue.Value)
                    return new(false, $"Power plan activation failed (error {actErr}); original setting ({oldValue}%) was restored.",
                        ActivationFailed: true, Target: target, PreviousValue: oldValue);

                return new(false, $"Power plan activation failed (error {actErr}) and rollback left the setting at {observed?.ToString(CultureInfo.InvariantCulture) ?? "unknown"}%.",
                    ActivationFailed: true, PartialChange: true, ObservedValueAfter: observed, Target: target, PreviousValue: oldValue);
            }
        }

        return new(true, $"Configured maximum processor state on AC set to {newValue}%.", Target: target, PreviousValue: oldValue);
    }
}
