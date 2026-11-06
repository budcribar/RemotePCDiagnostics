namespace RemotePCDiagnostics.Core;

/// <summary>
/// The permanent identity of every built-in module. An id is fixed forever and never reused: results, History, preferences and fixes key
/// on it, so changing one would orphan saved data. ModuleIdsTests pins each value. A module that is dropped keeps its id here, because
/// History can still show its old results. Field names match today's module names (the slugs).
/// </summary>
public static class ModuleIds
{
    /// <summary>Slug <c>Osquery</c>.</summary>
    public static readonly Guid Osquery = new("44bcd831-09d1-46e8-8355-289ae77c7bf0");
    /// <summary>Slug <c>Sensors</c>.</summary>
    public static readonly Guid Sensors = new("0693da7b-093d-4f58-9e31-de22588fc0e7");
    /// <summary>Slug <c>CpuStress</c>.</summary>
    public static readonly Guid CpuStress = new("32813968-b952-417a-b5c0-53909188581d");
    /// <summary>Slug <c>MemoryTest</c>.</summary>
    public static readonly Guid MemoryTest = new("cfe95422-ed12-4dde-8bdc-9fed3db3a614");
    /// <summary>Slug <c>DiskSpeed</c>.</summary>
    public static readonly Guid DiskSpeed = new("09250d9c-dffb-4ad5-afb8-8bdb61e35230");
    /// <summary>Slug <c>GpuStress</c>.</summary>
    public static readonly Guid GpuStress = new("ff15c281-8b03-43d3-9465-d3f5e2187bb3");
    /// <summary>Slug <c>NetworkTest</c>.</summary>
    public static readonly Guid NetworkTest = new("b2383e8c-57ec-47a4-8de2-830adb3b75c3");
    /// <summary>Slug <c>DriveHealth</c>.</summary>
    public static readonly Guid DriveHealth = new("6e35be79-5873-46de-b029-de1c69e05d58");
    /// <summary>Slug <c>Services</c>.</summary>
    public static readonly Guid Services = new("33fea5b3-3004-4fe5-8188-1d0cb0e14c93");
    /// <summary>Slug <c>Programs</c>.</summary>
    public static readonly Guid Programs = new("031e7150-84b6-4d77-8788-28dccaa94246");
    /// <summary>Slug <c>Network</c>.</summary>
    public static readonly Guid Network = new("b20a783c-c8b2-4674-a40a-37244b1b5e02");
    /// <summary>Slug <c>EventLog</c>.</summary>
    public static readonly Guid EventLog = new("3f767a16-4998-45dc-8883-f1f0068adfc0");
    /// <summary>Slug <c>Crashes</c>.</summary>
    public static readonly Guid Crashes = new("31248025-232b-48ed-a0aa-b1a90fa045c0");
    /// <summary>Slug <c>ResourceHogs</c>.</summary>
    public static readonly Guid ResourceHogs = new("bb36465f-fcbc-4eb3-a6c9-de953345b9b0");
    /// <summary>Slug <c>DeviceDrivers</c>.</summary>
    public static readonly Guid DeviceDrivers = new("09f626ba-8cda-4c17-a273-ad98dd9eff40");
    /// <summary>Slug <c>DismScanHealth</c>.</summary>
    public static readonly Guid DismScanHealth = new("350cb8c3-5dd6-431c-833c-702370d9d8da");
    /// <summary>Slug <c>SfcVerifyOnly</c>.</summary>
    public static readonly Guid SfcVerifyOnly = new("aed77d8b-a41d-426c-9b0e-07ee8b9af2e1");
    /// <summary>Slug <c>BatteryPower</c>.</summary>
    public static readonly Guid BatteryPower = new("f9635901-3c6c-4c69-bdc7-b4f10d0c53a0");
    /// <summary>Slug <c>BsodHistory</c>.</summary>
    public static readonly Guid BsodHistory = new("79f39506-a342-4820-a4eb-5a77155e1aa4");
    /// <summary>Slug <c>WifiConfig</c>.</summary>
    public static readonly Guid WifiConfig = new("952f327a-daad-40b2-a177-ffab335d7246");
    /// <summary>Slug <c>SecurityAudit</c>.</summary>
    public static readonly Guid SecurityAudit = new("2a538099-302e-41ca-9e31-93a425bf76b3");
    /// <summary>Slug <c>SpeakerToMic</c>.</summary>
    public static readonly Guid SpeakerToMic = new("8b37f40f-7a2e-428e-a71e-057e895e920d");
    /// <summary>Slug <c>MicToSpeaker</c>.</summary>
    public static readonly Guid MicToSpeaker = new("670ba9f7-bd2c-4207-b13b-9a9f7262489d");
    /// <summary>Slug <c>Webcam</c>.</summary>
    public static readonly Guid Webcam = new("243be433-599b-42e4-ad92-04346a59a292");
    /// <summary>Slug <c>NpuTest</c>.</summary>
    public static readonly Guid NpuTest = new("85ffb9ea-fb21-4189-9714-5d58f7115237");
    /// <summary>Slug <c>BootSecurity</c>.</summary>
    public static readonly Guid BootSecurity = new("61025d7b-f5ef-4286-82ff-df9a74834b39");

    /// <summary>Every built-in id with its slug (the module's Name). Includes modules that are not registered on every build.</summary>
    public static IReadOnlyDictionary<Guid, string> BuiltIn { get; } = new Dictionary<Guid, string>
    {
        [Osquery] = ModuleSlugs.Osquery,
        [Sensors] = ModuleSlugs.Sensors,
        [CpuStress] = ModuleSlugs.CpuStress,
        [MemoryTest] = ModuleSlugs.MemoryTest,
        [DiskSpeed] = ModuleSlugs.DiskSpeed,
        [GpuStress] = ModuleSlugs.GpuStress,
        [NetworkTest] = ModuleSlugs.NetworkTest,
        [DriveHealth] = ModuleSlugs.DriveHealth,
        [Services] = ModuleSlugs.Services,
        [Programs] = ModuleSlugs.Programs,
        [Network] = ModuleSlugs.Network,
        [EventLog] = ModuleSlugs.EventLog,
        [Crashes] = ModuleSlugs.Crashes,
        [ResourceHogs] = ModuleSlugs.ResourceHogs,
        [DeviceDrivers] = ModuleSlugs.DeviceDrivers,
        [DismScanHealth] = ModuleSlugs.DismScanHealth,
        [SfcVerifyOnly] = ModuleSlugs.SfcVerifyOnly,
        [BatteryPower] = ModuleSlugs.BatteryPower,
        [BsodHistory] = ModuleSlugs.BsodHistory,
        [WifiConfig] = ModuleSlugs.WifiConfig,
        [SecurityAudit] = ModuleSlugs.SecurityAudit,
        [SpeakerToMic] = ModuleSlugs.SpeakerToMic,
        [MicToSpeaker] = ModuleSlugs.MicToSpeaker,
        [Webcam] = ModuleSlugs.Webcam,
        [NpuTest] = ModuleSlugs.NpuTest,
        [BootSecurity] = ModuleSlugs.BootSecurity,
    };

    /// <summary>The built-in id for a slug (case-insensitive), or null for an unknown name.</summary>
    public static Guid? FromSlug(string? slug)
    {
        if (string.IsNullOrEmpty(slug)) return null;
        foreach (var (id, s) in BuiltIn)
            if (string.Equals(s, slug, StringComparison.OrdinalIgnoreCase)) return id;
        return null;
    }
}

/// <summary>The slug (<see cref="IDiagnosticModule.Name"/>) of every built-in module, as constants so code never spells a module name out.</summary>
public static class ModuleSlugs
{
    public const string Osquery = "Osquery";
    public const string Sensors = "Sensors";
    public const string CpuStress = "CpuStress";
    public const string MemoryTest = "MemoryTest";
    public const string DiskSpeed = "DiskSpeed";
    public const string GpuStress = "GpuStress";
    public const string NetworkTest = "NetworkTest";
    public const string DriveHealth = "DriveHealth";
    public const string Services = "Services";
    public const string Programs = "Programs";
    public const string Network = "Network";
    public const string EventLog = "EventLog";
    public const string Crashes = "Crashes";
    public const string ResourceHogs = "ResourceHogs";
    public const string DeviceDrivers = "DeviceDrivers";
    public const string DismScanHealth = "DismScanHealth";
    public const string SfcVerifyOnly = "SfcVerifyOnly";
    public const string BatteryPower = "BatteryPower";
    public const string BsodHistory = "BsodHistory";
    public const string WifiConfig = "WifiConfig";
    public const string SecurityAudit = "SecurityAudit";
    public const string SpeakerToMic = "SpeakerToMic";
    public const string MicToSpeaker = "MicToSpeaker";
    public const string Webcam = "Webcam";
    public const string NpuTest = "NpuTest";
    public const string BootSecurity = "BootSecurity";
}
