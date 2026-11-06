using System.Reflection;
using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Module ids are permanent: results, History and saved state key on them. This table is the record of every id ever shipped.
/// If one of these tests fails, an id was changed or removed by accident: put it back. A new module adds a row here; a row is never edited
/// or deleted.
/// </summary>
public class ModuleIdsTests
{
    private static readonly Dictionary<string, string> Pinned = new()
    {
        ["Osquery"] = "44bcd831-09d1-46e8-8355-289ae77c7bf0",
        ["Sensors"] = "0693da7b-093d-4f58-9e31-de22588fc0e7",
        ["CpuStress"] = "32813968-b952-417a-b5c0-53909188581d",
        ["MemoryTest"] = "cfe95422-ed12-4dde-8bdc-9fed3db3a614",
        ["DiskSpeed"] = "09250d9c-dffb-4ad5-afb8-8bdb61e35230",
        ["GpuStress"] = "ff15c281-8b03-43d3-9465-d3f5e2187bb3",
        ["NetworkTest"] = "b2383e8c-57ec-47a4-8de2-830adb3b75c3",
        ["DriveHealth"] = "6e35be79-5873-46de-b029-de1c69e05d58",
        ["Services"] = "33fea5b3-3004-4fe5-8188-1d0cb0e14c93",
        ["Programs"] = "031e7150-84b6-4d77-8788-28dccaa94246",
        ["Network"] = "b20a783c-c8b2-4674-a40a-37244b1b5e02",
        ["EventLog"] = "3f767a16-4998-45dc-8883-f1f0068adfc0",
        ["Crashes"] = "31248025-232b-48ed-a0aa-b1a90fa045c0",
        ["ResourceHogs"] = "bb36465f-fcbc-4eb3-a6c9-de953345b9b0",
        ["DeviceDrivers"] = "09f626ba-8cda-4c17-a273-ad98dd9eff40",
        ["DismScanHealth"] = "350cb8c3-5dd6-431c-833c-702370d9d8da",
        ["SfcVerifyOnly"] = "aed77d8b-a41d-426c-9b0e-07ee8b9af2e1",
        ["BatteryPower"] = "f9635901-3c6c-4c69-bdc7-b4f10d0c53a0",
        ["BsodHistory"] = "79f39506-a342-4820-a4eb-5a77155e1aa4",
        ["WifiConfig"] = "952f327a-daad-40b2-a177-ffab335d7246",
        ["SecurityAudit"] = "2a538099-302e-41ca-9e31-93a425bf76b3",
        ["SpeakerToMic"] = "8b37f40f-7a2e-428e-a71e-057e895e920d",
        ["MicToSpeaker"] = "670ba9f7-bd2c-4207-b13b-9a9f7262489d",
        ["Webcam"] = "243be433-599b-42e4-ad92-04346a59a292",
        ["NpuTest"] = "85ffb9ea-fb21-4189-9714-5d58f7115237",
        ["BootSecurity"] = "61025d7b-f5ef-4286-82ff-df9a74834b39",
    };

    [Fact]
    public void Every_built_in_id_is_pinned()
    {
        var fields = typeof(ModuleIds).GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(Guid)).ToList();
        Assert.Equal(Pinned.Count, fields.Count);
        foreach (var f in fields)
        {
            Assert.True(Pinned.TryGetValue(f.Name, out var expected), $"ModuleIds.{f.Name} has no pinned row; add one to this test.");
            Assert.Equal(Guid.Parse(expected), (Guid)f.GetValue(null)!);
        }
    }

    [Fact]
    public void BuiltIn_maps_every_id_to_its_slug()
    {
        Assert.Equal(Pinned.Count, ModuleIds.BuiltIn.Count);
        foreach (var (slug, id) in Pinned)
        {
            Assert.Equal(slug, ModuleIds.BuiltIn[Guid.Parse(id)]);
            Assert.Equal(Guid.Parse(id), ModuleIds.FromSlug(slug));
            Assert.Equal(Guid.Parse(id), ModuleIds.FromSlug(slug.ToLowerInvariant()));
            Assert.Equal(slug, typeof(ModuleSlugs).GetField(slug)!.GetRawConstantValue());
        }
        Assert.Null(ModuleIds.FromSlug("NoSuchModule"));
        Assert.Null(ModuleIds.FromSlug(null));
    }

    [Fact]
    public void Ids_are_unique_and_not_empty()
    {
        var all = Pinned.Values.Select(Guid.Parse).ToList();
        Assert.DoesNotContain(Guid.Empty, all);
        Assert.Equal(all.Count, all.Distinct().Count());
    }

    [Fact]
    public void Register_rejects_a_duplicate_id()
    {
        var svc = new DiagnosticsService(new ResultStore());
        var id = Guid.NewGuid();
        svc.Register(new IdModule("First", id));
        var ex = Assert.Throws<InvalidOperationException>(() => svc.Register(new IdModule("Second", id)));
        Assert.Contains("First", ex.Message);
    }

    [Fact]
    public void Register_rejects_an_empty_id()
    {
        var svc = new DiagnosticsService(new ResultStore());
        Assert.Throws<InvalidOperationException>(() => svc.Register(new IdModule("NoId", Guid.Empty)));
    }

    private sealed class IdModule(string name, Guid id) : IDiagnosticModule
    {
        public Guid Id => id;
        public string Name => name;
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) =>
            Task.FromResult(new DiagnosticResult(name, DiagnosticStatus.Ok, "ok", DateTimeOffset.Now));
    }
}
