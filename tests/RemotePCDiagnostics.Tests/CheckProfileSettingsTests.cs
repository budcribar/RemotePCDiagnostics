using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Checks;

namespace RemotePCDiagnostics.Tests;

/// <summary>Picking check profiles on the Checks page: what is saved on the PC, and when the profile choice is dropped.</summary>
public class CheckProfileSettingsTests
{
    private static readonly string[] Available =
    [
        ModuleSlugs.Osquery, ModuleSlugs.Sensors, ModuleSlugs.DeviceDrivers, ModuleSlugs.DriveHealth, ModuleSlugs.ResourceHogs,
        ModuleSlugs.BatteryPower, ModuleSlugs.SleepWake, ModuleSlugs.Network, ModuleSlugs.Services, ModuleSlugs.EventLog,
        ModuleSlugs.Crashes, ModuleSlugs.Programs, ModuleSlugs.DeveloperSetup, ModuleSlugs.SecurityEssentials,
        ModuleSlugs.WindowsMaintenance, ModuleSlugs.Sound,
    ];

    [Fact]
    public void Picking_a_profile_saves_the_whole_on_off_list_and_the_profile_in_one_save()
    {
        var store = new CountingStore();
        var svc = new CheckSettingsService(store);

        svc.SetProfiles([CheckProfiles.Office], Available, persistToHost: true);

        Assert.Equal(1, store.Saves);
        var saved = store.State!;
        Assert.Equal([CheckProfiles.Office], saved.Profiles);
        var office = CheckProfiles.Find(CheckProfiles.Office)!.CheckIds;
        foreach (var id in Available)
            Assert.Equal(office.Contains(id), saved.IsEnabled(id));
        Assert.False(svc.HasSessionPrefs);
    }

    [Fact]
    public void Profiles_are_additive_and_dropping_the_last_one_turns_every_check_back_on()
    {
        var store = new CountingStore();
        var svc = new CheckSettingsService(store);

        svc.SetProfiles([CheckProfiles.Gamer, CheckProfiles.Developer], Available, persistToHost: true);
        Assert.True(store.State!.IsEnabled(ModuleSlugs.Sensors));
        Assert.True(store.State.IsEnabled(ModuleSlugs.DeveloperSetup));
        Assert.False(store.State.IsEnabled(ModuleSlugs.SecurityEssentials));
        Assert.Equal([CheckProfiles.Developer, CheckProfiles.Gamer], store.State.Profiles);

        svc.SetProfiles([], Available, persistToHost: true);
        Assert.Empty(store.State.Profiles);
        Assert.All(Available, id => Assert.True(store.State.IsEnabled(id)));
    }

    [Fact]
    public void Turning_a_check_on_or_off_by_hand_clears_the_profile_but_keeps_the_list()
    {
        var store = new CountingStore();
        var svc = new CheckSettingsService(store);
        svc.SetProfiles([CheckProfiles.Home], Available, persistToHost: true);

        svc.SetEnabled(ModuleSlugs.Sound, on: true, available: true, persistToHost: true);

        Assert.Empty(store.State!.Profiles);
        Assert.True(store.State.IsEnabled(ModuleSlugs.Sound));
        Assert.True(store.State.IsEnabled(ModuleSlugs.SecurityEssentials));
        Assert.False(store.State.IsEnabled(ModuleSlugs.Sensors));

        svc.SetProfiles([CheckProfiles.Home], Available, persistToHost: true);
        svc.SetAll(Available, on: true, persistToHost: true);
        Assert.Empty(store.State.Profiles);
    }

    [Fact]
    public void A_remote_technician_picking_a_profile_changes_only_the_session_not_the_pc()
    {
        var store = new CountingStore();
        var svc = new CheckSettingsService(store);

        svc.SetProfiles([CheckProfiles.Performance], Available, persistToHost: false);

        Assert.Equal(0, store.Saves);
        Assert.True(svc.HasSessionPrefs);
        Assert.Equal([CheckProfiles.Performance], svc.Settings.Profiles);
        Assert.False(svc.Settings.IsEnabled(ModuleSlugs.Sound));
        Assert.True(svc.SavedSettings.IsEnabled(ModuleSlugs.Sound));
    }

    [Fact]
    public void Hidden_checks_keep_their_saved_state_when_a_profile_is_picked()
    {
        var store = new CountingStore { State = new CheckSettings { Disabled = [ModuleSlugs.Webcam] } };
        var svc = new CheckSettingsService(store);

        svc.SetProfiles([CheckProfiles.Office], [ModuleSlugs.Network, ModuleSlugs.Osquery], persistToHost: true);

        Assert.False(store.State!.IsEnabled(ModuleSlugs.Webcam));
        Assert.True(store.State.IsEnabled(ModuleSlugs.Network));
        Assert.False(store.State.IsEnabled(ModuleSlugs.Osquery));
        Assert.True(store.State.IsEnabled(ModuleSlugs.Sound)); // not available here, so not touched
    }

    [Fact]
    public void Profiles_round_trip_through_the_saved_file_and_unknown_ids_are_dropped()
    {
        var json = new CheckSettings { Profiles = ["GAMER", "nope", CheckProfiles.Developer, "gamer"] }.ToJson();
        var back = CheckSettings.FromJson(json)!;
        Assert.Equal([CheckProfiles.Developer, CheckProfiles.Gamer], back.Profiles);

        Assert.Empty(CheckSettings.FromJson("""{ "Disabled": [] }""")!.Profiles);
    }

    [Fact]
    public void Every_profile_names_only_built_in_checks_and_office_includes_sound()
    {
        var checks = BuiltInModules.Descriptors
            .Where(d => d.Kind == ModuleKind.Check && d.MergedInto is null)
            .Select(d => d.Slug)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var profile in CheckProfiles.All)
        {
            Assert.NotEmpty(profile.CheckIds);
            Assert.All(profile.CheckIds, id => Assert.Contains(id, checks));
        }
        Assert.Contains(ModuleSlugs.Sound, CheckProfiles.Find(CheckProfiles.Office)!.CheckIds);
        Assert.Contains(ModuleSlugs.Sensors, CheckProfiles.Find(CheckProfiles.Gamer)!.CheckIds);
    }

    [Fact]
    public void The_checks_page_data_lists_each_profile_its_checks_and_which_are_picked()
    {
        CheckChoice[] choices =
        [
            new(ModuleSlugs.Osquery, "Hardware inventory", "Hardware", Available: true, Enabled: true, Reason: null),
            new(ModuleSlugs.Sound, "Sound", "Audio", Available: true, Enabled: false, Reason: null),
        ];

        using var doc = System.Text.Json.JsonDocument.Parse(AgentExports.CheckEnablement(choices, [CheckProfiles.Office]));
        var root = doc.RootElement;
        var profiles = root.GetProperty("profiles").EnumerateArray().ToList();
        Assert.Equal(CheckProfiles.All.Select(p => p.Id), profiles.Select(p => p.GetProperty("id").GetString()));
        var office = profiles.Single(p => p.GetProperty("id").GetString() == CheckProfiles.Office);
        Assert.True(office.GetProperty("active").GetBoolean());
        Assert.Equal("Office worker", office.GetProperty("name").GetString());
        Assert.Contains(ModuleSlugs.Sound, office.GetProperty("checks").EnumerateArray().Select(c => c.GetString()));
        Assert.All(profiles.Where(p => p.GetProperty("id").GetString() != CheckProfiles.Office), p => Assert.False(p.GetProperty("active").GetBoolean()));

        var rows = root.GetProperty("checks").EnumerateArray().ToList();
        Assert.Equal([CheckProfiles.Developer, CheckProfiles.Performance], rows[0].GetProperty("profiles").EnumerateArray().Select(p => p.GetString()));
        Assert.Equal([CheckProfiles.Office], rows[1].GetProperty("profiles").EnumerateArray().Select(p => p.GetString()));
        Assert.Equal(6, BrowserContract.Checks);
    }

    private sealed class CountingStore : ICheckSettingsStore
    {
        public CheckSettings? State;
        public int Saves;
        public CheckSettings? Load() => State;
        public void Save(CheckSettings settings) { State = settings; Saves++; }
    }
}
