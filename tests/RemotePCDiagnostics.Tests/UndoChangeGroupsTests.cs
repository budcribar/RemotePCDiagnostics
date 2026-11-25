using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class UndoChangeGroupsTests
{
    private sealed class FakeJournal : IChangeJournal
    {
        public List<ChangeRecord> Records { get; } = [];
        public IReadOnlyList<ChangeRecord> All => Records;
        public event Action? Changed;
        public void Add(ChangeRecord record) { Records.Add(record); Changed?.Invoke(); }
        public void Remove(Guid id) { Records.RemoveAll(r => r.Id == id); Changed?.Invoke(); }
        public void RemoveLatest(ChangeKind kind, string target)
        {
            var idx = Records.FindLastIndex(r => r.Kind == kind && string.Equals(r.Target, target, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0) { Records.RemoveAt(idx); Changed?.Invoke(); }
        }
    }

    private sealed class FakeUserEnvStore : IUserEnvironmentStore
    {
        public Dictionary<string, string?> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
        public string? Read(string name) => Values.TryGetValue(name, out var v) ? v : null;
        public void Write(string name, string value) => Values[name] = value;
        public void Delete(string name) => Values.Remove(name);
        public void EnsureDirectory(string path) { }
    }

    [Fact]
    public void Every_ChangeKind_maps_to_a_valid_category()
    {
        foreach (var kind in Enum.GetValues<ChangeKind>())
        {
            var cat = UndoChangeGroups.CategoryFor(kind);
            Assert.False(string.IsNullOrWhiteSpace(cat.Key));
            Assert.False(string.IsNullOrWhiteSpace(cat.Title));
            Assert.False(string.IsNullOrWhiteSpace(cat.Description));
        }
    }

    [Fact]
    public void Group_organizes_removed_apps_and_defender_exclusions_in_order_newest_first()
    {
        var t1 = new DateTimeOffset(2026, 11, 25, 10, 0, 0, TimeSpan.Zero);
        var t2 = t1.AddMinutes(5);
        var t3 = t1.AddMinutes(10);

        var records = new[]
        {
            new ChangeRecord(Guid.NewGuid(), t1, ChangeKind.DefenderExclusion, @"path|C:\src\app1", null, "Defender no longer scans C:\\src\\app1", "tech"),
            new ChangeRecord(Guid.NewGuid(), t2, ChangeKind.StoreReinstall, "Microsoft.BingWeather_8wekyb3d8bbwe", "9WZDNCRFJ3Q2", "Removed MSN Weather", "tech"),
            new ChangeRecord(Guid.NewGuid(), t3, ChangeKind.DefenderExclusion, @"path|C:\src\app2", null, "Defender no longer scans C:\\src\\app2", "tech"),
            new ChangeRecord(Guid.NewGuid(), t1, ChangeKind.StartupApp, "Spotify", null, "Spotify won't start with Windows", "tech"),
        };

        var groups = UndoChangeGroups.Group(records);

        Assert.Equal(3, groups.Count);
        Assert.Equal(UndoChangeGroups.RemovedApps.Key, groups[0].Key);
        Assert.Single(groups[0].Items);

        Assert.Equal(UndoChangeGroups.DefenderExclusions.Key, groups[1].Key);
        Assert.Equal(2, groups[1].Items.Count);
        // Newest first inside the group
        Assert.Contains("app2", groups[1].Items[0].Label);
        Assert.Contains("app1", groups[1].Items[1].Label);

        Assert.Equal(UndoChangeGroups.StartupAndServices.Key, groups[2].Key);
        Assert.Single(groups[2].Items);
    }

    [Fact]
    public async Task UndoSelectedAsync_reverts_only_selected_category_and_preserves_other_entries()
    {
        var journal = new FakeJournal();
        var env = new FakeUserEnvStore();
        env.Values["NUGET_PACKAGES"] = @"D:\packages\nuget";
        env.Values["npm_config_cache"] = @"D:\packages\npm";

        var env1 = ChangeRecord.New(ChangeKind.UserEnvironmentVariable, "NUGET_PACKAGES", null, "Moved NuGet cache to D:\\", "tech");
        var env2 = ChangeRecord.New(ChangeKind.UserEnvironmentVariable, "npm_config_cache", @"C:\old\npm", "Moved npm cache to D:\\", "tech");
        var storeApp = ChangeRecord.New(ChangeKind.StoreReinstall, "Microsoft.BingWeather_8wekyb3d8bbwe", "9WZDNCRFJ3Q2", "Removed MSN Weather", "tech");
        journal.Add(env1);
        journal.Add(env2);
        journal.Add(storeApp);

        var undo = new UndoService(journal, new SystemCommandRunner(), userEnv: env);
        var result = await undo.UndoSelectedAsync([env1.Id, env2.Id], "tech", CancellationToken.None);

        Assert.Equal(2, result.Succeeded);
        Assert.Equal(0, result.Failed);
        Assert.Null(env.Read("NUGET_PACKAGES"));
        Assert.Equal(@"C:\old\npm", env.Read("npm_config_cache"));
        // Only the unselected Store app remains in the journal.
        var remaining = Assert.Single(journal.Records);
        Assert.Equal(storeApp.Id, remaining.Id);
    }
}
