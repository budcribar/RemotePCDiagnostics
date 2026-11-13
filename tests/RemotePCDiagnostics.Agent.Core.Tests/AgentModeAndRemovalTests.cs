using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent.Core.Tests;

public class AgentModeTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void No_install_and_no_status_is_local_only()
    {
        var snap = AgentMode.From(new AgentModeSignals(false, false, null, null), Now);
        Assert.Equal(AgentModeKind.LocalOnly, snap.Kind);
        Assert.Equal("Local only", snap.Label);
        Assert.Equal("badge badge-local", snap.CssClass);
        Assert.Null(snap.ShopGroup);
        Assert.Equal(AgentMode.Tooltip, snap.Tooltip);
    }

    [Fact]
    public void Installed_without_a_fresh_link_is_not_connected_and_hides_any_group()
    {
        var snap = AgentMode.From(new AgentModeSignals(true, true, Now.AddMinutes(-3), "acme-pc"), Now);
        Assert.Equal(AgentModeKind.InstalledNotConnected, snap.Kind);
        Assert.Equal("Agent installed, not connected", snap.Label);
        Assert.Equal("badge", snap.CssClass);
        Assert.Null(snap.ShopGroup);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Fresh_link_is_connected_whether_or_not_the_default_exe_was_found(bool installed)
    {
        var snap = AgentMode.From(new AgentModeSignals(installed, true, Now.AddSeconds(-10), "Acme-PC"), Now);
        Assert.Equal(AgentModeKind.Connected, snap.Kind);
        Assert.Equal("acme-pc", snap.ShopGroup);
        Assert.Equal("Agent connected · acme-pc", snap.Label);
        Assert.Equal("badge badge-remote", snap.CssClass);
    }

    [Fact]
    public void Connected_without_a_known_group_does_not_invent_one()
    {
        var snap = AgentMode.From(new AgentModeSignals(true, true, Now, "  "), Now);
        Assert.Equal(AgentModeKind.Connected, snap.Kind);
        Assert.Null(snap.ShopGroup);
        Assert.Equal("Agent connected", snap.Label);
    }

    [Fact]
    public void A_group_with_a_slash_is_not_shown()
    {
        var snap = AgentMode.From(new AgentModeSignals(true, true, Now, "../acme"), Now);
        Assert.Equal("Agent connected", snap.Label);
        Assert.Null(snap.ShopGroup);
    }

    [Fact]
    public void Link_stays_fresh_through_ninety_seconds_and_five_seconds_of_clock_skew()
    {
        Assert.True(AgentMode.IsFresh(Now.AddSeconds(-90), Now));
        Assert.False(AgentMode.IsFresh(Now.AddSeconds(-90).AddTicks(-1), Now));
        Assert.True(AgentMode.IsFresh(Now.AddSeconds(5), Now));
        Assert.False(AgentMode.IsFresh(Now.AddSeconds(5).AddTicks(1), Now));
    }

    [Fact]
    public void Explicitly_down_link_is_not_connected_even_when_the_timestamp_is_fresh()
    {
        var snap = AgentMode.From(new AgentModeSignals(true, false, Now, "acme-pc"), Now);
        Assert.Equal(AgentModeKind.InstalledNotConnected, snap.Kind);
    }

    [Fact]
    public void Stale_status_file_without_an_install_stays_local_only()
    {
        var snap = AgentMode.From(new AgentModeSignals(false, true, Now.AddMinutes(-10), "acme-pc"), Now);
        Assert.Equal(AgentModeKind.LocalOnly, snap.Kind);
    }

    [Fact]
    public void Status_json_round_trips_without_an_enrollment_key()
    {
        var status = new AgentLinkStatus
        {
            Connected = true,
            UpdatedUtc = "2026-11-13T12:00:00.0000000+00:00",
            Group = "acme-pc",
        };
        var json = status.ToJson();
        Assert.DoesNotContain("key", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("rpd_live", json, StringComparison.OrdinalIgnoreCase);

        var parsed = AgentLinkStatus.Parse(json + "");
        Assert.NotNull(parsed);
        Assert.True(parsed.Connected);
        Assert.Equal(Now, parsed.Updated);
        Assert.Equal("acme-pc", parsed.Group);

        var poisoned = AgentLinkStatus.Parse(
            "{\"connected\":true,\"updatedUtc\":\"2026-11-13T12:00:00.0000000+00:00\",\"group\":\"acme-pc\",\"key\":\"rpd_live_secret\"}");
        Assert.NotNull(poisoned);
        Assert.DoesNotContain("rpd_live_secret", poisoned.ToJson(), StringComparison.Ordinal);
        Assert.Null(AgentLinkStatus.Parse("{not json"));
        Assert.Null(AgentLinkStatus.Parse(""));
    }

    [Fact]
    public void Reader_uses_the_service_only_when_the_exe_is_missing_and_rereads_status_when_it_changes()
    {
        var root = Path.Combine(Path.GetTempPath(), "rpcd-mode-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var exe = Path.Combine(root, "RemotePCDiagnostics.Agent.exe");
            var statusPath = Path.Combine(root, "agent-status.json");
            var calls = 0;
            var reader = new AgentModeReader(exe, statusPath, () => { calls++; return true; }, TimeSpan.FromSeconds(30));

            File.WriteAllText(exe, "agent");
            var withExe = reader.Read(Now);
            Assert.Equal(AgentModeKind.InstalledNotConnected, withExe.Kind);
            Assert.Equal(0, calls);

            File.Delete(exe);
            var serviceSeen = reader.Read(Now.AddSeconds(30));
            Assert.Equal(AgentModeKind.InstalledNotConnected, serviceSeen.Kind);
            Assert.Equal(1, calls);
            reader.Read(Now.AddSeconds(40));
            Assert.Equal(1, calls);
            reader.Read(Now.AddSeconds(60));
            Assert.Equal(2, calls);

            var down = new AgentLinkStatus { Connected = false, UpdatedUtc = Now.ToString("O"), Group = "secret-shop" };
            File.WriteAllText(statusPath, down.ToJson());
            var stamp = new DateTime(2026, 11, 13, 12, 0, 0, DateTimeKind.Utc);
            File.SetLastWriteTimeUtc(statusPath, stamp);
            var serviceOff = new AgentModeReader(exe, statusPath, () => false, TimeSpan.Zero);
            Assert.Equal(AgentModeKind.LocalOnly, serviceOff.Read(Now).Kind);

            var up = new AgentLinkStatus { Connected = true, UpdatedUtc = Now.AddSeconds(-5).ToString("O"), Group = "Acme-PC" };
            File.WriteAllText(statusPath, up.ToJson());
            File.SetLastWriteTimeUtc(statusPath, stamp);
            Assert.Equal(AgentModeKind.LocalOnly, serviceOff.Read(Now).Kind);

            File.SetLastWriteTimeUtc(statusPath, stamp.AddSeconds(1));
            var connected = serviceOff.Read(Now);
            Assert.Equal(AgentModeKind.Connected, connected.Kind);
            Assert.Equal("acme-pc", connected.ShopGroup);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Monitor_raises_changed_only_when_the_badge_changes_and_stops_when_disposed()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var monitor = new AgentModeMonitor(_ =>
        {
            if (Interlocked.Increment(ref calls) == 1)
                return AgentModeSnapshot.LocalOnly;
            release.Task.GetAwaiter().GetResult();
            return new AgentModeSnapshot(AgentModeKind.InstalledNotConnected, null);
        }, TimeSpan.FromMilliseconds(20));
        try
        {
            Assert.Equal(AgentModeKind.LocalOnly, monitor.Current.Kind);
            var changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            monitor.Changed += () => changed.TrySetResult();
            release.TrySetResult();
            await changed.Task.WaitAsync(TimeSpan.FromSeconds(3));
            Assert.Equal("Agent installed, not connected", monitor.Current.Label);
        }
        finally
        {
            release.TrySetResult();
            monitor.Dispose();
        }

        var quiet = new AgentModeMonitor(_ => AgentModeSnapshot.LocalOnly, startLoop: false);
        var raised = 0;
        quiet.Changed += () => raised++;
        quiet.Refresh(Now);
        Assert.Equal(0, raised);
        quiet.Dispose();
    }
}

public class AgentRemovalTests
{
    [Fact]
    public void Install_accepts_a_shop_group_and_stores_it_beside_the_key()
    {
        var parsed = AgentCommandLine.Parse(["install", "--group=Acme-PC", "--key=rpd_live_secret", "--lifetime=persistent"]);
        Assert.Null(parsed.Error);
        Assert.Equal("acme-pc", parsed.Group);

        var config = AgentConfig.ForInstall(null, parsed, Guid.Parse("7e57c0de-0000-4000-8000-000000000042"));
        Assert.Equal("acme-pc", config.Group);
        Assert.Equal("rpd_live_secret", config.Key);
        var roundTrip = AgentConfig.Parse(config.ToJson());
        Assert.NotNull(roundTrip);
        Assert.Equal("acme-pc", roundTrip.Group);
        Assert.Equal("rpd_live_secret", roundTrip.Key);

        var kept = AgentConfig.ForInstall(config, new AgentArgs(AgentCommand.Install, Server: "https://relay.example:443"), Guid.NewGuid());
        Assert.Equal("acme-pc", kept.Group);

        Assert.NotNull(AgentCommandLine.Parse(["install", "--group=../x"]).Error);
        Assert.NotNull(AgentCommandLine.Parse(["uninstall", "--group=acme"]).Error);
    }

    [Fact]
    public void Delete_removes_the_key_cache_and_install_folder_and_leaves_the_undo_journal()
    {
        var root = Path.Combine(Path.GetTempPath(), "rpcd-uninstall-" + Guid.NewGuid().ToString("N"));
        var data = Path.Combine(root, "RemotePCDiagnostics");
        var install = Path.Combine(root, "RemotePCDiagnosticsAgent");
        Directory.CreateDirectory(Path.Combine(data, "state"));
        Directory.CreateDirectory(Path.Combine(data, "app", "1.2.0"));
        Directory.CreateDirectory(Path.Combine(data, "logs"));
        Directory.CreateDirectory(install);
        var journal = Path.Combine(data, "state", "changes.json");
        File.WriteAllText(journal, "{\"undo\":true}");
        File.WriteAllText(Path.Combine(data, "state", "agent.json"), "do-not-treat-me-as-the-key-file");
        File.WriteAllText(Path.Combine(data, "notes.txt"), "keep");
        File.WriteAllText(Path.Combine(data, "agent.json"), "{\"key\":\"rpd_live_secret\"}");
        File.WriteAllText(Path.Combine(data, "agent-status.json"), "{\"connected\":true}");
        File.WriteAllText(Path.Combine(data, "agent-host.json"), "{\"hostEverSeen\":true}");
        File.WriteAllText(Path.Combine(data, "logs", "RemotePCDiagnostics.Agent.log"), "log");
        File.WriteAllText(Path.Combine(data, "app", "1.2.0", "RemotePCDiagnostics.Host.exe"), "cached");
        File.WriteAllText(Path.Combine(install, "RemotePCDiagnostics.Agent.exe"), "agent");

        try
        {
            var result = AgentRemoval.DeleteOwnedFiles(data, install, deleteInstallDirectory: true);
            Assert.False(File.Exists(Path.Combine(data, "agent.json")));
            Assert.False(File.Exists(Path.Combine(data, "agent-status.json")));
            Assert.False(File.Exists(Path.Combine(data, "agent-host.json")));
            Assert.False(Directory.Exists(Path.Combine(data, "app")));
            Assert.False(Directory.Exists(install));
            Assert.Equal("{\"undo\":true}", File.ReadAllText(journal));
            Assert.Equal("do-not-treat-me-as-the-key-file", File.ReadAllText(Path.Combine(data, "state", "agent.json")));
            Assert.Equal("keep", File.ReadAllText(Path.Combine(data, "notes.txt")));
            Assert.DoesNotContain(result.Removed, p => p.Contains($"{Path.DirectorySeparatorChar}state", StringComparison.OrdinalIgnoreCase));

            var wrong = Path.Combine(root, "Windows");
            Directory.CreateDirectory(wrong);
            File.WriteAllText(Path.Combine(wrong, "explorer.exe"), "nope");
            AgentRemoval.DeleteOwnedFiles(data, wrong, deleteInstallDirectory: true);
            Assert.True(File.Exists(Path.Combine(wrong, "explorer.exe")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Running_from_the_install_folder_schedules_deletion_instead_of_unlinking_itself()
    {
        var dir = Path.Combine(Path.GetTempPath(), "RemotePCDiagnosticsAgent");
        var exe = Path.Combine(dir, "RemotePCDiagnostics.Agent.exe");
        Assert.True(AgentRemoval.ShouldScheduleInstallDirectoryDelete(exe, dir));
        Assert.False(AgentRemoval.ShouldScheduleInstallDirectoryDelete(Path.Combine(Path.GetTempPath(), "other.exe"), dir));
        Assert.False(AgentRemoval.IsAgentInstallDirectory(Path.Combine(Path.GetTempPath(), "RemotePCDiagnostics")));

        var args = AgentRemoval.DelayedDirectoryDeleteArguments(dir);
        Assert.Contains("rmdir /s /q", args, StringComparison.Ordinal);
        Assert.Contains("RemotePCDiagnosticsAgent", args, StringComparison.Ordinal);
        Assert.DoesNotContain("agent.json", args, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Startup_entries_match_the_agent_and_not_the_desktop_workflow_task()
    {
        Assert.True(AgentRemoval.ShouldRemoveRunValue("RemotePCDiagnosticsAgent", null));
        Assert.True(AgentRemoval.ShouldRemoveRunValue("Anything", "\"C:\\Program Files\\RemotePCDiagnosticsAgent\\RemotePCDiagnostics.Agent.exe\" run"));
        Assert.False(AgentRemoval.ShouldRemoveRunValue("OneDrive", "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe"));
        Assert.False(AgentRemoval.CommandLaunchesAgent("C:\\Program Files\\RemotePCDiagnostics\\RemotePCDiagnostics.Host.exe"));

        Assert.True(AgentRemoval.IsAgentStartupShortcut("Remote PC Diagnostics Agent.lnk"));
        Assert.False(AgentRemoval.IsAgentStartupShortcut("Remote PC Diagnostics.lnk"));

        const string list = """
            Folder: \
            TaskName:      \Remote PC Diagnostics - continue service workflow
            Task To Run:   "C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Host.exe" --workflow

            Folder: \
            TaskName:      \RemotePCDiagnostics Agent
            Task To Run:   "C:\Program Files\RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe" run

            Folder: \
            TaskName:      \Nightly backup
            Task To Run:   C:\Tools\backup.exe
            """;
        var names = AgentRemoval.TaskNamesToDelete(list);
        Assert.Equal(["\\RemotePCDiagnostics Agent"], names);
        Assert.False(AgentRemoval.ShouldDeleteScheduledTask(@"\Remote PC Diagnostics - continue service workflow", "RemotePCDiagnostics.Host.exe"));

        const string localized = """
            Dossier: \
            Nom de la tâche:      \Invite install
            Tâche à exécuter:    C:\Tools\RemotePCDiagnostics.Agent.exe run

            Dossier: \
            Nom de la tâche:      \Remote PC Diagnostics - continue service workflow
            Tâche à exécuter:    C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Host.exe
            """;
        Assert.Equal(["\\Invite install"], AgentRemoval.TaskNamesToDelete(localized));
    }

    [Theory]
    [InlineData("BudCribar.RemotePCDiagnostics_1.2.0.0_x64__abc", true)]
    [InlineData("12345BudCribar.RemotePCDiagnostics_1.2.0.0_x64__publisher", true)]
    [InlineData("RemotePCDiagnostics_1.0.0.0_x64__zz", true)]
    [InlineData("BudCribar.RemotePCDiagnostics.Agent_1.2.0.0_x64__abc", false)]
    [InlineData("Contoso.OtherApp_1.0.0.0_x64__abc", false)]
    [InlineData("", false)]
    public void Store_package_names_match_the_desktop_app_only(string package, bool match) =>
        Assert.Equal(match, AgentRemoval.IsDesktopMsixPackage(package));

    [Fact]
    public void Inno_uninstall_key_is_not_the_agent_msi()
    {
        Assert.True(AgentRemoval.IsDesktopUninstallRegistryKey("{8F6D4A2E-5C91-4B73-9E18-3A7C2D9F41B0}_is1"));
        Assert.False(AgentRemoval.IsDesktopUninstallRegistryKey("{D4B8E7A2-91F3-4C65-8E12-7F3A9C5D21E4}"));
        var candidates = AgentRemoval.SetupHostExeCandidates(@"C:\Program Files", @"C:\Program Files (x86)");
        var hostExe = Path.Combine("RemotePCDiagnostics", "RemotePCDiagnostics.Host.exe");
        Assert.Contains(candidates, p => p.EndsWith(hostExe, StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(candidates, p => p.Contains("ProgramData", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(candidates, p => p.Contains($"{Path.DirectorySeparatorChar}app{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Self_removal_waits_for_two_confirmed_absences_and_an_idle_desktop()
    {
        var absent = new DesktopInstallObservation(false, false, false, false, false, DesktopProcessRunning: false);
        var present = absent with { SetupExePresent = true };
        var failed = absent with { MsixCheckFailed = true };
        var running = absent with { DesktopProcessRunning = true };

        Assert.False(AgentSelfRemoval.ShouldRemove(hostEverSeen: false, absentStreak: 2, absent));

        var streak = 0;
        streak = AgentSelfRemoval.NextAbsentStreak(streak, absent);
        Assert.Equal(1, streak);
        Assert.False(AgentSelfRemoval.ShouldRemove(true, streak, absent));

        streak = AgentSelfRemoval.NextAbsentStreak(streak, failed);
        Assert.Equal(1, streak);
        Assert.False(AgentSelfRemoval.ShouldRemove(true, streak, failed));

        streak = AgentSelfRemoval.NextAbsentStreak(streak, absent);
        Assert.Equal(2, streak);
        Assert.False(AgentSelfRemoval.ShouldRemove(true, streak, running));
        Assert.True(AgentSelfRemoval.ShouldRemove(true, streak, absent));

        Assert.Equal(0, AgentSelfRemoval.NextAbsentStreak(streak, present));
    }
}
