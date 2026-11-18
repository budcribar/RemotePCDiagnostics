using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>Single repair steps and single updates: each is its own fix, run alone, and says whether a restart is needed.</summary>
public class GranularFixTests
{
    private const string AnalyzeOutput = """
        Deployment Image Servicing and Management tool
        Version: 10.0.26100.1

        Image Version: 10.0.26100.2314

        [==========================100.0%==========================]

        Component Store (WinSxS) information:

        Windows Explorer Reported Size of Component Store : 9.48 GB

        Actual Size of Component Store : 9.19 GB

            Shared with Windows : 5.84 GB
            Backups and Disabled Features : 3.34 GB
            Cache and Temporary Data : 0 bytes

        Date of Last Cleanup : 2026-10-01 10:11:12

        Number of Reclaimable Packages : 2
        Component Store Cleanup Recommended : Yes

        The operation completed successfully.
        """;

    private const string WimList = """
        Details for image : D:\sources\install.wim

        Index : 1
        Name : Windows 11 Home
        Description : Windows 11 Home
        Size : 18,000,000,000 bytes

        Index : 2
        Name : Windows 11 Pro
        Description : Windows 11 Pro
        Size : 19,000,000,000 bytes

        The operation completed successfully.
        """;

    private static string WimDetail(int index, string name, string edition) => $"""
        Details for image : D:\sources\install.wim

        Index : {index}
        Name : {name}
        Description : {name}
        Architecture : x64
        Version : 10.0.26100
        ServicePack Build : 1742
        Edition : {edition}
        Installation : Client

        The operation completed successfully.
        """;

    // ---- DISM analyze and cleanup ---------------------------------------------------------------------------------------

    [Fact]
    public void Analyze_reports_size_and_the_cleanup_recommendation()
    {
        var (status, summary, reboot) = WindowsRepair.ParseAnalyze(AnalyzeOutput, 0);
        Assert.Equal(DiagnosticStatus.Ok, status);
        Assert.False(reboot);
        Assert.Contains("9.19 GB", summary);
        Assert.Contains("reclaimable packages: 2", summary);
        Assert.Contains("cleanup recommended", summary);
        Assert.Contains("3.34 GB", summary);
    }

    [Fact]
    public void Analyze_without_a_size_or_with_an_error_exit_fails()
    {
        Assert.Equal(DiagnosticStatus.Error, WindowsRepair.ParseAnalyze("Error: 740", 740).Status);
        Assert.Equal(DiagnosticStatus.Error, WindowsRepair.ParseAnalyze(AnalyzeOutput, null).Status);
        Assert.Contains("0x800F081F", WindowsRepair.ParseAnalyze("", unchecked((int)0x800f081f)).Summary);
    }

    [Fact]
    public void Cleanup_success_tells_the_person_to_restart_before_repairing()
    {
        var (status, summary, reboot) = WindowsRepair.ParseCleanup("[===100.0%===]\nThe operation completed successfully.", 0);
        Assert.Equal(DiagnosticStatus.Ok, status);
        Assert.False(reboot);
        Assert.Contains("Restart", summary);
        Assert.True(WindowsRepair.ParseCleanup("The operation completed successfully.", WindowsRepair.RebootRequiredExitCode).Reboot);
    }

    [Fact]
    public void Cleanup_blocked_by_a_pending_restart_says_so()
    {
        var (status, summary, reboot) = WindowsRepair.ParseCleanup("Error: 0x800f0806\nThe operation could not be completed due to pending operations.", unchecked((int)0x800f0806));
        Assert.Equal(DiagnosticStatus.Error, status);
        Assert.True(reboot);
        Assert.Contains("Restart", summary);
    }

    [Fact]
    public void Cleanup_failure_shows_the_exit_code_in_hex()
    {
        var (status, summary, _) = WindowsRepair.ParseCleanup("The operation failed.", unchecked((int)0x80070005));
        Assert.Equal(DiagnosticStatus.Error, status);
        Assert.Contains("0x80070005", summary);
    }

    // ---- Repair from a Windows image -------------------------------------------------------------------------------------

    [Theory]
    [InlineData(@"D:\sources\install.wim", true)]
    [InlineData(@"E:\sources\install.esd", true)]
    [InlineData(@"\\server\share\install.wim", true)]
    [InlineData(@"D:\sources\install.iso", false)]
    [InlineData(@"sources\install.wim", false)]
    [InlineData("D:\\sources\\\"x\".wim", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Image_path_must_be_a_rooted_wim_or_esd(string? path, bool ok) => Assert.Equal(ok, WindowsRepair.IsImagePath(path));

    [Fact]
    public void Image_source_argument_names_the_format_and_the_index()
    {
        Assert.Equal(@"/Source:WIM:D:\sources\install.wim:2", WindowsRepair.ImageSourceArg(@"D:\sources\install.wim", 2));
        Assert.Equal(@"/Source:ESD:D:\sources\install.esd:6", WindowsRepair.ImageSourceArg(@"D:\sources\install.esd", 6));
    }

    [Fact]
    public void Wim_listing_and_details_parse()
    {
        Assert.Equal([1, 2], WindowsRepair.ParseWimIndexes(WimList));
        var image = WindowsRepair.ParseWimImage(2, WimDetail(2, "Windows 11 Pro", "Professional"));
        Assert.Equal(new WimImageInfo(2, "Windows 11 Pro", "Professional", "10.0.26100.1742"), image);
        Assert.Null(WindowsRepair.ParseWimImage(1, "Error: 87"));
        Assert.Equal("Professional", WindowsRepair.ParseCurrentEdition("Image Version: 10.0.26100.2314\n\nCurrent edition is:\n\nCurrent Edition : Professional\n"));
        Assert.Null(WindowsRepair.ParseCurrentEdition("Error: 740"));
    }

    private static ScriptedLauncher ImageLauncher(string currentEdition, string repairOutput = "The restore operation completed successfully.\nThe operation completed successfully.", int repairExit = 0) =>
        new((file, args) =>
        {
            if (args.Contains("/Get-CurrentEdition")) return ScriptedLauncher.Ok($"Current Edition : {currentEdition}");
            if (args.Contains("/Get-WimInfo"))
                return args.FirstOrDefault(a => a.StartsWith("/Index:", StringComparison.Ordinal)) switch
                {
                    "/Index:1" => ScriptedLauncher.Ok(WimDetail(1, "Windows 11 Home", "Core")),
                    "/Index:2" => ScriptedLauncher.Ok(WimDetail(2, "Windows 11 Pro", "Professional")),
                    _ => ScriptedLauncher.Ok(WimList),
                };
            return new(repairExit, repairOutput, "");
        });

    [Fact]
    public async Task Repair_from_an_image_uses_the_index_of_this_PCs_edition()
    {
        var launcher = ImageLauncher("Professional");
        var result = await WindowsRepair.RunStepAsync(new SystemCommandRunner(launcher), RepairStep.RestoreHealthFromImage, @"D:\sources\install.wim", null, default);
        Assert.True(result.Success, result.Summary);
        Assert.Equal(WindowsRepair.ImageId, result.Id);
        var repair = launcher.Calls[^1].Args;
        Assert.Contains(@"/Source:WIM:D:\sources\install.wim:2", repair);
        Assert.Contains("/LimitAccess", repair);
        Assert.Contains("/RestoreHealth", repair);
        Assert.Contains(result.Details, d => d.Label == "Repair source" && d.Value.Contains("Windows 11 Pro") && d.Value.Contains("10.0.26100.1742"));
    }

    [Fact]
    public async Task Repair_from_an_image_of_another_edition_is_not_started()
    {
        var launcher = ImageLauncher("Enterprise");
        var result = await WindowsRepair.RunStepAsync(new SystemCommandRunner(launcher), RepairStep.RestoreHealthFromImage, @"D:\sources\install.wim", null, default);
        Assert.False(result.Success);
        Assert.Contains("Enterprise", result.Summary);
        Assert.Contains("Core", result.Summary);
        Assert.DoesNotContain(launcher.Calls, c => c.Args.Contains("/RestoreHealth"));
    }

    [Fact]
    public async Task Repair_from_something_that_is_not_an_image_runs_nothing()
    {
        var launcher = ImageLauncher("Professional");
        var result = await WindowsRepair.RunStepAsync(new SystemCommandRunner(launcher), RepairStep.RestoreHealthFromImage, @"D:\setup.exe", null, default);
        Assert.False(result.Success);
        Assert.Empty(launcher.Calls);
    }

    // ---- The steps as fixes ----------------------------------------------------------------------------------------------

    private static RemediationService Service(ScriptedLauncher launcher) => new(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local));

    [Fact]
    public async Task Each_repair_kind_runs_only_its_own_command()
    {
        var launcher = new ScriptedLauncher((_, args) => ScriptedLauncher.Ok(args.Contains("/AnalyzeComponentStore") ? AnalyzeOutput : "The operation completed successfully."));
        var svc = Service(launcher);

        var analyze = await svc.ExecuteAsync(new(RemediationKind.AnalyzeComponentStore, "Analyze store"));
        Assert.True(analyze.Success, analyze.Message);
        Assert.Contains("9.19 GB", analyze.Message);
        Assert.Equal(WindowsRepair.AnalyzeArgs, Assert.Single(launcher.Calls).Args);

        launcher.Calls.Clear();
        var cleanup = await svc.ExecuteAsync(new(RemediationKind.CleanUpComponentStore, "Clean up store"));
        Assert.True(cleanup.Success, cleanup.Message);
        Assert.False(cleanup.RestartNeeded);
        Assert.Equal(WindowsRepair.CleanupArgs, Assert.Single(launcher.Calls).Args);
        Assert.Equal(WindowsRepair.CleanupId, svc.LastRepair!.Id);
    }

    [Fact]
    public async Task A_repair_that_needs_a_restart_says_so_in_its_result()
    {
        var svc = Service(new ScriptedLauncher((_, _) => new(WindowsRepair.RebootRequiredExitCode, "The restore operation completed successfully.", "")));
        var result = await svc.ExecuteAsync(new(RemediationKind.RepairComponentStore, "Repair from Windows Update"));
        Assert.True(result.Success);
        Assert.True(result.RestartNeeded);
    }

    [Fact]
    public void Plans_say_what_each_step_runs_and_refuse_a_bad_target()
    {
        var svc = Service(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")));
        Assert.Contains("Changes nothing", svc.Plan(new(RemediationKind.AnalyzeComponentStore, "Analyze store")).WhatWillHappen);
        Assert.Contains("/StartComponentCleanup", svc.Plan(new(RemediationKind.CleanUpComponentStore, "Clean up store")).WhatWillHappen);
        Assert.True(svc.Plan(new(RemediationKind.RepairComponentStoreFromImage, "Repair", @"D:\sources\install.wim", @"D:\sources\install.wim")).Allowed);
        Assert.False(svc.Plan(new(RemediationKind.RepairComponentStoreFromImage, "Repair", @"D:\x.txt")).Allowed);
        Assert.True(svc.Plan(new(RemediationKind.InstallUpdate, "Install", "0f9a8a4d-6f0a-4d5e-9f50-3d1b2c3d4e5f", "2026-11 Cumulative Update")).Allowed);
        Assert.False(svc.Plan(new(RemediationKind.InstallUpdate, "Install", "'; Remove-Item C:\\ -Recurse #")).Allowed);
    }

    [Fact]
    public void Dism_card_offers_analyze_and_cleanup_always_and_the_repairs_only_for_corruption()
    {
        Assert.Null(DismScanHealthModule.Actions(DiagnosticStatus.Error, []));
        Assert.Equal([RemediationKind.AnalyzeComponentStore, RemediationKind.CleanUpComponentStore],
            DismScanHealthModule.Actions(DiagnosticStatus.Ok, [@"D:\sources\install.wim"])!.Select(a => a.Kind));
        var corrupt = DismScanHealthModule.Actions(DiagnosticStatus.Warning, [@"D:\sources\install.wim", @"D:\not-an-image.txt"])!;
        Assert.Equal([RemediationKind.AnalyzeComponentStore, RemediationKind.CleanUpComponentStore, RemediationKind.RepairComponentStore,
            RemediationKind.RepairComponentStoreFromImage, RemediationKind.ScheduleCleanRestart], corrupt.Select(a => a.Kind));
        Assert.Equal(@"D:\sources\install.wim", corrupt.Single(a => a.Kind == RemediationKind.RepairComponentStoreFromImage).Target);
    }

    // ---- One update at a time ---------------------------------------------------------------------------------------------

    private const string Id1 = "0f9a8a4d-6f0a-4d5e-9f50-3d1b2c3d4e5f", Id2 = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f";

    private static string PendingJson(bool reboot = false) => $$"""
        {"Ok":true,"RebootRequired":{{(reboot ? "true" : "false")}},"Error":"","Updates":[
          {"Id":"{{Id1}}","Title":"2026-11 Cumulative Update for Windows 11 (KB5068861)","Kb":"KB5068861","Driver":false,"Category":"Security Updates","SizeBytes":"734003200","Downloaded":false,"MayNeedRestart":true,"Severity":"Critical","DriverModel":""},
          {"Id":"{{Id2}}","Title":"Realtek - Net - 10.68.815.2023","Kb":"","Driver":true,"Category":"Drivers","SizeBytes":"1048576","Downloaded":true,"MayNeedRestart":false,"Severity":"","DriverModel":"Realtek PCIe GbE Family Controller"},
          {"Id":"not-a-guid","Title":"Broken","Kb":"","Driver":false,"Category":"","SizeBytes":"0","Downloaded":false,"MayNeedRestart":false,"Severity":"","DriverModel":""}]}
        """;

    [Fact]
    public void Pending_updates_parse_and_drop_entries_without_an_update_id()
    {
        var list = PendingUpdates.Parse(PendingJson())!;
        Assert.Equal([Id1, Id2], list.Updates.Select(u => u.Id));
        Assert.False(list.RebootRequired);
        Assert.Equal(734003200, list.Updates[0].SizeBytes);
        Assert.True(list.Updates[1].Driver);
        Assert.Null(PendingUpdates.Parse("""{"Ok":false,"Error":"service disabled","Updates":[]}"""));
        Assert.Null(PendingUpdates.Parse("not json"));
        Assert.Null(PendingUpdates.Parse(""));
    }

    [Fact]
    public void Pending_updates_parse_a_single_update_written_as_an_object()
    {
        var one = PendingUpdates.Parse("{\"Ok\":true,\"RebootRequired\":true,\"Updates\":{\"Id\":\"" + Id1 + "\",\"Title\":\"One\",\"Driver\":false}}")!;
        Assert.Equal(Id1, Assert.Single(one.Updates).Id);
        Assert.True(one.RebootRequired);
    }

    [Fact]
    public void Each_pending_update_gets_its_own_install_button_on_the_right_card()
    {
        var list = PendingUpdates.Parse(PendingJson())!;
        var software = PendingUpdates.Card(list, drivers: false);
        var row = Assert.Single(software.Rows);
        Assert.Equal(Id1, row.Key);
        var install = Assert.Single(row.Actions!);
        Assert.Equal((RemediationKind.InstallUpdate, Id1), (install.Kind, install.Target));
        Assert.Contains("KB5068861", row.Values[1]);
        Assert.Equal("May be needed", row.Values[3]);
        Assert.Null(software.Actions); // one update: its own button is enough

        var drivers = PendingUpdates.Card(list, drivers: true);
        Assert.Equal(Id2, Assert.Single(drivers.Rows).Key);
        Assert.Equal("Realtek PCIe GbE Family Controller", drivers.Rows[0].Values[1]);
        Assert.NotEqual(software.Id, drivers.Id);
    }

    [Fact]
    public void Pending_card_offers_the_restart_when_Windows_waits_for_one_and_never_fails_the_check()
    {
        var waiting = PendingUpdates.Card(PendingUpdates.Parse(PendingJson(reboot: true)), drivers: false);
        Assert.Contains(waiting.Actions!, a => a.Kind == RemediationKind.ScheduleCleanRestart);
        var unreadable = PendingUpdates.Card(null, drivers: false);
        Assert.Equal(AreaLevel.Neutral, unreadable.Level);
        Assert.Null(unreadable.ErrorText);
        Assert.Equal(AreaLevel.Ok, PendingUpdates.Card(new([], false), drivers: true).Level);
    }

    [Fact]
    public void Pending_cards_join_their_checks_without_changing_the_result()
    {
        var programs = ProgramsModule.Build(new Dictionary<string, string> { ["name"] = "Windows 11 Pro" }, true, [new("KB1", "Update", new DateOnly(2026, 11, 1))], [], new DateOnly(2026, 11, 17));
        var with = ProgramsModule.WithPendingUpdates(programs, PendingUpdates.Parse(PendingJson()));
        Assert.Equal(programs.Status, with.Status);
        Assert.Equal(PendingUpdates.SoftwareCardId, with.Cards[with.Cards.ToList().FindIndex(c => c.Id == "updates") + 1].Id);

        var devices = DeviceDriversModule.Build([], []);
        var withDrivers = DeviceDriversModule.WithPendingUpdates(devices, null);
        Assert.Equal(devices.Status, withDrivers.Status);
        Assert.Equal(PendingUpdates.DriverCardId, withDrivers.Cards[^1].Id);
    }

    [Fact]
    public void Install_script_takes_only_a_Windows_Update_ID()
    {
        var script = RemediationService.BuildInstallUpdateScript(Id1.ToUpperInvariant())!;
        Assert.Contains($"UpdateID=''{Id1}''", script);
        Assert.DoesNotContain("__UPDATE_ID__", script);
        Assert.Null(RemediationService.BuildInstallUpdateScript("x' or 'a'='a"));
        Assert.Null(RemediationService.BuildInstallUpdateScript(null));
    }

    [Theory]
    [InlineData("""{"Found":true,"Installed":true,"ResultCode":2,"HResult":0,"RebootRequired":true,"Title":"KB5068861","Error":""}""", true, true, "Installed KB5068861")]
    [InlineData("""{"Found":true,"Installed":true,"ResultCode":2,"HResult":0,"RebootRequired":false,"Title":"KB5068861","Error":""}""", true, false, "Installed KB5068861")]
    [InlineData("""{"Found":false,"Installed":false,"ResultCode":-1,"HResult":0,"RebootRequired":false,"Title":"","Error":""}""", false, false, "no longer offers")]
    [InlineData("""{"Found":true,"Installed":false,"ResultCode":4,"HResult":-2145124329,"RebootRequired":false,"Title":"KB5068861","Error":""}""", false, false, "0x80240017")]
    [InlineData("""{"Found":true,"Installed":false,"DownloadResult":4,"ResultCode":-1,"HResult":0,"RebootRequired":false,"Title":"KB5068861","Error":""}""", false, false, "download")]
    [InlineData("""{"Found":false,"Installed":false,"ResultCode":-1,"Error":"Access is denied."}""", false, false, "Access is denied")]
    [InlineData("", false, false, "Couldn't ask")]
    [InlineData("oops", false, false, "Couldn't read")]
    public void Install_result_is_read_from_the_script(string json, bool success, bool restart, string says)
    {
        var result = RemediationService.ParseInstallUpdate(json, "the update");
        Assert.Equal(success, result.Success);
        Assert.Equal(restart, result.RestartNeeded);
        Assert.Contains(says, result.Message);
        Assert.Equal(success ? 1 : 0, result.UpdatesInstalled);
    }

    [Fact]
    public async Task Installing_one_update_runs_the_script_for_that_update_only()
    {
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("""{"Found":true,"Installed":true,"ResultCode":2,"HResult":0,"RebootRequired":true,"Title":"Realtek - Net","Error":""}"""));
        var result = await Service(launcher).ExecuteAsync(new(RemediationKind.InstallUpdate, "Install", Id2, "Realtek - Net"));
        Assert.True(result.Success);
        Assert.True(result.RestartNeeded);
        Assert.Contains(Id2, Assert.Single(launcher.Calls).Args[^1]);

        var refused = await Service(launcher).ExecuteAsync(new(RemediationKind.InstallUpdate, "Install", "nope"));
        Assert.False(refused.Success);
        Assert.Single(launcher.Calls);
    }

    [Fact]
    public async Task Installing_everything_reports_a_needed_restart()
    {
        var svc = Service(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("""{"Count":1,"Installed":1,"InstallResult":2,"RebootRequired":true,"Titles":["KB5068861"]}""")));
        var result = await svc.ExecuteAsync(new(RemediationKind.CheckAndInstallWindowsUpdates, "Check & install updates"));
        Assert.True(result.Success);
        Assert.True(result.RestartNeeded);
        Assert.Contains("Restart", result.Message);
    }

    // ---- A fix keeps running when its page is left -------------------------------------------------------------------------

    [Fact]
    public async Task A_tracked_fix_is_visible_while_it_runs_and_leaves_a_numbered_result()
    {
        var gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var svc = Service(new ScriptedLauncher((_, _) => { started.TrySetResult(true); gate.Task.Wait(TimeSpan.FromSeconds(30)); return ScriptedLauncher.Ok("The operation completed successfully."); }));
        var changes = 0;
        svc.RunChanged += () => Interlocked.Increment(ref changes);

        var run = svc.RunTrackedAsync(new(RemediationKind.CleanUpComponentStore, "Clean up store"), "DismScanHealth");
        await started.Task.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        Assert.Equal(RemediationKind.CleanUpComponentStore, svc.Running!.Action.Kind);
        Assert.Equal("DismScanHealth", svc.Running.Origin);

        // Only one fix at a time: a second one is refused, not queued.
        var second = await svc.RunTrackedAsync(new(RemediationKind.CleanTempFiles, "Clean"), "DriveHealth");
        Assert.False(second.Success);
        Assert.Contains("still running", second.Message);
        Assert.Null(svc.LastRun);

        gate.SetResult(true);
        Assert.True((await run).Success);
        Assert.Null(svc.Running);
        Assert.Equal((1, "DismScanHealth", true), (svc.LastRun!.Seq, svc.LastRun.Origin, svc.LastRun.Success));
        Assert.True(changes >= 2);

        await svc.RunTrackedAsync(new(RemediationKind.AnalyzeComponentStore, "Analyze store"), "DismScanHealth");
        Assert.Equal(2, svc.LastRun!.Seq);
        Assert.False(svc.LastRun.Success); // "operation completed" without a size is not an analysis
    }

    [Fact]
    public void Fix_state_export_names_the_running_fix_and_the_last_result()
    {
        var action = new AreaAction(RemediationKind.RepairComponentStore, "Repair from Windows Update");
        var state = AgentExports.BuildFixState(new(action, "Repair the Windows component store", "DismScanHealth", DateTimeOffset.UnixEpoch, "Repair 40% complete"),
            new(3, action, "DismScanHealth", true, "Windows component store repaired; a restart finishes the repair.", true, DateTimeOffset.UnixEpoch));
        Assert.Equal(("RepairComponentStore", "DismScanHealth", "Repair 40% complete"), (state.Running!.Kind, state.Running.Origin, state.Running.Progress));
        Assert.Equal((3, "succeeded", true, false), (state.Last!.Seq, state.Last.Outcome, state.Last.RestartNeeded, state.Last.ReadOnly));
        Assert.Equal("{\"schema\":1}", AgentExports.FixState(null, null)); // nothing running, nothing last
    }

    // ---- What agents and the workflow see --------------------------------------------------------------------------------

    [Fact]
    public void Exported_fixes_carry_their_traits()
    {
        var report = new AreaReport([new("integrity", "Windows component store (DISM)", AreaLevel.Warning, "x", "", ["Detail", "Value"], [],
            Actions: DismScanHealthModule.Actions(DiagnosticStatus.Warning, []))], "x", DiagnosticStatus.Warning);
        var actions = AreaReportExport.Build(report).Cards[0].Actions!.ToDictionary(a => a.Kind);
        Assert.True(actions["AnalyzeComponentStore"].ReadOnly);
        Assert.Null(actions["CleanUpComponentStore"].ReadOnly);
        Assert.Equal(("medium", "none", true, true), (actions["CleanUpComponentStore"].Risk, actions["CleanUpComponentStore"].Undo, actions["CleanUpComponentStore"].Slow, actions["CleanUpComponentStore"].MayNeedRestart));
        Assert.True(actions["ScheduleCleanRestart"].RestartsPc);
        Assert.Null(actions["RepairComponentStore"].RestartsPc);
        Assert.Equal("nothing", actions["AnalyzeComponentStore"].Undo);
    }

    [Fact]
    public void Every_fix_kind_has_a_key_and_new_kinds_keep_old_numbers()
    {
        Assert.All(Enum.GetValues<RemediationKind>(), k => Assert.True(FixKeys.Remediation.ContainsKey(k), k.ToString()));
        Assert.Equal(18, (int)RemediationKind.ApplySecuritySetting);
        Assert.True((int)RemediationKind.AnalyzeComponentStore > (int)RemediationKind.ApplySecuritySetting);
    }

    private static DiagnosticResult Scan(string module, AreaReport report) => new(module, report.Status, report.Summary, DateTimeOffset.Now, report);

    [Fact]
    public void Workflow_lists_the_card_steps_once_and_leaves_the_opt_in_ones_unticked()
    {
        var dism = new AreaReport([new("integrity", "Windows component store (DISM)", AreaLevel.Warning, "corrupt", "", ["Detail", "Value"], [],
            Actions: DismScanHealthModule.Actions(DiagnosticStatus.Warning, [@"D:\sources\install.wim"]))], "DISM found repairable corruption in the Windows component store.", DiagnosticStatus.Warning);
        var programs = ProgramsModule.WithPendingUpdates(
            ProgramsModule.Build(new Dictionary<string, string> { ["name"] = "Windows 11 Pro" }, true, [new("KB1", "Update", new DateOnly(2026, 11, 1))], [], new DateOnly(2026, 11, 17)),
            PendingUpdates.Parse(PendingJson()));
        var fixes = FixCatalog.Build([Scan(DismScanHealthModule.ModuleName, dism), Scan(ProgramsModule.ModuleName, programs)], Array.Empty<MemorySuggestion>(),
            Service(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))));

        Assert.DoesNotContain(fixes, f => f.Remediation?.Kind is RemediationKind.AnalyzeComponentStore or RemediationKind.ScheduleCleanRestart or RemediationKind.InstallUpdate);
        Assert.Single(fixes, f => f.Remediation?.Kind == RemediationKind.RepairComponentStore);
        Assert.Single(fixes, f => f.Remediation?.Kind == RemediationKind.RepairSystemFiles);
        var cleanup = Assert.Single(fixes, f => f.Remediation?.Kind == RemediationKind.CleanUpComponentStore);
        var image = Assert.Single(fixes, f => f.Remediation?.Kind == RemediationKind.RepairComponentStoreFromImage);
        Assert.All(new[] { cleanup, image }, f => { Assert.False(f.DefaultOn); Assert.True(f.NeedsAdmin); Assert.True(f.Slow); Assert.Equal(SuggestionRisk.Medium, f.Risk); Assert.Equal(FixCatalog.RepairArea, f.Area); Assert.Equal(UndoSupport.None, f.Undo); });
        var order = fixes.Where(f => f.Area == FixCatalog.RepairArea).OrderBy(f => f.Order).Select(f => f.Remediation!.Kind).ToList();
        Assert.Equal(RemediationKind.CleanUpComponentStore, order[0]);
        Assert.Equal(RemediationKind.RepairSystemFiles, order[^1]);
        Assert.Single(fixes, f => f.Remediation?.Kind == RemediationKind.CheckAndInstallWindowsUpdates);
    }
}
