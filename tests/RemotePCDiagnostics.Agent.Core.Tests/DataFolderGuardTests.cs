using RemotePCDiagnostics.Agent;

namespace RemotePCDiagnostics.Agent.Core.Tests;

[CollectionDefinition("AgentConfigPathEnv", DisableParallelization = true)]
public sealed class AgentConfigPathEnvCollection;

/// <summary>
/// Links and stray entries in the agent's data folder: never followed, removed instead. Uses symbolic links, which Windows only
/// lets an elevated or Developer Mode account make; elsewhere those tests are skipped.
/// </summary>
[Collection("AgentConfigPathEnv")]
public sealed class DataFolderGuardTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "rpcd-guard-" + Guid.NewGuid().ToString("N"));
    private readonly string _outside;

    public DataFolderGuardTests()
    {
        Directory.CreateDirectory(_root);
        _outside = _root + "-outside";
        Directory.CreateDirectory(_outside);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
        try { Directory.Delete(_outside, recursive: true); } catch { }
    }

    private static void LinkFile(string link, string target)
    {
        try { File.CreateSymbolicLink(link, target); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { Assert.Skip("This account can't create symbolic links."); }
    }

    private static void LinkDirectory(string link, string target)
    {
        try { Directory.CreateSymbolicLink(link, target); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { Assert.Skip("This account can't create symbolic links."); }
    }

    [Fact]
    public void Missing_path_is_not_a_link_and_a_plain_folder_is_not_either()
    {
        Assert.False(DataFolderGuard.IsLink(Path.Combine(_root, "nothing")));
        Assert.False(DataFolderGuard.IsLink(_root));
        Assert.False(DataFolderGuard.RemoveLink(_root));
        Assert.True(Directory.Exists(_root));
    }

    [Fact]
    public void Removing_a_folder_link_leaves_its_target_and_contents()
    {
        File.WriteAllText(Path.Combine(_outside, "keep.txt"), "keep");
        var link = Path.Combine(_root, "sessions");
        LinkDirectory(link, _outside);

        Assert.True(DataFolderGuard.RemoveLink(link));

        Assert.False(Directory.Exists(link));
        Assert.Equal("keep", File.ReadAllText(Path.Combine(_outside, "keep.txt")));
    }

    [Fact]
    public void Scrub_removes_links_and_folders_in_sessions_but_keeps_session_files_and_link_targets()
    {
        var sessions = Path.Combine(_root, "sessions");
        Directory.CreateDirectory(sessions);
        File.WriteAllText(Path.Combine(sessions, "active-session.json"), "{}");
        Directory.CreateDirectory(Path.Combine(sessions, "planted"));
        var target = Path.Combine(_outside, "system.dat");
        File.WriteAllText(target, "original");
        var logs = Path.Combine(_root, "logs");
        Directory.CreateDirectory(logs);
        LinkFile(Path.Combine(logs, "RemotePCDiagnostics.Agent.log"), target);
        LinkDirectory(Path.Combine(_root, "app"), _outside);
        LinkFile(Path.Combine(sessions, "rpcd-activity.json"), target);

        DataFolderGuard.Scrub(_root, sessions, null);

        Assert.True(File.Exists(Path.Combine(sessions, "active-session.json")));
        Assert.False(Directory.Exists(Path.Combine(sessions, "planted")));
        Assert.False(File.Exists(Path.Combine(sessions, "rpcd-activity.json")));
        Assert.False(File.Exists(Path.Combine(logs, "RemotePCDiagnostics.Agent.log")));
        Assert.True(Directory.Exists(logs));
        Assert.False(Directory.Exists(Path.Combine(_root, "app")));
        Assert.Equal("original", File.ReadAllText(target));
        Assert.True(Directory.Exists(_outside));
    }

    [Fact]
    public void Config_write_replaces_a_linked_temp_file_and_a_linked_config_without_touching_their_targets()
    {
        var configPath = Path.Combine(_root, "agent.json");
        var tempTarget = Path.Combine(_outside, "temp-target.txt");
        var configTarget = Path.Combine(_outside, "config-target.txt");
        File.WriteAllText(tempTarget, "temp original");
        File.WriteAllText(configTarget, "config original");
        LinkFile(configPath + ".tmp", tempTarget);
        LinkFile(configPath, configTarget);

        WithConfigPath(configPath, () => AgentPaths.WriteSecuredConfig(new AgentConfig { MachineId = "m-1", Key = "k" }));

        Assert.False(DataFolderGuard.IsLink(configPath));
        Assert.Contains("m-1", File.ReadAllText(configPath));
        Assert.False(File.Exists(configPath + ".tmp"));
        Assert.Equal("temp original", File.ReadAllText(tempTarget));
        Assert.Equal("config original", File.ReadAllText(configTarget));
    }

    [Fact]
    public void Config_write_refuses_when_the_folder_is_a_link()
    {
        var linkedFolder = Path.Combine(_root, "RemotePCDiagnostics");
        LinkDirectory(linkedFolder, _outside);
        var configPath = Path.Combine(linkedFolder, "agent.json");

        var ex = Assert.Throws<IOException>(() =>
            WithConfigPath(configPath, () => AgentPaths.WriteSecuredConfig(new AgentConfig { MachineId = "m-2" })));

        Assert.Contains("is a link", ex.Message);
        Assert.False(File.Exists(Path.Combine(_outside, "agent.json")));
    }

    [Fact]
    public void Config_write_still_works_in_a_plain_folder()
    {
        var configPath = Path.Combine(_root, "agent.json");
        File.WriteAllText(configPath + ".tmp", "left over from a crash");

        WithConfigPath(configPath, () => AgentPaths.WriteSecuredConfig(new AgentConfig { MachineId = "m-3" }));

        Assert.Contains("\"m-3\"", File.ReadAllText(configPath));
        Assert.False(File.Exists(configPath + ".tmp"));
    }

    [Fact]
    public void Sessions_folder_lets_users_add_files_but_not_folders_and_each_file_belongs_to_its_creator()
    {
        if (!OperatingSystem.IsWindows()) Assert.Skip("Windows permissions.");
        var rules = AgentPaths.SessionsDirectorySecurity()
            .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>()
            .ToList();
        var users = rules.Single(r => ((System.Security.Principal.SecurityIdentifier)r.IdentityReference).IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinUsersSid));
        Assert.Equal(System.Security.AccessControl.InheritanceFlags.None, users.InheritanceFlags);
        Assert.True(users.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.CreateFiles));
        Assert.False(users.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.CreateDirectories));
        Assert.False(users.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles));
        var owner = rules.Single(r => ((System.Security.Principal.SecurityIdentifier)r.IdentityReference).IsWellKnown(System.Security.Principal.WellKnownSidType.CreatorOwnerSid));
        Assert.Equal(System.Security.AccessControl.PropagationFlags.InheritOnly, owner.PropagationFlags);
        Assert.Equal(System.Security.AccessControl.InheritanceFlags.ObjectInherit, owner.InheritanceFlags);
        Assert.Equal(4, rules.Count);
    }

    private static void WithConfigPath(string path, Action action)
    {
        var old = Environment.GetEnvironmentVariable(AgentLayout.ConfigPathEnvVar);
        Environment.SetEnvironmentVariable(AgentLayout.ConfigPathEnvVar, path);
        try { action(); }
        finally { Environment.SetEnvironmentVariable(AgentLayout.ConfigPathEnvVar, old); }
    }
}
