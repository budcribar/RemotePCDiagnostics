using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>Where the loader looks and what it trusts.</summary>
public sealed record ModuleLoaderOptions
{
    /// <summary>%ProgramFiles%\RemotePCDiagnostics\modules: standard users can't write there. Nothing loads from anywhere else.</summary>
    public string ModulesFolder { get; init; } = DefaultModulesFolder();
    /// <summary>%ProgramData%\RemotePCDiagnostics\catalog: each plugin's module.json and strings, kept after the DLL is removed.</summary>
    public string CatalogFolder { get; init; } = DefaultCatalogFolder();
    /// <summary>%ProgramFiles%\RemotePCDiagnostics\checks: custom JSON checks. Null uses the default folder.</summary>
    public string? ChecksFolder { get; init; }
    /// <summary>The project's module signing public key (PEM, ECDSA P-256). Empty: no module counts as signed.</summary>
    public string? PublicKeyPem { get; init; } = ModuleSigningKey.PublicKeyPem;
    public Version HostVersion { get; init; } = new(0, 0);
    /// <summary>The person at the PC turned unsigned (user-mode) modules on. Never set from a remote session.</summary>
    public bool AllowUnsigned { get; init; }
    /// <summary>builtin-modules\ next to the app's exe: the modules that ship with the app, one DLL each. They are part of the app's own
    /// install (the release zip the agent verified, or the build output), so they load into the app process like the app's other DLLs.
    /// Only ids the app already knows (<see cref="BuiltInModules.Descriptors"/>) load from here. Null: none.</summary>
    public string? BundledFolder { get; init; } = DefaultBundledFolder();
    /// <summary>Where each module that ships with the app runs (the About page's process-mode switch). Default: as each module.json says.</summary>
    public ModuleProcessModeSetting ProcessModes { get; init; } = new();

    public static string DefaultModulesFolder() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RemotePCDiagnostics", "modules");
    public static string DefaultBundledFolder() => Path.Combine(AppContext.BaseDirectory, BundledFolderName);
    public const string BundledFolderName = "builtin-modules";
    public static string DefaultCatalogFolder() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RemotePCDiagnostics", "catalog");
}

/// <summary>The release key that signs modules allowed to run in the app process. Set by tools/New-ModuleSigningKey.ps1.</summary>
public static class ModuleSigningKey
{
    public const string PublicKeyPem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOveRgnw3/QQKbqvUxAcz300rcJxo\n9SGZ2uqTInJVMOr3+so0D6lH6LsT13JkcU+0yks6OFL8Rxwegi18Uy4vjQ==\n-----END PUBLIC KEY-----";
}

/// <summary>Detached module signature: &lt;Module&gt;.dll.sig holds base64 ECDSA P-256 / SHA-256 (IEEE P1363) over the DLL's exact bytes,
/// the same scheme as the agent's manifest.sig.</summary>
public static class ModuleSignature
{
    public const string Extension = ".sig";

    public static bool Verify(byte[] dll, string? signatureText, string? publicKeyPem) =>
        publicKeyPem is { Length: > 0 } && ManifestSignature.Verify(dll, signatureText, publicKeyPem);

    /// <summary>Signs <paramref name="dll"/> (for the packaging script and tests).</summary>
    public static string Sign(byte[] dll, ECDsa key) =>
        Convert.ToBase64String(key.SignData(dll, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
}

/// <summary>
/// Loads module DLLs once at startup, before the container is built: discover, verify, read the manifest (no code runs), catalog, load
/// into its own <see cref="AssemblyLoadContext"/>, register through <see cref="PluginRegistrar"/>. One bad plugin never stops startup.
/// </summary>
/// <param name="userMode">Makes the in-app stand-in for an unsigned module (a <see cref="UserModeModuleProxy"/>); null leaves user-mode
/// modules listed in <see cref="UserMode"/> only.</param>
public sealed class ModuleLoader(ModuleLoaderOptions options, PluginRegistrar registrar, ILogger? log = null,
    Func<UserModeModule, IDiagnosticModule>? userMode = null)
{
    /// <summary>Modules found unsigned that may run in the user-mode module host (see <see cref="UserModeModule"/>).</summary>
    public IReadOnlyList<UserModeModule> UserMode => _userMode;
    private readonly List<UserModeModule> _userMode = [];

    public void LoadAll(IServiceCollection services, ModuleCatalog? builtIns = null)
    {
        var taken = new Dictionary<Guid, string>();
        var slugs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in (builtIns ?? new ModuleCatalog()).All) { taken[d.Id] = d.Slug; slugs[d.Slug] = d.Slug; }

        foreach (var path in Discover())
        {
            var pluginId = Path.GetFileNameWithoutExtension(path);
            var record = new PluginRecord(pluginId, ModuleSource.Plugin, PluginState.Loaded) { Path = path };
            try
            {
                var dll = File.ReadAllBytes(path); // verify, read and load these exact bytes (no swap between check and load)
                var sigPath = path + ModuleSignature.Extension;
                var signed = ModuleSignature.Verify(dll, File.Exists(sigPath) ? File.ReadAllText(sigPath) : null, options.PublicKeyPem);
                record = record with { Signature = signed ? "Signed (project key)" : File.Exists(sigPath) ? "Signature does not match" : "Unsigned" };

                var (manifest, strings) = ModuleManifest.ReadFromAssembly(dll);
                pluginId = manifest.Slug;
                var descriptor = manifest.ToDescriptor(pluginId);
                record = record with { PluginId = pluginId, Version = manifest.Version, ModuleId = manifest.Id, DisplayName = descriptor.DisplayName };

                if (manifest.Problem(options.HostVersion) is { } problem) { registrar.RecordDisabled(record with { Reason = problem }, descriptor); continue; }
                if (taken.TryGetValue(manifest.Id, out var owner)) { registrar.RecordDisabled(record with { Reason = $"id {manifest.Id} is already used by {owner}" }); continue; }
                if (slugs.ContainsKey(manifest.Slug)) { registrar.RecordDisabled(record with { Reason = $"slug {manifest.Slug} is already used" }); continue; }
                taken[manifest.Id] = manifest.Slug;
                slugs[manifest.Slug] = manifest.Slug;
                SaveToCatalog(manifest, strings);

                if (!signed)
                {
                    // Unsigned code never loads into the (elevated) app process.
                    var why = manifest.NeedsAdmin ? "needs administrator, so it must be signed with the project key"
                        : manifest.ChangesSystem ? "changes the PC, so it must be signed with the project key"
                        : !options.AllowUnsigned ? "unsigned modules are turned off (turn them on at this PC to run them in user mode)"
                        : null;
                    if (why is not null) { registrar.RecordDisabled(record with { Reason = why }, descriptor); continue; }
                    var um = new UserModeModule(path, manifest, descriptor);
                    _userMode.Add(um);
                    var userRecord = record with { Reason = "runs in user mode, out of process", UserMode = true, Hosting = ModuleHosting.Unsigned(manifest) };
                    if (userMode is null) { registrar.RecordDisabled(userRecord, descriptor); continue; }
                    if (registrar.Register(services, new SingleModulePlugin(userMode(um)), pluginId, ModuleSource.Plugin, manifest.Id, userRecord, descriptor))
                        Log($"{pluginId} {manifest.Version} ({manifest.Id}) runs in user mode from {path}");
                    continue;
                }

                var plugin = Instantiate(pluginId, dll, manifest);
                if (registrar.Register(services, plugin, pluginId, ModuleSource.Plugin, manifest.Id, record with { Hosting = ModuleHosting.Signed(manifest) }, descriptor))
                    Log($"loaded {pluginId} {manifest.Version} ({manifest.Id}) from {path}");
            }
            catch (Exception ex)
            {
                registrar.RecordDisabled(record with { Reason = $"{ex.GetType().Name}: {ex.Message}" });
            }
        }
        LoadRetired(taken);
    }

    /// <summary>
    /// Loads the modules that ship with the app (<see cref="ModuleLoaderOptions.BundledFolder"/>), each into its own load context, with no
    /// signature check: they come with the app's other DLLs. Each must carry the id and slug of a module the app knows
    /// (<paramref name="known"/>, by default <see cref="BuiltInModules.Descriptors"/>), so the descriptor (group, order, run order) stays the
    /// app's own and History keeps naming the module even when its DLL is missing. Run before <see cref="LoadAll"/>.
    /// </summary>
    public void LoadBundled(IServiceCollection services, IEnumerable<ModuleDescriptor>? known = null)
    {
        var folder = options.BundledFolder;
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
        if (SameFolder(folder, options.ModulesFolder)) { LogWarn($"{folder} is also the plugin folder; its modules load as plugins only"); return; }
        var byId = (known ?? BuiltInModules.Descriptors).ToDictionary(d => d.Id);
        var loaded = new HashSet<Guid>();
        foreach (var path in Directory.EnumerateFiles(folder, "*.dll", SearchOption.TopDirectoryOnly).Order(StringComparer.OrdinalIgnoreCase).ToList())
        {
            var pluginId = Path.GetFileNameWithoutExtension(path);
            var record = new PluginRecord(pluginId, ModuleSource.BuiltIn, PluginState.Loaded) { Path = path, Signature = BundledSignature, Version = AppBuildInfo.Release };
            try
            {
                var dll = File.ReadAllBytes(path);
                var (manifest, _) = ModuleManifest.ReadFromAssembly(dll);
                record = record with { ModuleId = manifest.Id, DisplayName = manifest.DisplayName };
                var why = !byId.TryGetValue(manifest.Id, out var d) ? $"id {manifest.Id} is not a module that ships with this app"
                    : !string.Equals(d.Slug, manifest.Slug, StringComparison.Ordinal) ? $"slug {manifest.Slug} should be {d.Slug} for id {manifest.Id}"
                    : !loaded.Add(manifest.Id) ? $"module {manifest.Slug} was already loaded from another DLL"
                    : manifest.Problem(options.HostVersion, vendorSlug: false);
                if (why is not null) { registrar.RecordDisabled(record with { Reason = why }); continue; }
                var hosting = ModuleHosting.For(manifest, options.ProcessModes.For(manifest.Slug));
                if (hosting.OutOfProcess && userMode is not null)
                {
                    // Its code never loads into the app: the app holds a stand-in that asks the module host to run it (restricted token, or
                    // the app's own token for a module that needs administrator).
                    var um = new UserModeModule(path, manifest, d!) { Bundled = true, Elevated = hosting.Elevated };
                    var outOfProcess = record with { Reason = hosting.Elevated ? "runs out of process, as administrator" : "runs out of process, in user mode", UserMode = true, Hosting = hosting };
                    if (registrar.Register(services, new SingleModulePlugin(userMode(um)), pluginId, ModuleSource.BuiltIn, manifest.Id, outOfProcess))
                    {
                        Log($"built-in {manifest.Slug} ({manifest.Id}) runs out of process{(hosting.Elevated ? " (administrator)" : "")} from {path}");
                        // Its page is the app's own code reading only results: it still renders in the app.
                        if (manifest is { HasUi: true, PortableUi: false, ResultOnlyUi: true })
                            registrar.RegisterUiOnly(Instantiate(pluginId, dll, manifest), pluginId, manifest.Id);
                    }
                    continue;
                }
                // No module host (tests, tools): a module that ships with the app may always load in process like the others.
                if (hosting.OutOfProcess) hosting = hosting with { OutOfProcess = false, Elevated = false };
                else if (hosting.Requested == ModuleProcessMode.OutOfProcess && hosting.InProcessOnly is { } stays)
                    Log($"built-in {manifest.Slug} stays in process: {stays}");
                var plugin = Instantiate(pluginId, dll, manifest);
                // No manifest descriptor: the app's own descriptor (group, order, RunAfter) stays the one used.
                if (registrar.Register(services, plugin, pluginId, ModuleSource.BuiltIn, manifest.Id, record with { Hosting = hosting }))
                    Log($"loaded built-in {manifest.Slug} ({manifest.Id}) from {path}");
            }
            catch (Exception ex)
            {
                registrar.RecordDisabled(record with { Reason = $"{ex.GetType().Name}: {ex.Message}" });
            }
        }
    }

    /// <summary>Shown as the signature of a module that ships with the app (About page, Event Log).</summary>
    public const string BundledSignature = "Ships with the app";

    private static IModulePlugin Instantiate(string pluginId, byte[] dll, ModuleManifest manifest)
    {
        var alc = new ModuleLoadContext(pluginId, dll);
        var asm = alc.LoadFromStream(new MemoryStream(dll, writable: false));
        var entry = asm.GetType(manifest.EntryType, throwOnError: false)
            ?? throw new InvalidDataException($"entryType {manifest.EntryType} not found");
        return Activator.CreateInstance(entry) as IModulePlugin
            ?? throw new InvalidDataException($"{manifest.EntryType} does not implement IModulePlugin");
    }

    private static bool SameFolder(string a, string b)
    {
        try { return string.Equals(Path.GetFullPath(a).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
            Path.GetFullPath(b).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }

    /// <summary>Plugins whose DLL is gone keep their catalog copy, so History can still name their results.</summary>
    private void LoadRetired(Dictionary<Guid, string> loaded)
    {
        if (!Directory.Exists(options.CatalogFolder)) return;
        foreach (var dir in Directory.EnumerateDirectories(options.CatalogFolder))
        {
            try
            {
                var file = Path.Combine(dir, ModuleManifest.ResourceName);
                if (!File.Exists(file)) continue;
                var m = ModuleManifest.Parse(File.ReadAllBytes(file));
                if (m.Id == Guid.Empty || loaded.ContainsKey(m.Id)) continue;
                registrar.AddRetired(m.ToDescriptor(m.Slug));
            }
            catch (Exception ex) { Log($"catalog entry {dir} unreadable: {ex.Message}"); }
        }
    }

    private IEnumerable<string> Discover()
    {
        if (!Directory.Exists(options.ModulesFolder)) return [];
        return Directory.EnumerateFiles(options.ModulesFolder, "*.dll", SearchOption.TopDirectoryOnly).Order(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private void SaveToCatalog(ModuleManifest manifest, IReadOnlyDictionary<string, byte[]> strings)
    {
        try
        {
            var dir = Path.Combine(options.CatalogFolder, manifest.Id.ToString("D"));
            Directory.CreateDirectory(Path.Combine(dir, "strings"));
            File.WriteAllText(Path.Combine(dir, ModuleManifest.ResourceName), manifest.ToJson());
            foreach (var (name, bytes) in strings) File.WriteAllBytes(Path.Combine(dir, "strings", Path.GetFileName(name)), bytes);
        }
        catch (Exception ex) { LogWarn($"couldn't save {manifest.Slug} to the catalog: {ex.Message}"); }
    }

    private void Log(string m) => log.Info("Modules: " + m);
    private void LogWarn(string m) => log.Warn("Modules: " + m);
}

/// <summary>Registers one ready-made module (the user-mode stand-in).</summary>
internal sealed class SingleModulePlugin(IDiagnosticModule module) : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) => services.AddSingleton<IDiagnosticModule>(_ => module);
}

/// <summary>A module the user-mode module host runs out of process: an unsigned plugin, or a module that ships with the app and asks to
/// (<see cref="ModuleManifest.OutOfProcess"/>).</summary>
public sealed record UserModeModule(string Path, ModuleManifest Manifest, ModuleDescriptor Descriptor)
{
    /// <summary>Ships with the app (builtin-modules\): trusted like the app's own code, so its report keeps its one-click fixes and the
    /// module page shows no "Unsigned module" banner. It still runs with the restricted token.</summary>
    public bool Bundled { get; init; }

    /// <summary>Ships with the app and needs administrator: the module host runs with the app's own (elevated) token instead of a restricted
    /// one. Out of process for crash and memory isolation, not for fewer rights.</summary>
    public bool Elevated { get; init; }
}

/// <summary>
/// One load context per module. The contract assembly, DI and logging abstractions and ASP.NET Components come from the host, so types match across
/// the boundary; the module's own dependencies come from its embedded "lib/&lt;name&gt;.dll" resources.
/// </summary>
public sealed class ModuleLoadContext(string name, byte[] moduleBytes) : AssemblyLoadContext($"module:{name}", isCollectible: false)
{
    private static readonly string[] Shared = ["RemotePCDiagnostics.Abstractions", "Microsoft.Extensions.DependencyInjection.Abstractions", "Microsoft.Extensions.Logging.Abstractions", "Microsoft.AspNetCore.Components", "Microsoft.JSInterop"];

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        var n = assemblyName.Name ?? "";
        if (Shared.Any(s => n.Equals(s, StringComparison.OrdinalIgnoreCase) || n.StartsWith(s + ".", StringComparison.OrdinalIgnoreCase))) return null;
        if (EmbeddedLibrary(n) is { } bytes) return LoadFromStream(new MemoryStream(bytes, writable: false));
        return null; // framework assemblies resolve from the default context
    }

    private byte[]? EmbeddedLibrary(string assemblyName)
    {
        var main = Assemblies.FirstOrDefault();
        if (main is null) return null;
        using var s = main.GetManifestResourceStream($"lib/{assemblyName}.dll");
        if (s is null) return null;
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>The bytes the module was loaded from (kept for diagnostics).</summary>
    public int ModuleSize => moduleBytes.Length;
}
