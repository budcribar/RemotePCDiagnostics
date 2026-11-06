using System.Collections.Concurrent;

namespace RemotePCDiagnostics.Core.Scripts;

/// <summary>
/// The app's fixed PowerShell scripts, embedded from Core/Scripts/*.ps1 and loaded by name (the file name without .ps1). Only for what
/// has no reasonable in-process replacement (CIM/Storage cmdlets, Windows Update COM, Defender, the search index); registry and WMI
/// one-liners go through <see cref="Areas.ISystemSettings"/> instead. Scripts never contain user input.
/// </summary>
public static class PowerShellScripts
{
    private static readonly ConcurrentDictionary<string, string> Cache = new(StringComparer.Ordinal);

    /// <summary>The script's text. Throws for an unknown name (a build mistake, caught by the tests).</summary>
    public static string Get(string name) => Cache.GetOrAdd(name, static n =>
    {
        using var stream = typeof(PowerShellScripts).Assembly.GetManifestResourceStream($"Scripts/{n}.ps1")
            ?? throw new InvalidOperationException($"No embedded script named {n}.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim().TrimStart('﻿');
    });

    /// <summary>Every embedded script name.</summary>
    public static IReadOnlyList<string> Names { get; } = typeof(PowerShellScripts).Assembly.GetManifestResourceNames()
        .Where(r => r.StartsWith("Scripts/", StringComparison.Ordinal) && r.EndsWith(".ps1", StringComparison.Ordinal))
        .Select(r => r["Scripts/".Length..^".ps1".Length]).Order(StringComparer.Ordinal).ToList();
}
