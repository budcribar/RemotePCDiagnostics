namespace RemotePCDiagnostics.Core.Theming;

/// <summary>User's theme choice. System follows the OS light/dark setting.</summary>
public enum ThemeChoice { Dark, System, Light }

/// <summary>Pure helpers for parsing/resolving the theme choice (mirrors the JS in index.html).</summary>
public static class ThemePreference
{
    public const ThemeChoice Default = ThemeChoice.System;
    public const string StorageKey = "rpd-theme";

    /// <summary>Parses a stored value ("dark"/"system"/"light", any case). Anything else gives <see cref="Default"/>.</summary>
    public static ThemeChoice Parse(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "dark" => ThemeChoice.Dark,
        "light" => ThemeChoice.Light,
        "system" => ThemeChoice.System,
        _ => Default,
    };

    /// <summary>Value stored in localStorage and used in the UI.</summary>
    public static string ToStorage(ThemeChoice c) => c.ToString().ToLowerInvariant();

    /// <summary>Effective data-theme attribute ("dark" or "light") given whether the OS prefers dark.</summary>
    public static string Resolve(ThemeChoice c, bool systemPrefersDark) => c switch
    {
        ThemeChoice.Dark => "dark",
        ThemeChoice.Light => "light",
        _ => systemPrefersDark ? "dark" : "light",
    };
}
