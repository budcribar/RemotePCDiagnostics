using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

public sealed record InstalledProgram(string Name, string Version, string Publisher, DateOnly? InstalledOn)
{
    public static InstalledProgram FromRow(IReadOnlyDictionary<string, string> r) =>
        new(r.Str("name"), r.Str("version"), r.Str("publisher"), ProgramsModule.ParseDate(r.Str("install_date")));
}

public sealed record InstalledUpdate(string Id, string Description, DateOnly? InstalledOn)
{
    public static InstalledUpdate FromRow(IReadOnlyDictionary<string, string> r) =>
        new(r.Str("hotfix_id"), r.Str("description"), ProgramsModule.ParseDate(r.Str("installed_on")));
}

/// <summary>Windows version, installed updates (osquery <c>os_version</c>, <c>patches</c>) and installed programs (<c>programs</c>).</summary>
public sealed class ProgramsModule(OsqueryRunner runner, Func<DateOnly>? today = null) : OsqueryAreaModuleBase(runner)
{
    public const string ModuleName = "Programs";
    public const string OsSql = "SELECT * FROM os_version;";
    public const string PatchesSql = "SELECT hotfix_id, description, installed_on FROM patches;";
    public const string ProgramsSql = "SELECT name, version, publisher, install_date FROM programs;";
    /// <summary>Monthly Windows updates; older than this is flagged.</summary>
    public const int StaleUpdateDays = 60;

    public override string Name => ModuleName;
    public override string DisplayName => "Programs & updates";
    protected override string FailedMessage => "Couldn't read installed programs and updates on this PC.";
    private readonly Func<DateOnly> _today = today ?? (() => DateOnly.FromDateTime(DateTime.Today));

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 3, "Checking Windows version…");
        var os = await QueryAsync(OsSql, ct).ConfigureAwait(false);
        progress.ReportStep(2, 3, "Checking installed Windows updates…");
        var patches = await QueryAsync(PatchesSql, ct).ConfigureAwait(false);
        progress.ReportStep(3, 3, "Reading installed programs…");
        var programs = await QueryAsync(ProgramsSql, ct).ConfigureAwait(false);
        return Build(os.Success ? os.Rows!.FirstOrDefault() : null, os.Success,
            patches.Success ? patches.Rows!.Select(InstalledUpdate.FromRow).ToList() : null,
            programs.Success ? programs.Rows!.Select(InstalledProgram.FromRow).ToList() : null, _today());
    }

    private static readonly string[] DateFormats = ["yyyyMMdd", "M/d/yyyy", "MM/dd/yyyy", "yyyy-MM-dd", "M/d/yyyy h:mm:ss tt", "yyyy-MM-dd HH:mm:ss"];

    public static DateOnly? ParseDate(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        if (DateTime.TryParseExact(s, DateFormats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)) return DateOnly.FromDateTime(d);
        // os_version.install_date is Unix seconds.
        if (s.Length is 9 or 10 && long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var unix))
            return DateOnly.FromDateTime(DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime);
        // Some patches report a hex FILETIME (e.g. "01d9a2b3c4d5e6f7").
        if (s.Length == 16 && long.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var ft))
        {
            try { return DateOnly.FromDateTime(DateTime.FromFileTimeUtc(ft)); } catch (ArgumentOutOfRangeException) { }
        }
        return null;
    }

    public static string FormatDate(DateOnly? d) => d?.ToString("d MMM yyyy", CultureInfo.InvariantCulture) ?? "";
    public static string DateKey(DateOnly? d) => d?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "";

    public static AreaReport Build(IReadOnlyDictionary<string, string>? os, bool osOk, IReadOnlyList<InstalledUpdate>? updates, IReadOnlyList<InstalledProgram>? programs, DateOnly today)
    {
        if (!osOk && updates is null && programs is null)
            return AreaReport.Failed("Couldn't read installed programs and updates on this PC.");
        var cards = new List<AreaCard>();
        var parts = new List<string>();

        // Windows version
        if (!osOk) cards.Add(AreaCard.Failed("windows", "Windows version", "Couldn't read the Windows version."));
        else if (os is null) cards.Add(new("windows", "Windows version", AreaLevel.Neutral, "", "", [], [], EmptyText: "Windows version isn't available."));
        else
        {
            var name = os.Str("name");
            var display = os.Str("display_version"); // e.g. 23H2, when reported
            var build = os.Str("build");
            var meta = string.Join(" · ", new[] { display.Length > 0 ? $"Version {display}" : null, build.Length > 0 ? $"Build {build}" : null }.Where(x => x is not null));
            var rows = new List<AreaRow>();
            void Add(string l, string v) { if (v.Length > 0) rows.Add(new(AreaLevel.Neutral, [l, v])); }
            Add("Edition", name); Add("Version", display); Add("Build", build); Add("Full version number", os.Str("version")); Add("Architecture", os.Str("arch"));
            Add("Installed on", FormatDate(ParseDate(os.Str("install_date"))));
            cards.Add(new("windows", "Windows version", AreaLevel.Ok, name.Length > 0 ? name : "Windows", meta, ["Detail", "Value"], rows));
            if (name.Length > 0) parts.Add(name);
        }

        // Windows updates
        var level = AreaLevel.Ok;
        if (updates is null) cards.Add(AreaCard.Failed("updates", "Windows updates", "Couldn't read installed updates."));
        else
        {
            var latest = updates.Select(u => u.InstalledOn).Where(d => d is not null).DefaultIfEmpty(null).Max();
            var age = latest is { } l ? today.DayNumber - l.DayNumber : (int?)null;
            level = updates.Count == 0 || age > StaleUpdateDays ? AreaLevel.Warning : AreaLevel.Ok;
            var headline = updates.Count == 0 ? "No updates found"
                : latest is null ? AreaModuleBase.Plural(updates.Count, "update") + " installed"
                : $"Last update {Ago(age!.Value)}";
            var meta = updates.Count == 0 ? "Run Windows Update to get the latest fixes"
                : (age > StaleUpdateDays ? $"No updates for over {StaleUpdateDays} days – run Windows Update · " : "") + AreaModuleBase.Plural(updates.Count, "update") + " installed";
            var rows = updates.OrderByDescending(u => u.InstalledOn ?? DateOnly.MinValue)
                .Select(u => new AreaRow(AreaLevel.Neutral, [u.Id, u.Description, u.InstalledOn is null ? "Unknown" : FormatDate(u.InstalledOn)],
                    [null, null, DateKey(u.InstalledOn)])).ToList();
            cards.Add(new("updates", "Windows updates", level, headline, meta, ["Update", "Type", "Installed"], rows,
                Note: "Windows lists the main updates here; some feature and driver updates aren't included.",
                Actions: [new(RemediationKind.CheckAndInstallWindowsUpdates, "Check & install updates")]));
            parts.Add(updates.Count == 0 ? "no updates found" : latest is null ? AreaModuleBase.Plural(updates.Count, "update") : $"last update {Ago(age!.Value)}");
        }

        // Installed programs
        if (programs is null) cards.Add(AreaCard.Failed("programs", "Installed programs", "Couldn't read installed programs."));
        else
        {
            var list = programs.Where(p => p.Name.Length > 0)
                .DistinctBy(p => (p.Name.ToUpperInvariant(), p.Version))
                .OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
            var recent = list.Where(p => p.InstalledOn is { } d && today.DayNumber - d.DayNumber <= 30).ToList();
            cards.Add(new("programs", "Installed programs", AreaLevel.Ok, AreaModuleBase.Plural(list.Count, "program"),
                recent.Count > 0 ? $"{recent.Count} installed or updated in the last 30 days" : "None installed in the last 30 days",
                ["Program", "Version", "Publisher", "Installed"],
                list.Select(p => new AreaRow(AreaLevel.Neutral, [p.Name, p.Version, p.Publisher, FormatDate(p.InstalledOn)],
                    [null, null, null, DateKey(p.InstalledOn)])).ToList(),
                EmptyText: list.Count == 0 ? "No installed programs were found." : null));
            parts.Add(AreaModuleBase.Plural(list.Count, "program"));
        }

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, parts.Count > 0 ? string.Join(" · ", parts) : "Some details couldn't be read.", status);
    }

    public static string Ago(int days) => days switch { <= 0 => "today", 1 => "yesterday", < 60 => $"{days} days ago", _ => $"{days / 30} months ago" };
}
