using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Checks;

/// <summary>One column of a check's table: the osquery column and its heading.</summary>
public sealed record JsonCheckColumn(string Name, string Title);

/// <summary>A pass/warn/fail rule on one column. A row takes the level of the worst rule it matches.</summary>
public sealed record JsonCheckRule
{
    public string Column { get; init; } = "";
    /// <summary>eq, ne, lt, le, gt, ge (numbers), contains, notContains (text, case-insensitive), empty, notEmpty.</summary>
    public string Op { get; init; } = "eq";
    public string? Value { get; init; }
    public AreaLevel Level { get; init; } = AreaLevel.Warning;
    /// <summary>Shown when expanding the row. Plain text, never HTML.</summary>
    public string? Message { get; init; }

    public bool Matches(IReadOnlyDictionary<string, string> row)
    {
        var v = row.GetValueOrDefault(Column) ?? "";
        double? Num(string? s) => double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
        return Op.ToLowerInvariant() switch
        {
            "eq" => string.Equals(v, Value, StringComparison.OrdinalIgnoreCase),
            "ne" => !string.Equals(v, Value, StringComparison.OrdinalIgnoreCase),
            "contains" => Value is { Length: > 0 } && v.Contains(Value, StringComparison.OrdinalIgnoreCase),
            "notcontains" => Value is { Length: > 0 } && !v.Contains(Value, StringComparison.OrdinalIgnoreCase),
            "empty" => v.Length == 0,
            "notempty" => v.Length > 0,
            "lt" => Num(v) < Num(Value), "le" => Num(v) <= Num(Value), "gt" => Num(v) > Num(Value), "ge" => Num(v) >= Num(Value),
            _ => false,
        };
    }

    public static readonly string[] Ops = ["eq", "ne", "lt", "le", "gt", "ge", "contains", "notcontains", "empty", "notempty"];
}

/// <summary>
/// A check written as data (%ProgramFiles%\RemotePCDiagnostics\checks\*.json): a read-only osquery query, the columns to show and rules on
/// them. It carries no code, so it runs in the app unsigned, shown in the standard report view. Same descriptor fields as a module.
/// </summary>
public sealed record JsonCheck
{
    public Guid Id { get; init; }
    public string Slug { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public string Group { get; init; } = ModuleGroups.Other;
    public int Order { get; init; } = 10_000;
    public List<Guid> DependsOn { get; init; } = [];
    public List<Guid> RunAfter { get; init; } = [];
    public string Query { get; init; } = "";
    public List<JsonCheckColumn> Columns { get; init; } = [];
    public List<JsonCheckRule> Rules { get; init; } = [];
    /// <summary>Headline when no row matches a rule.</summary>
    public string? OkText { get; init; }
    /// <summary>Shown when the query returns no rows.</summary>
    public string? EmptyText { get; init; }
    /// <summary>Level when the query returns no rows (Ok by default).</summary>
    public AreaLevel EmptyLevel { get; init; } = AreaLevel.Ok;

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static JsonCheck Parse(string json) => JsonSerializer.Deserialize<JsonCheck>(json, Json) ?? throw new InvalidDataException("empty check");

    /// <summary>Tables that reach outside the PC or copy files, refused even though osquery can't change anything.</summary>
    private static readonly string[] DeniedTables = ["curl", "curl_certificate", "carves", "carve"];

    /// <summary>What's wrong with this check, or null when it can run.</summary>
    public string? Problem()
    {
        if (Id == Guid.Empty) return "no id";
        if (string.IsNullOrWhiteSpace(Slug) || !Slug.Contains('.')) return "slug must be vendor.name";
        if (string.IsNullOrWhiteSpace(Query)) return "no query";
        var q = Query.Trim().TrimEnd(';').Trim();
        if (!(q.StartsWith("select ", StringComparison.OrdinalIgnoreCase) || q.StartsWith("with ", StringComparison.OrdinalIgnoreCase)))
            return "the query must be a SELECT";
        if (q.Contains(';') || q.StartsWith('.')) return "the query must be one statement";
        var words = q.Split([' ', '\t', '\r', '\n', ',', '(', ')', '"', '\'', '`', '[', ']', '/', '*', '=', '.'], StringSplitOptions.RemoveEmptyEntries);
        if (words.Any(w => DeniedTables.Contains(w, StringComparer.OrdinalIgnoreCase))) return "the query uses a table checks may not use";
        if (words.Any(w => w.Equals("attach", StringComparison.OrdinalIgnoreCase) || w.Equals("pragma", StringComparison.OrdinalIgnoreCase)))
            return "the query must be a plain SELECT";
        if (Columns.Count == 0) return "no columns";
        if (Rules.FirstOrDefault(r => !JsonCheckRule.Ops.Contains(r.Op.ToLowerInvariant())) is { } bad) return $"unknown rule op '{bad.Op}'";
        return null;
    }

    public ModuleDescriptor ToDescriptor() =>
        new(Id, Slug, string.IsNullOrWhiteSpace(DisplayName) ? Slug : DisplayName, ModuleKind.Check, Group, Order)
        {
            Source = ModuleSource.Plugin, PluginId = "check:" + Slug, DependsOn = DependsOn, RunAfter = RunAfter,
        };

    /// <summary>The report for the query's rows.</summary>
    public AreaReport Evaluate(IReadOnlyList<IReadOnlyDictionary<string, string>> rows)
    {
        var title = string.IsNullOrWhiteSpace(DisplayName) ? Slug : DisplayName;
        if (rows.Count == 0)
        {
            var empty = new AreaCard(Slug, title, EmptyLevel, EmptyText ?? "Nothing found", "", Columns.Select(c => c.Title).ToList(), [], EmptyText: EmptyText);
            return new AreaReport([empty], EmptyText ?? "Nothing found", AreaReport.Worst([EmptyLevel]));
        }
        var areaRows = new List<AreaRow>();
        foreach (var row in rows)
        {
            var matched = Rules.Where(r => r.Matches(row)).ToList();
            var level = matched.Count == 0 ? AreaLevel.Ok : matched.Max(r => r.Level);
            var detail = string.Join(Environment.NewLine, matched.Select(r => r.Message).Where(m => !string.IsNullOrWhiteSpace(m)));
            areaRows.Add(new AreaRow(level, Columns.Select(c => row.GetValueOrDefault(c.Name) ?? "").ToList(), Detail: detail.Length > 0 ? detail : null));
        }
        var errors = areaRows.Count(r => r.Level == AreaLevel.Error);
        var warnings = areaRows.Count(r => r.Level == AreaLevel.Warning);
        var worst = areaRows.Max(r => r.Level);
        var headline = errors + warnings == 0 ? OkText ?? $"{rows.Count} checked, no problems"
            : string.Join(", ", new[] { errors > 0 ? $"{errors} problem{(errors == 1 ? "" : "s")}" : null, warnings > 0 ? $"{warnings} warning{(warnings == 1 ? "" : "s")}" : null }.OfType<string>());
        var card = new AreaCard(Slug, title, worst, headline, $"{rows.Count} row{(rows.Count == 1 ? "" : "s")}", Columns.Select(c => c.Title).ToList(), areaRows);
        return new AreaReport([card], headline, AreaReport.Worst(areaRows.Select(r => r.Level)));
    }
}

/// <summary>Runs one <see cref="JsonCheck"/> through osquery.</summary>
public sealed class JsonCheckModule(JsonCheck check, Func<string, CancellationToken, Task<OsqueryQueryResult>> query,
    Func<ModuleAvailability>? availability = null, ILogger? log = null) : AreaModuleBase(log.AsAction())
{
    public JsonCheck Check => check;
    public override Guid Id => check.Id;
    public override string Name => check.Slug;
    public override string DisplayName => string.IsNullOrWhiteSpace(check.DisplayName) ? check.Slug : check.DisplayName;
    protected override string FailedMessage => $"Couldn't run {DisplayName}.";

    public override Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(availability?.Invoke() ?? ModuleAvailability.Available);

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report($"Running {DisplayName}…");
        var r = await query(check.Query, ct).ConfigureAwait(false);
        if (!r.Success) return AreaReport.Failed($"Couldn't read the data for {DisplayName}: {r.Error}");
        return check.Evaluate(r.Rows ?? []);
    }

    /// <summary>
    /// Reads every *.json in <paramref name="folder"/> (top level only). A check with a problem, or whose id or slug is taken, is skipped and
    /// reported in <paramref name="problems"/>; the rest are returned in file-name order.
    /// </summary>
    public static IReadOnlyList<JsonCheck> LoadFolder(string folder, IDictionary<Guid, string> takenIds, ISet<string> takenSlugs, List<(string File, string Problem)> problems)
    {
        var checks = new List<JsonCheck>();
        if (!Directory.Exists(folder)) return checks;
        foreach (var file in Directory.EnumerateFiles(folder, "*.json", SearchOption.TopDirectoryOnly).Order(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var c = JsonCheck.Parse(File.ReadAllText(file));
                if (c.Problem() is { } p) { problems.Add((file, p)); continue; }
                if (takenIds.TryGetValue(c.Id, out var owner)) { problems.Add((file, $"id {c.Id} is already used by {owner}")); continue; }
                if (!takenSlugs.Add(c.Slug)) { problems.Add((file, $"slug {c.Slug} is already used")); continue; }
                takenIds[c.Id] = c.Slug;
                checks.Add(c);
            }
            catch (Exception ex) { problems.Add((file, $"{ex.GetType().Name}: {ex.Message}")); }
        }
        return checks;
    }

    public static string DefaultFolder() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RemotePCDiagnostics", "checks");
}

/// <summary>Registers one JSON check, running its query through the app's osquery.</summary>
public sealed class JsonCheckPlugin(JsonCheck check, ILogger? log = null) : Plugins.IModulePlugin
{
    public void Register(Microsoft.Extensions.DependencyInjection.IServiceCollection services, Plugins.IPluginContext context) =>
        Microsoft.Extensions.DependencyInjection.ServiceCollectionServiceExtensions.AddSingleton<IDiagnosticModule>(services, sp =>
        {
            var osquery = (OsqueryRunner)sp.GetService(typeof(OsqueryRunner))!;
            return new JsonCheckModule(check, osquery.RunQueryAsync, osquery.CheckAvailability, log);
        });
}
