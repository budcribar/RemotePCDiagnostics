using System.Text.Json;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Security;

public enum AntivirusProductState { Unknown, On, Off, Snoozed, Expired }

public enum AntivirusSignatureStatus { Unknown, UpToDate, OutOfDate }

public enum AntivirusInventoryStatus { Ok, Incomplete, Unavailable }

/// <summary>One antivirus registration from Windows Security Center (<c>IWscProduct</c>) or WMI fallback.</summary>
public sealed record AntivirusProductInfo(
    string Name,
    AntivirusProductState State,
    AntivirusSignatureStatus Signatures = AntivirusSignatureStatus.Unknown,
    string Source = "wsc")
{
    public bool IsDefender =>
        Name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase)
        || Name.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase)
        || string.Equals(Name.Trim(), "Defender", StringComparison.OrdinalIgnoreCase);

    public string FormatState()
    {
        var state = State switch
        {
            AntivirusProductState.On => "On",
            AntivirusProductState.Off => "Off",
            AntivirusProductState.Snoozed => "Snoozed",
            AntivirusProductState.Expired => "Expired",
            _ => "State unknown",
        };
        var sig = Signatures switch
        {
            AntivirusSignatureStatus.UpToDate => ", definitions up to date",
            AntivirusSignatureStatus.OutOfDate => ", definitions out of date",
            _ => "",
        };
        return state + sig;
    }
}

/// <summary>Result of enumerating Windows Security Center antivirus products via <see cref="IAntivirusProductSource"/>.</summary>
public sealed record AntivirusInventoryResult(
    AntivirusInventoryStatus Status,
    IReadOnlyList<AntivirusProductInfo> Products,
    string? Error = null)
{
    public static AntivirusInventoryResult Unavailable(string? error = null) =>
        new(AntivirusInventoryStatus.Unavailable, [], error);

    /// <summary>Encodes as a <see cref="WmiQueryResult"/> so record/replay captures it alongside WMI and registry calls.</summary>
    public WmiQueryResult ToRecordedResult()
    {
        if (Status == AntivirusInventoryStatus.Unavailable)
            return WmiQueryResult.Failed("wsc", "antivirus", Error ?? "WSC unavailable");

        var rows = new List<WmiRow>(Products.Count);
        foreach (var p in Products)
        {
            var dict = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase)
            {
                ["Name"] = JsonSerializer.SerializeToElement(p.Name),
                ["State"] = JsonSerializer.SerializeToElement(p.State.ToString()),
                ["Signatures"] = JsonSerializer.SerializeToElement(p.Signatures.ToString()),
                ["Source"] = JsonSerializer.SerializeToElement(p.Source),
            };
            if (Status == AntivirusInventoryStatus.Incomplete)
                dict["Incomplete"] = JsonSerializer.SerializeToElement(true);
            rows.Add(new WmiRow(dict));
        }
        return new WmiQueryResult("wsc", Status == AntivirusInventoryStatus.Incomplete ? "antivirus:incomplete" : "antivirus", rows);
    }

    public static AntivirusInventoryResult FromRecordedResult(WmiQueryResult r)
    {
        if (!r.Success)
            return Unavailable(r.Error);

        var incomplete = string.Equals(r.Query, "antivirus:incomplete", StringComparison.OrdinalIgnoreCase);
        var list = new List<AntivirusProductInfo>();
        foreach (var row in r.Rows ?? [])
        {
            var name = row.Str("Name").Trim();
            if (name.Length == 0) continue;
            var state = Enum.TryParse<AntivirusProductState>(row.Str("State"), ignoreCase: true, out var st) ? st : AntivirusProductState.Unknown;
            var sig = Enum.TryParse<AntivirusSignatureStatus>(row.Str("Signatures"), ignoreCase: true, out var sg) ? sg : AntivirusSignatureStatus.Unknown;
            var src = row.Str("Source");
            if (row.Bool("Incomplete") == true) incomplete = true;
            list.Add(new AntivirusProductInfo(name, state, sig, src.Length > 0 ? src : "wsc"));
        }
        return new AntivirusInventoryResult(incomplete ? AntivirusInventoryStatus.Incomplete : AntivirusInventoryStatus.Ok, list);
    }
}

/// <summary>Reads registered antivirus product states from the documented Windows Security Center COM API (<c>WSCProductList</c>).</summary>
public interface IAntivirusProductSource
{
    Task<AntivirusInventoryResult> ReadAsync(CancellationToken ct = default);
}
