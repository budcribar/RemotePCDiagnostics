using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

public class KeyboardLayoutTests
{
    [Theory]
    [InlineData("en-GB", "Lenovo", "IdeaPad Slim 5 16AHP11", "", "iso-uk-numpad")]
    [InlineData("de-DE", "LENOVO", "IdeaPad Slim 5 16IAH10", "", "iso-de-numpad")]
    [InlineData("fr-FR", "Lenovo", "IdeaPad Slim 5 16ABR8", "", "iso-fr-numpad")]
    [InlineData("en-US", "Dell Inc.", "Latitude 5530", "", "ansi-numpad")]
    [InlineData("en-US", "Dell Inc.", "Latitude 5440", "", "ansi")]
    [InlineData("en-US", "Dell Inc.", "Latitude E5530", "", "ansi")]
    [InlineData("en-US", "ASUSTeK COMPUTER INC.", "Vivobook M1502YA_M1502YA", "", "ansi-numpad")]
    [InlineData("en-US", "Hewlett-Packard", "HP Laptop 15-fc1001", "", "ansi-numpad")]
    [InlineData("en-US", "HP", "Victus 15-fb3001", "", "ansi-numpad")]
    [InlineData("en-US", "HP", "HP ProBook 450 15.6 inch G10", "", "ansi-numpad")]
    [InlineData("en-US", "HP", "HP Laptop 15-fc9000", "", "ansi")]
    [InlineData("en-US", "Acer", "Aspire A315-24P", "", "ansi-numpad")]
    [InlineData("en-US", "Unknown", "Aspire A315-24P", "", "ansi")]
    [InlineData("en-US", "Lenovo", "82R4", "LENOVO_MT_82R4", "ansi-numpad")]
    [InlineData("en-US", "Lenovo", "82R4", "82R4010NJP", "jis-numpad")]
    [InlineData("ja-JP", "Lenovo", "82R4002PUS", "", "ansi-numpad")]
    [InlineData("ja-JP", "", "", "", "jis")]
    public void Ranks_first_candidate_and_preserves_all_choices(
        string language, string manufacturer, string model, string sku, string expected)
    {
        var candidates = KeyboardLayout.GetCandidates(language, manufacturer, model, sku);

        Assert.Equal(expected, candidates[0].Id);
        Assert.Equal(10, candidates.Select(candidate => candidate.Id).Distinct().Count());
    }

    [Fact]
    public void Layouts_keep_unique_physical_codes_and_show_expected_variant_keys()
    {
        var layouts = KeyboardLayout.GetCandidates("en-US", "", "", "");
        foreach (var layout in layouts)
        {
            var codes = layout.Caps.Select(cap => cap.Code).ToHashSet();
            Assert.Equal(layout.Caps.Count, codes.Count);
            Assert.Contains("Enter", codes);
            Assert.Equal(layout.Id.EndsWith("-numpad", StringComparison.Ordinal), codes.Contains("NumpadEnter"));
            Assert.Equal(layout.Id.StartsWith("iso-", StringComparison.Ordinal), codes.Contains("IntlBackslash"));
            Assert.Equal(layout.Id.StartsWith("jis", StringComparison.Ordinal), codes.Contains("IntlYen"));
            Assert.Equal(layout.Id.StartsWith("jis", StringComparison.Ordinal), codes.Contains("IntlRo"));
        }

        var german = layouts.Single(layout => layout.Id == "iso-de");
        Assert.Equal("Z", german.Caps.Single(cap => cap.Code == "KeyY").Label);
        Assert.Equal("Y", german.Caps.Single(cap => cap.Code == "KeyZ").Label);
    }
}
