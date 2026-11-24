using System.Xml.Linq;
using RemotePCDiagnostics.Core.Bios;

namespace RemotePCDiagnostics.Tests.Bios;

/// <summary>
/// Real HP Image Assistant catalog CABs (LZX, 2 MB window, many 32 KB frames) must decode to well-formed XML.
/// Synthetic CABs only cover what the test builder can produce; these come straight from HP's servers.
/// </summary>
public sealed class RealHpCabTests
{
    private static byte[] Fixture(string name) =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Bios", "Fixtures", name));

    [Theory]
    [InlineData("hp-platformList.cab", "platformList.xml")]
    [InlineData("hp-8b41_64_11.0.23h2.cab", "8b41_64_11.0.23h2.xml")]
    public void RealHpCatalogCab_DecodesToWellFormedXml(string cab, string expectedEntry)
    {
        var status = BiosArchiveAndXml.TryExtractCabEntriesWithStatus(Fixture(cab), out var entries);

        Assert.Equal(CabExtractionStatus.Succeeded, status);
        var (name, bytes) = Assert.Single(entries);
        Assert.Equal(expectedEntry, name, ignoreCase: true);
        Assert.True(bytes.Length > 64 * 1024, $"Expected a multi-frame file, got {bytes.Length} bytes.");

        var xml = BiosArchiveAndXml.ParseXmlSafe(new MemoryStream(bytes), maxCharactersInDocument: 64L * 1024 * 1024);
        Assert.NotNull(xml.Root);
        Assert.NotEmpty(xml.Root.Elements());
    }
}
