using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Drivers;

namespace RemotePCDiagnostics.Tests.Drivers;

public sealed class VendorDriverCatalogTests
{
    private static async Task<XDocument> HpFixtureAsync()
    {
        var bytes = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Bios", "Fixtures", "hp-8b41_64_11.0.23h2.cab"));
        var xml = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(bytes, "test", maxDecompressedBytes: 64L * 1024 * 1024);
        return BiosArchiveAndXml.ParseXmlSafe(xml!);
    }

    [Fact]
    public async Task Hp_catalog_flags_only_softpaqs_whose_installed_file_is_older()
    {
        var doc = await HpFixtureAsync();
        // A ZBook-like PC: Intel ME older than HP's (the one real gap found on IA8), the Intel GPU driver newer (from Windows Update).
        var files = new Dictionary<string, Version>(StringComparer.OrdinalIgnoreCase)
        {
            [@"%SystemRoot%\System32\drivers\IntelMEFWVer.dll"] = new(2603, 9, 4, 0),
            [@"%SystemRoot%\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\igdkmdn64.sys"] = new(32, 0, 101, 7090),
            [@"%SystemRoot%\System32\DriverStore\FileRepository\ish.inf_amd64_*\ISH.sys"] = new(3, 1, 0, 4599),
        };
        var (updates, compared) = HpDriverCatalog.Evaluate(doc, ["W11_23H2"], p => files.GetValueOrDefault(p));

        // ME (two SoftPaqs list the same file), graphics and sensor hub were compared.
        Assert.Equal(4, compared);
        var me = Assert.Single(updates);
        Assert.Equal("Intel Management Engine Driver", me.Title);
        Assert.Equal("Driver - Chipset", me.Category);
        Assert.Equal("2603.9.4", me.InstalledVersion);
        Assert.Equal("2613.9.28", me.AvailableVersion);
        Assert.Equal("sp173748", me.PackageId);
        Assert.StartsWith("https://ftp.hp.com/pub/softpaq/", me.DownloadUrl);
        Assert.EndsWith("sp173748.exe", me.DownloadUrl);
        Assert.EndsWith(".html", me.DetailsUrl);
        Assert.True(me.SizeBytes > 0);
    }

    [Fact]
    public async Task Hp_catalog_skips_bios_docks_software_and_files_that_arent_there()
    {
        var doc = await HpFixtureAsync();
        var asked = new List<string>();
        var (updates, compared) = HpDriverCatalog.Evaluate(doc, ["W11_23H2"], p => { asked.Add(p); return null; });

        Assert.Empty(updates);
        Assert.Equal(0, compared);
        Assert.DoesNotContain(asked, p => p.Contains("HP Firmware Installer", StringComparison.OrdinalIgnoreCase)); // docks
        Assert.DoesNotContain(asked, p => p.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase)); // software
        Assert.Contains(@"%SystemRoot%\System32\drivers\IntelMEFWVer.dll", asked);
    }

    [Fact]
    public async Task Hp_catalog_uses_the_next_os_list_when_this_release_has_none()
    {
        var doc = await HpFixtureAsync();
        var files = new Dictionary<string, Version>(StringComparer.OrdinalIgnoreCase) { [@"%SystemRoot%\System32\drivers\IntelMEFWVer.dll"] = new(2603, 9, 4, 0) };
        var (updates, _) = HpDriverCatalog.Evaluate(doc, ["W11_27H2", "W11_23H2"], p => files.GetValueOrDefault(p));
        Assert.Contains(updates, u => u.PackageId == "sp173748");
    }

    [Theory]
    [InlineData(@"<WINSYSDIR>\DriverStore\FileRepository\ish.inf_amd64_e0c5ebcbfde15d36\", @"%SystemRoot%\System32\DriverStore\FileRepository\ish.inf_amd64_*")]
    [InlineData(@"<WINSYSDIR>\DriverStore\FileRepository\hpsvcsscancomp.inf_amd64_af1aa699aae8adfb\x64", @"%SystemRoot%\System32\DriverStore\FileRepository\hpsvcsscancomp.inf_amd64_*\x64")]
    [InlineData(@"<DRIVERS>\", @"%SystemRoot%\System32\drivers")]
    [InlineData(@"<DRIVERS>\UMDF\", @"%SystemRoot%\System32\drivers\UMDF")]
    [InlineData(@"<ProgramFilesDir>\Intel\TXT\", @"%ProgramFiles%\Intel\TXT")]
    [InlineData(@"<PROGRAMFILESDIRX86>\HP\x", @"%ProgramFiles(x86)%\HP\x")]
    [InlineData(@"<WINSYSDISK>\programdata\HP\Intel Chipset Driver\", @"%SystemDrive%\programdata\HP\Intel Chipset Driver")]
    [InlineData(@"<UNKNOWN>\x", null)]
    [InlineData(@"<DRIVERS>\..\..\Users", null)]
    [InlineData(@"C:\Windows", null)]
    public void Hp_folder_tokens_become_windows_paths(string catalog, string? expected) =>
        Assert.Equal(expected, HpDriverCatalog.WindowsDirectory(catalog));

    [Fact]
    public void Hp_catalog_tries_this_release_first_then_newer_then_older()
    {
        var urls = HpDriverCatalog.CatalogCandidates(HpDriverCatalog.DefaultCatalogUrlTemplate, "896D", "23H2", arm64: false, win11: true);
        Assert.Equal(["23H2", "24H2", "25H2", "26H2", "22H2", "21H2"], urls.Select(u => u.Release));
        Assert.Equal("https://hpia.hpcloud.hp.com/ref/896d/896d_64_11.0.23h2.cab", urls[0].Url);

        var arm = HpDriverCatalog.CatalogCandidates(HpDriverCatalog.DefaultCatalogUrlTemplate, "8CBE", "", arm64: true, win11: true);
        Assert.Equal("https://hpia.hpcloud.hp.com/ref/8cbe/8cbe_arm64_11.0.26h2.cab", arm[0].Url);
        Assert.Equal(["W11A_24H2", "W11A_25H2"], HpDriverCatalog.OsTags("24H2", "25h2", arm64: true, win11: true));
    }

    [Theory]
    [InlineData("31.0.101.5594", "31.0.101.5594")]
    [InlineData("10.50.511.2021^", "10.50.511.2021")]
    [InlineData("03.05.00.1611", "3.5.0.1611")]
    [InlineData("1.2", "1.2")]
    [InlineData("A05", null)]
    [InlineData("1.2.3.4.5", null)]
    [InlineData("", null)]
    public void Driver_versions_parse_the_leading_dotted_number(string text, string? expected) =>
        Assert.Equal(expected, DriverVersion.Parse(text) is { } v ? DriverVersion.Format(v) : null);

    private const string LenovoDescriptor = """
        <Package id="r1cdu05w" name="R1CDU05W" version="2.2.0.136" hide="False">
          <Title default="EN"><Desc id="EN">AMD GPIO Driver for Windows 11</Desc></Title>
          <ReleaseDate>2026-03-02</ReleaseDate>
          <DetectInstall>
            <Or>
              <_Driver><HardwareID><![CDATA[ACPI\VEN_AMDI&DEV_0030]]></HardwareID><Version>2.2.0.136^</Version></_Driver>
              <Not><_Driver><HardwareID><![CDATA[ACPI\VEN_AMDI&DEV_0031]]></HardwareID><Version>9.0^</Version></_Driver></Not>
            </Or>
          </DetectInstall>
          <Files>
            <Installer><File><Name>r1cdu05w.exe</Name><CRC>X</CRC><Size>1048576</Size></File></Installer>
            <Readme><File><Name>r1cdu05w.txt</Name></File></Readme>
          </Files>
        </Package>
        """;

    private static readonly Uri LenovoUri = new("https://download.lenovo.com/consumer/mobiles/r1cdu05w_2_.xml");

    [Fact]
    public void Lenovo_descriptor_flags_a_device_with_an_older_driver()
    {
        InstalledDriver[] drivers =
        [
            new(@"ACPI\AMDI0030\0", @"ACPI\VEN_AMDI&DEV_0030", "AMD GPIO Controller", "2.2.0.133"),
            new(@"ACPI\AMDI0031\0", @"ACPI\VEN_AMDI&DEV_0031", "Other", "1.0"),
        ];
        var result = LenovoDriverCatalog.Evaluate(XDocument.Parse(LenovoDescriptor), LenovoUri, "Chipset", drivers);

        Assert.NotNull(result);
        Assert.True(result.Value.Compared);
        var u = result.Value.Update!;
        Assert.Equal("AMD GPIO Driver for Windows 11", u.Title);
        Assert.Equal("2.2.0.133", u.InstalledVersion);
        Assert.Equal("2.2.0.136", u.AvailableVersion);
        Assert.Equal("https://download.lenovo.com/consumer/mobiles/r1cdu05w.exe", u.DownloadUrl);
        Assert.Equal("https://download.lenovo.com/consumer/mobiles/r1cdu05w.txt", u.DetailsUrl);
        Assert.Equal(1048576, u.SizeBytes);
        Assert.Equal(new DateOnly(2026, 3, 2), u.Released);
    }

    [Fact]
    public void Lenovo_descriptor_is_current_when_the_driver_is_as_new_and_skipped_when_the_device_is_absent()
    {
        var doc = XDocument.Parse(LenovoDescriptor);
        var current = LenovoDriverCatalog.Evaluate(doc, LenovoUri, "Chipset", [new(@"ACPI\AMDI0030\0", @"ACPI\VEN_AMDI&DEV_0030", "GPIO", "2.2.0.136")]);
        Assert.Equal((true, (VendorDriverUpdate?)null), current);
        // "DEV_00301" isn't DEV_0030, and the rule under <Not> doesn't count.
        var absent = LenovoDriverCatalog.Evaluate(doc, LenovoUri, "Chipset", [new(@"ACPI\X\0", @"ACPI\VEN_AMDI&DEV_00301", "GPIO", "1.0")]);
        Assert.Equal((false, (VendorDriverUpdate?)null), absent);
    }

    [Fact]
    public void Lenovo_index_keeps_driver_packages_on_lenovo_and_drops_bios()
    {
        var index = XDocument.Parse("""
            <packages>
              <package><location>https://download.lenovo.com/consumer/mobiles/a_2_.xml</location><category>Audio</category></package>
              <package><location>https://download.lenovo.com/consumer/mobiles/b_2_.xml</location><category>BIOS/UEFI</category></package>
              <package><location>https://evil.example.com/c.xml</location><category>Network</category></package>
            </packages>
            """);
        Assert.Equal([("https://download.lenovo.com/consumer/mobiles/a_2_.xml", "Audio")], LenovoDriverCatalog.ParseIndex(index));
    }

    private const string DellCatalog = """
        <Manifest baseLocation="downloads.dell.com" version="1">
          <SoftwareComponent packageID="AAA01" releaseID="AAA01" path="FOLDER01/1/Intel-Chipset_AAA01_WIN64_10.1.19.exe" dateTime="2026-05-01T00:00:00+00:00" vendorVersion="10.1.19.8637" size="5000">
            <Name><Display lang="en"><![CDATA[Intel Chipset Device Software]]></Display></Name>
            <ComponentType value="DRVR"><Display lang="en">Drivers</Display></ComponentType>
            <Category value="CS"><Display lang="en">Chipset</Display></Category>
            <SupportedDevices><Device componentID="1"><PCIInfo deviceID="A0EF" vendorID="8086" subDeviceID="0A2E" subVendorID="1028"/></Device></SupportedDevices>
            <SupportedSystems><Brand key="1" prefix="LAT"><Model systemID="0A2E"/></Brand></SupportedSystems>
            <SupportedOperatingSystems><OperatingSystem osCode="W11P4" osArch="x64"/></SupportedOperatingSystems>
            <ImportantInfo URL="https://www.dell.com/support/home/drivers/DriversDetails?driverId=AAA01"/>
          </SoftwareComponent>
          <SoftwareComponent packageID="AAA00" path="FOLDER00/1/Intel-Chipset_AAA00_WIN64_10.1.18.exe" vendorVersion="10.1.18.1" size="4000">
            <Name><Display lang="en"><![CDATA[Intel Chipset Device Software]]></Display></Name>
            <ComponentType value="DRVR"/>
            <SupportedDevices><Device><PCIInfo deviceID="A0EF" vendorID="8086"/></Device></SupportedDevices>
            <SupportedSystems><Brand><Model systemID="0A2E"/></Brand></SupportedSystems>
            <SupportedOperatingSystems><OperatingSystem osCode="W11P4" osArch="x64"/></SupportedOperatingSystems>
          </SoftwareComponent>
          <SoftwareComponent packageID="BBB01" path="FOLDER02/1/Realtek-Audio_BBB01_WIN64_6.0.9999.1.exe" vendorVersion="6.0.9999.1">
            <Name><Display lang="en">Realtek Audio Driver</Display></Name>
            <ComponentType value="DRVR"/>
            <SupportedDevices><Device><PCIInfo deviceID="0257" vendorID="10EC"/></Device></SupportedDevices>
            <SupportedSystems><Brand><Model systemID="0B99"/></Brand></SupportedSystems>
            <SupportedOperatingSystems><OperatingSystem osCode="W11P4" osArch="x64"/></SupportedOperatingSystems>
          </SoftwareComponent>
          <SoftwareComponent packageID="CCC01" path="FOLDER03/1/BIOS_CCC01.exe" vendorVersion="1.30.0">
            <ComponentType value="BIOS"/>
            <SupportedSystems><Brand><Model systemID="0A2E"/></Brand></SupportedSystems>
          </SoftwareComponent>
        </Manifest>
        """;

    [Fact]
    public void Dell_catalog_flags_the_newest_package_for_this_model_and_device()
    {
        InstalledDriver[] drivers =
        [
            new(@"PCI\VEN_8086&DEV_A0EF&SUBSYS_0A2E1028&REV_20\3&11583659&0&F8", @"PCI\VEN_8086&DEV_A0EF&SUBSYS_0A2E1028&REV_20", "Intel SMBus", "10.1.18.1"),
            new(@"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257\4&1", @"HDAUDIO\FUNC_01&VEN_10EC&DEV_0257", "Realtek Audio", "6.0.1.1"),
        ];
        var (updates, compared) = DellDriverCatalog.Evaluate(new StringReader(DellCatalog), "0A2E", drivers, win11: true, arm64: false);

        Assert.Equal(1, compared);
        var u = Assert.Single(updates);
        Assert.Equal("Intel Chipset Device Software", u.Title);
        Assert.Equal("Chipset", u.Category);
        Assert.Equal("10.1.18.1", u.InstalledVersion);
        Assert.Equal("10.1.19.8637", u.AvailableVersion);
        Assert.Equal("https://downloads.dell.com/FOLDER01/1/Intel-Chipset_AAA01_WIN64_10.1.19.exe", u.DownloadUrl);
        Assert.StartsWith("https://www.dell.com/support/", u.DetailsUrl);
    }

    [Fact]
    public void Driver_card_lists_windows_update_and_pc_maker_rows_together()
    {
        var wu = new PendingUpdateList([new("11111111-1111-1111-1111-111111111111", "Intel - Display - 32.0.101.7088", "", true, "Drivers", 1000, false, false, "", "Display")],
            RebootRequired: false, CheckedOnline: true);
        var scan = new VendorDriverScan("HP", [new("Intel Management Engine Driver", "Driver - Chipset", "2603.9.4", "2613.9.28", null,
            "https://ftp.hp.com/pub/softpaq/sp173748.exe", "https://ftp.hp.com/pub/softpaq/sp173748.html", 2048, "sp173748")], Compared: 12);

        var card = PendingUpdates.Card(wu, drivers: true, scan);

        Assert.Equal(PendingUpdates.DriverCardId, card.Id);
        Assert.Equal("2 driver updates waiting", card.Headline);
        Assert.Equal("1 from Windows Update · 1 newer from HP", card.Meta);
        Assert.Equal(2, card.Rows.Count);
        Assert.Equal(RemediationKind.InstallUpdate, Assert.Single(card.Rows[0].Actions!).Kind);
        var hp = card.Rows[1];
        Assert.Null(hp.Actions);
        Assert.Equal("Intel Management Engine Driver 2613.9.28", hp.Values[0]);
        Assert.Equal("Newer from HP (installed 2603.9.4)", hp.Values[1]);
        Assert.Equal("https://ftp.hp.com/pub/softpaq/sp173748.exe", hp.LinkUri);
        Assert.Equal("Download from HP", hp.LinkText);
        Assert.Contains("12 packages matched this PC", card.Note);
        Assert.Contains("checked online just now", card.Note);
        Assert.Equal(RemediationKind.CheckAndInstallDriverUpdates, Assert.Single(card.Actions!).Kind);
    }

    [Fact]
    public void Driver_card_says_why_the_pc_makers_catalog_was_not_read()
    {
        var card = PendingUpdates.Card(new PendingUpdateList([], false), drivers: true, VendorDriverScan.Failed("Lenovo", "Couldn't reach Lenovo's driver catalog."));
        Assert.Equal("No driver updates waiting", card.Headline);
        Assert.Equal(AreaLevel.Ok, card.Level);
        Assert.Contains("Lenovo: Couldn't reach Lenovo's driver catalog.", card.Note);
        Assert.Null(card.Actions);
    }

    [Fact]
    public void Driver_card_without_a_pc_maker_catalog_is_unchanged()
    {
        var list = new PendingUpdateList([], false);
        var card = PendingUpdates.Card(list, drivers: true, vendor: null);
        Assert.Equal("No driver updates waiting", card.Headline);
        Assert.Equal("As of Windows' last check with Windows Update", card.Meta);
        Assert.StartsWith("From Windows' last check", card.Note);
    }

    [Theory]
    [InlineData("26100", "24H2")]
    [InlineData("22631", "23H2")]
    [InlineData("26200", "25H2")]
    [InlineData("x", "")]
    public void Windows_release_from_the_build_number(string build, string release) =>
        Assert.Equal(release, WindowsDriverInventory.ReleaseForBuild(build));
}
