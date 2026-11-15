using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class WindowsRepairTests
{
    private const string DismOk = "Deployment Image Servicing and Management tool\n[==========================100.0%==========================]\nThe restore operation completed successfully.\nThe operation completed successfully.";

    [Fact]
    public void Dism_Success_IsOk() => Assert.Equal(DiagnosticStatus.Ok, WindowsRepair.ParseDism(DismOk, 0).Status);

    [Fact]
    public void Dism_3010_IsOkWithReboot()
    {
        var (st, sum, reboot) = WindowsRepair.ParseDism(DismOk, 3010);
        Assert.Equal(DiagnosticStatus.Ok, st);
        Assert.True(reboot);
        Assert.Contains("restart", sum);
    }

    [Theory]
    [InlineData("0x800f0915", "payload")]
    [InlineData("0x800f081f", "source")]
    [InlineData("0x800f0906", "internet")]
    [InlineData("0x800f0907", "policy")]
    [InlineData("0x800f0954", "policy")]
    [InlineData("0x80073712", "component store")]
    [InlineData("0x80070002", "path")]
    public void Dism_KnownErrors_HavePlainHints(string code, string word)
    {
        var (st, sum, _) = WindowsRepair.ParseDism($"Error: {code}\nThe operation failed.", 1);
        Assert.Equal(DiagnosticStatus.Error, st);
        Assert.Contains(code, sum, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(word, sum, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Dism_NegativeExitCode_FormatsAsHexWithoutNegativeDecimal()
    {
        // Exit code -2146498283 is 0x800F0915 (DISM_E_SOURCE_NOT_FOUND)
        const int exitCode = -2146498283;
        var (st, sum, _) = WindowsRepair.ParseDism("The operation failed.", exitCode);
        Assert.Equal(DiagnosticStatus.Error, st);
        Assert.Contains("0x800F0915", sum);
        Assert.DoesNotContain("-2146498283", sum);
        Assert.Contains("payload", sum, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Dism_WithDismLogExcerpt_ExtractsFailedPackageAndActionableSummary()
    {
        const string excerpt = @"
2026-11-15 12:34:56, Error DISM DISM Package Manager: PID=1234 TID=5678 Failed to download payload for package: Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.3570.1.7 - CPackageManagerRestoreHealthHandler::DownloadPackagePayload(hr:0x800f0915)
2026-11-15 12:34:56, Error DISM DISM Package Manager: PID=1234 TID=5678 The repair content could not be found anywhere: Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.3570.1.7 - CPackageManagerRestoreHealthHandler::DownloadPackagePayload(hr:0x800f0915)";

        var summary = WindowsRepair.SummarizeDism(excerpt);
        Assert.Contains("Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.3570.1.7", summary);
        Assert.Contains("Missing repair payload", summary);

        var (st, sum, _) = WindowsRepair.ParseDism("The operation failed.", -2146498283, excerpt);
        Assert.Equal(DiagnosticStatus.Error, st);
        Assert.Contains("Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.3570.1.7", sum);
        Assert.Contains("0x800F0915", sum);
    }

    [Fact]
    public void Dism_GenericNegativeExitCode_FormatsHex()
    {
        const int exitCode = unchecked((int)0x80004005); // E_FAIL
        var (st, sum, _) = WindowsRepair.ParseDism("Unknown failure", exitCode);
        Assert.Equal(DiagnosticStatus.Error, st);
        Assert.Contains("0x80004005", sum);
        Assert.DoesNotContain(exitCode.ToString(), sum);
    }

    [Fact]
    public void Dism_GenericFailure_IsError()
    {
        Assert.Equal(DiagnosticStatus.Error, WindowsRepair.ParseDism("Error: 87", 87).Status);
        Assert.Equal(DiagnosticStatus.Error, WindowsRepair.ParseDism("", null).Status);
    }

    [Fact]
    public void Sfc_Clean_IsOk() =>
        Assert.Equal(DiagnosticStatus.Ok, WindowsRepair.ParseSfc("Windows Resource Protection did not find any integrity violations.", 0).Status);

    [Fact]
    public void Sfc_Repaired_IsOkRepaired()
    {
        var (st, sum, _) = WindowsRepair.ParseSfc("Windows Resource Protection found corrupt files and successfully repaired them.", 0);
        Assert.Equal(DiagnosticStatus.Ok, st);
        Assert.Contains("repaired", sum);
    }

    [Fact]
    public void Sfc_UnableToFix_IsError() =>
        Assert.Equal(DiagnosticStatus.Error, WindowsRepair.ParseSfc("Windows Resource Protection found corrupt files but was unable to fix some of them.", 0).Status);

    [Fact]
    public void Sfc_Pending_IsRebootWarning()
    {
        var (st, _, reboot) = WindowsRepair.ParseSfc("There is a system repair pending which requires reboot to complete.", 0);
        Assert.Equal(DiagnosticStatus.Warning, st);
        Assert.True(reboot);
    }

    [Fact]
    public void Sfc_Localized_UsesExitCodeAndCbs()
    {
        const string german = "Der Windows-Ressourcenschutz hat keine Integritätsverletzungen gefunden.";
        Assert.Equal(DiagnosticStatus.Ok, WindowsRepair.ParseSfc(german, 0, ["2026-11-02 10:00:00, Info CSI 00000001 [SR] Verify complete"]).Status);
        Assert.Equal(DiagnosticStatus.Ok, WindowsRepair.ParseSfc(german, 0, ["... [SR] Repairing corrupted file \\??\\C:\\Windows\\x.dll"]).Status);
        Assert.Equal(DiagnosticStatus.Error, WindowsRepair.ParseSfc(german, 0, ["... [SR] Cannot repair member file x.dll"]).Status);
        Assert.Equal(DiagnosticStatus.Error, WindowsRepair.ParseSfc(german, 0).Status); // unknown without CBS evidence
    }

    [Fact]
    public void CleanOutput_StripsProgress()
    {
        var c = WindowsRepair.CleanOutput("Beginning\r\n[====  10.0%   ]\r\nVerification 45% complete.\r\nDone.\0");
        Assert.DoesNotContain("%", c);
        Assert.Contains("Beginning", c);
        Assert.Contains("Done.", c);
    }

    private static DiagnosticResult R(string module, DiagnosticStatus st, string msg = "x", bool cancelled = false) =>
        new(module, st, msg, DateTimeOffset.Now, new AreaReport([], msg, st, Cancelled: cancelled)) { Cancelled = cancelled };

    [Fact]
    public void Catalog_DismCorrupt_OffersBoth_DismFirst()
    {
        var fixes = FixCatalog.RepairFixes([R(DismScanHealthModule.ModuleName, DiagnosticStatus.Warning), R(SfcVerifyOnlyModule.ModuleName, DiagnosticStatus.Ok)]);
        Assert.Equal([RemediationKind.RepairComponentStore, RemediationKind.RepairSystemFiles], fixes.OrderBy(f => f.Order).Select(f => f.Remediation!.Kind));
        Assert.All(fixes, f => { Assert.True(f.DefaultOn); Assert.True(f.NeedsAdmin); Assert.Equal(UndoSupport.None, f.Undo); });
    }

    [Fact]
    public void Catalog_SfcOnly_OffersSfc() =>
        Assert.Equal(RemediationKind.RepairSystemFiles, Assert.Single(FixCatalog.RepairFixes([R(SfcVerifyOnlyModule.ModuleName, DiagnosticStatus.Warning)])).Remediation!.Kind);

    [Fact]
    public void Catalog_CleanOrCancelled_OffersNothing()
    {
        Assert.Empty(FixCatalog.RepairFixes([R(DismScanHealthModule.ModuleName, DiagnosticStatus.Ok), R(SfcVerifyOnlyModule.ModuleName, DiagnosticStatus.Ok)]));
        Assert.Empty(FixCatalog.RepairFixes([R(DismScanHealthModule.ModuleName, DiagnosticStatus.Warning, "Scan cancelled", cancelled: true)]));
    }

    [Fact]
    public void Catalog_CannotBeRepaired_StillOffered_NeedsSource()
    {
        var fix = FixCatalog.RepairFixes([R(DismScanHealthModule.ModuleName, DiagnosticStatus.Warning, DismScanHealthModule.CannotBeRepairedSummary)])
            .Single(f => f.Remediation!.Kind == RemediationKind.RepairComponentStore);
        Assert.Equal("needs-source", fix.Remediation!.Target);
    }
}
