using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.Workflow;

public enum HardwareQaVerdict
{
    CertifiedPass,
    PassedWithNotes,
    AttentionRequired,
    IntakeSnapshot,
}

public sealed record HardwareQaItem(
    string Id,
    string Label,
    DiagnosticStatus Status,
    string Summary,
    bool Cancelled = false);

public sealed record HardwareQaSnapshot(
    string CertificateId,
    string VerificationHash,
    string QrPayload,
    DateTimeOffset Generated,
    string MachineName,
    string ManufacturerModel,
    string SerialNumber,
    string Processor,
    string Memory,
    string Storage,
    string OperatingSystem,
    HardwareQaVerdict Verdict,
    IReadOnlyList<HardwareQaItem> Items,
    ShopBranding? Branding = null)
{
    public int TestedCount => Items.Count(i => IsTested(i));
    public int PassedCount => Items.Count(i => i.Status == DiagnosticStatus.Ok && !i.Cancelled);
    public int WarningCount => Items.Count(i => i.Status == DiagnosticStatus.Warning && !i.Cancelled);
    public int ErrorCount => Items.Count(i => i.Status == DiagnosticStatus.Error && !i.Cancelled);

    private static bool IsTested(HardwareQaItem i) =>
        i.Status is DiagnosticStatus.Ok or DiagnosticStatus.Warning or DiagnosticStatus.Error && !i.Cancelled;
}

/// <summary>
/// Builds a self-contained, 1-page printable Buyer Hardware QA Certificate with an inline ISO/IEC 18004 vector QR badge and tamper-evident
/// SHA-256 digest for laptop refurbishers (eBay, Swappa, BackMarket) and repair shop bench QA — with zero hardware audio/USB dongles.
/// </summary>
public static class HardwareQaCertificate
{
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    public static HardwareQaSnapshot Capture(
        ResultStore store,
        string machineName,
        DateTimeOffset? generated = null,
        ShopBranding? branding = null,
        string? operatingSystem = null,
        bool includeNpuWhenNotRun = false,
        PhysicalBenchQaSnapshot? physicalQa = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        var when = generated ?? DateTimeOffset.Now;
        var normBrand = branding?.Normalized();

        var hwRes = store.Get(ModuleSlugs.Osquery);
        var inv = hwRes.Report() as HardwareInventory;
        var sys = inv?.System.Items.FirstOrDefault();

        var resolvedMachine = !string.IsNullOrWhiteSpace(machineName)
            ? machineName.Trim()
            : sys is { ComputerName.Length: > 0 } cn ? cn.ComputerName
            : sys is { Hostname.Length: > 0 } hn ? hn.Hostname
            : "Windows PC";

        var vendorModel = sys is not null ? $"{sys.HardwareVendor} {sys.HardwareModel}".Trim() : "";
        if (string.IsNullOrWhiteSpace(vendorModel) && sys is not null)
            vendorModel = $"{sys.BoardVendor} {sys.BoardModel}".Trim();
        if (string.IsNullOrWhiteSpace(vendorModel))
            vendorModel = "Not reported";

        var serial = sys is { HardwareSerial.Length: > 0 } hs && !IsPlaceholderSerial(hs.HardwareSerial)
            ? hs.HardwareSerial
            : sys is { BoardSerial.Length: > 0 } bs && !IsPlaceholderSerial(bs.BoardSerial)
                ? bs.BoardSerial
                : "Not reported";

        var cpuItem = inv?.Cpus.Items.FirstOrDefault();
        var cpuName = cpuItem is { Model.Length: > 0 } cm ? cm.Model : sys?.CpuBrand ?? "";
        var cores = cpuItem?.NumberOfCores ?? sys?.CpuPhysicalCores;
        var threads = cpuItem?.LogicalProcessors ?? sys?.CpuLogicalCores;
        var processor = string.IsNullOrWhiteSpace(cpuName)
            ? "Not reported"
            : cores is > 0 && threads is > 0
                ? $"{cpuName} ({cores}C / {threads}T)"
                : cores is > 0 ? $"{cpuName} ({cores} cores)" : cpuName;

        var memory = FormatMemorySpec(inv);
        var storage = FormatStorageSpec(inv);
        var os = !string.IsNullOrWhiteSpace(operatingSystem) ? operatingSystem.Trim() : RuntimeInformation.OSDescription;

        var items = new List<HardwareQaItem>
        {
            BuildSimpleItem("hardware", "System & SMBIOS inventory", hwRes,
                inv is { FailedSections: 0 } ? $"{vendorModel} · S/N {serial}" : null),
            BuildAreaItem("battery", "Battery & power health", store.Get(ModuleSlugs.BatteryPower)),
            BuildAreaItem("smart", "Storage S.M.A.R.T. health", store.Get(ModuleSlugs.DriveHealth)),
            BuildSensorsItem(store.Get(ModuleSlugs.Sensors)),
            BuildStabilityItem(store),
            BuildSimpleItem("cpu-stress", "CPU stress verification", store.Get(ModuleSlugs.CpuStress)),
            BuildSimpleItem("ram-test", "Memory (RAM) verification", store.Get(ModuleSlugs.MemoryTest)),
            BuildDiskSpeedItem(store.Get(ModuleSlugs.DiskSpeed)),
            BuildSimpleItem("gpu-stress", "Graphics (GPU) stress verification", store.Get(ModuleSlugs.GpuStress)),
            BuildAudioItem(store.Get(ModuleSlugs.SpeakerToMic), store.Get(ModuleSlugs.MicToSpeaker)),
            BuildSimpleItem("webcam", "Camera frame & exposure check", store.Get(ModuleSlugs.Webcam)),
            BuildKeyboardItem(physicalQa),
            BuildDisplayItem(physicalQa),
        };

        var npu = store.Get(ModuleSlugs.NpuTest);
        if (includeNpuWhenNotRun || npu.Status != DiagnosticStatus.NotRun)
            items.Add(BuildSimpleItem("npu", "AI accelerator (NPU)", npu));

        items.Add(BuildAreaItem("drivers", "Device drivers", store.Get(ModuleSlugs.DeviceDrivers)));
        items.Add(BuildIntegrityItem(store.Get(ModuleSlugs.DismScanHealth), store.Get(ModuleSlugs.SfcVerifyOnly)));

        var verdict = ComputeVerdict(items);
        var digestHex = ComputeVerificationHash(when, resolvedMachine, vendorModel, serial, verdict, items);
        var shortHash = digestHex[..12].ToUpperInvariant();
        var certId = $"QA-{when.UtcDateTime:yyyyMMdd}-{digestHex[..6].ToUpperInvariant()}";
        var qrPayload = BuildQrPayload(certId, shortHash, vendorModel, resolvedMachine, serial, verdict, when, normBrand);

        return new HardwareQaSnapshot(
            CertificateId: certId,
            VerificationHash: digestHex,
            QrPayload: qrPayload,
            Generated: when,
            MachineName: resolvedMachine,
            ManufacturerModel: vendorModel,
            SerialNumber: serial,
            Processor: processor,
            Memory: memory,
            Storage: storage,
            OperatingSystem: os,
            Verdict: verdict,
            Items: items,
            Branding: normBrand);
    }

    public static string BuildHtml(HardwareQaSnapshot s)
    {
        ArgumentNullException.ThrowIfNull(s);
        var b = s.Branding?.Normalized();
        var shopTitle = b?.ShopName is { Length: > 0 } sn ? sn : "Hardware QA Certificate";
        var (badgeBg, badgeBorder, badgeFg, verdictTitle, verdictSub) = s.Verdict switch
        {
            HardwareQaVerdict.CertifiedPass => (
                "#ecfdf5", "#10b981", "#065f46",
                "CERTIFIED HARDWARE PASS",
                $"{s.PassedCount} of {s.TestedCount} verified subsystems passed with zero errors or warnings."),
            HardwareQaVerdict.PassedWithNotes => (
                "#fffbeb", "#f59e0b", "#92400e",
                "PASSED WITH ADVISORY NOTES",
                $"{s.PassedCount} passed · {s.WarningCount} advisory note{(s.WarningCount == 1 ? "" : "s")} · 0 failures."),
            HardwareQaVerdict.AttentionRequired => (
                "#fef2f2", "#ef4444", "#991b1b",
                "ATTENTION REQUIRED",
                $"{s.ErrorCount} subsystem failure{(s.ErrorCount == 1 ? "" : "s")} detected during bench QA."),
            _ => (
                "#f8fafc", "#94a3b8", "#334155",
                "BENCH INTAKE SNAPSHOT",
                $"{s.TestedCount} of {s.Items.Count} subsystems checked so far — run full checks + stress suite for complete certification."),
        };

        var qrSvg = QrCodeSvg.Render(s.QrPayload, quietZoneModules: 2, ariaLabel: $"Hardware QA verification QR code {s.CertificateId}");
        var sb = new StringBuilder(14_000);

        sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
          .Append("<title>").Append(E(shopTitle)).Append(" – ").Append(E(s.ManufacturerModel != "Not reported" ? s.ManufacturerModel : s.MachineName)).Append(" (").Append(E(s.CertificateId)).Append(")</title><style>")
          .Append("@page{size:auto;margin:10mm}")
          .Append("*{box-sizing:border-box}body{font-family:Segoe UI,system-ui,-apple-system,sans-serif;color:#111827;max-width:860px;margin:20px auto;padding:0 18px;line-height:1.4;background:#fff}")
          .Append(".cert-shell{border:2px solid #e5e7eb;border-radius:14px;padding:20px 22px}")
          .Append(".top-row{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;border-bottom:1px solid #e5e7eb;padding-bottom:14px;margin-bottom:14px}")
          .Append(".brand-block{display:flex;align-items:center;gap:14px;min-width:0}")
          .Append(".shop-logo{max-height:54px;max-width:160px;object-fit:contain;border-radius:6px}")
          .Append("h1{font-size:21px;margin:0;line-height:1.2}.sub{color:#4b5563;font-size:12.5px;margin-top:3px}")
          .Append(".qr-card{display:flex;align-items:center;gap:10px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:8px 10px;flex-shrink:0}")
          .Append(".qr-box{width:84px;height:84px;flex-shrink:0}.qr-box svg{width:100%;height:100%;display:block}")
          .Append(".qr-meta{font-size:11px;color:#374151;max-width:155px}.qr-id{font-weight:700;font-family:Consolas,monospace;font-size:12px;color:#111827}")
          .Append(".verdict{display:flex;justify-content:space-between;align-items:center;gap:12px;border-radius:10px;padding:12px 16px;margin-bottom:14px;background:")
          .Append(badgeBg).Append(";border:1.5px solid ").Append(badgeBorder).Append(";color:").Append(badgeFg).Append('}')
          .Append(".verdict strong{font-size:17px;letter-spacing:.02em;display:block}.verdict span{font-size:13px}")
          .Append(".specs{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px 12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:12.5px}")
          .Append(".spec-k{font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;color:#64748b;font-weight:600}.spec-v{font-weight:600;color:#0f172a;overflow-wrap:anywhere}")
          .Append("table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e5e7eb;vertical-align:middle}")
          .Append("th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;background:#f9fafb}")
          .Append(".pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap}")
          .Append(".pill-ok{background:#d1fae5;color:#065f46}.pill-warn{background:#fef3c7;color:#92400e}.pill-err{background:#fee2e2;color:#991b1b}.pill-na{background:#f1f5f9;color:#475569}")
          .Append(".notes{background:#f8fafc;border-left:3px solid #3b82f6;padding:8px 12px;margin-top:12px;font-size:12.5px;border-radius:0 8px 8px 0}")
          .Append(".footer{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-top:14px;padding-top:10px;border-top:1px solid #e5e7eb;font-size:11.5px;color:#4b5563}")
          .Append(".hash{font-family:Consolas,monospace;font-size:10.5px;color:#6b7280}")
          .Append("@media print{body{margin:0;padding:0}.cert-shell{border-width:1.5px;padding:14px 16px}}")
          .Append("</style></head><body><div class=\"cert-shell\" data-testid=\"qa-certificate\">");

        // Header: Shop Branding + Scannable QR Badge
        sb.Append("<div class=\"top-row\"><div class=\"brand-block\" data-testid=\"qa-brand-header\">");
        if (b?.SafeLogoDataUri is { } logo)
            sb.Append("<img class=\"shop-logo\" data-testid=\"qa-shop-logo\" src=\"").Append(E(logo)).Append("\" alt=\"").Append(E(b.ShopName ?? "Shop logo")).Append("\">");
        sb.Append("<div><h1>").Append(E(b?.ShopName is { Length: > 0 } n ? $"{n} — Hardware QA Certificate" : "Hardware QA Certificate")).Append("</h1>");
        var contactParts = BuildContactParts(b);
        if (contactParts.Count > 0)
            sb.Append("<div class=\"sub\">").Append(string.Join(" · ", contactParts)).Append("</div>");
        sb.Append("<div class=\"sub\">Issued ").Append(E(s.Generated.ToString("yyyy-MM-dd HH:mm zzz", System.Globalization.CultureInfo.InvariantCulture)));
        if (b?.TechnicianName is { Length: > 0 } tech)
            sb.Append(" · Verified by ").Append(E(tech));
        sb.Append("</div></div></div>");

        sb.Append("<div class=\"qr-card\" data-testid=\"qa-qr-badge\"><div class=\"qr-box\">").Append(qrSvg).Append("</div><div class=\"qr-meta\">")
          .Append("<div class=\"qr-id\" data-testid=\"qa-cert-id\">").Append(E(s.CertificateId)).Append("</div>")
          .Append("<div>Scan to verify hardware serial &amp; QA digest</div>")
          .Append("<div class=\"hash\">SHA-256: ").Append(E(s.VerificationHash[..12].ToUpperInvariant())).Append("</div>")
          .Append("</div></div></div>");

        // Verdict Banner
        sb.Append("<div class=\"verdict\" data-testid=\"qa-verdict\"><div><strong>").Append(E(verdictTitle)).Append("</strong><span>")
          .Append(E(verdictSub)).Append("</span></div></div>");

        // Hardware Identity Grid
        sb.Append("<div class=\"specs\" data-testid=\"qa-specs\">")
          .Append("<div><div class=\"spec-k\">System model</div><div class=\"spec-v\">").Append(E(s.ManufacturerModel)).Append("</div></div>")
          .Append("<div><div class=\"spec-k\">Serial / Service Tag</div><div class=\"spec-v\" data-testid=\"qa-serial\">").Append(E(s.SerialNumber)).Append("</div></div>")
          .Append("<div><div class=\"spec-k\">Computer name</div><div class=\"spec-v\">").Append(E(s.MachineName)).Append("</div></div>")
          .Append("<div><div class=\"spec-k\">Processor</div><div class=\"spec-v\">").Append(E(s.Processor)).Append("</div></div>")
          .Append("<div><div class=\"spec-k\">Installed memory</div><div class=\"spec-v\">").Append(E(s.Memory)).Append("</div></div>")
          .Append("<div><div class=\"spec-k\">Storage</div><div class=\"spec-v\">").Append(E(s.Storage)).Append("</div></div>")
          .Append("</div>");

        // Subsystem Verification Table
        sb.Append("<table data-testid=\"qa-items-table\"><thead><tr><th>Subsystem</th><th>Status</th><th>Measured result</th></tr></thead><tbody>");
        foreach (var item in s.Items)
        {
            var (pillCls, pillText) = item.Cancelled
                ? ("pill-na", "STOPPED")
                : item.Status switch
                {
                    DiagnosticStatus.Ok => ("pill-ok", "PASS"),
                    DiagnosticStatus.Warning => ("pill-warn", "NOTE"),
                    DiagnosticStatus.Error => ("pill-err", "FAIL"),
                    DiagnosticStatus.Running => ("pill-na", "RUNNING"),
                    _ => ("pill-na", "NOT RUN"),
                };
            sb.Append("<tr data-qa-item=\"").Append(E(item.Id)).Append("\"><td><strong>").Append(E(item.Label)).Append("</strong></td>")
              .Append("<td><span class=\"pill ").Append(pillCls).Append("\">").Append(pillText).Append("</span></td>")
              .Append("<td>").Append(E(item.Summary)).Append("</td></tr>");
        }
        sb.Append("</tbody></table>");

        if (b?.TechnicianNotes is { Length: > 0 } notes)
        {
            sb.Append("<div class=\"notes\" data-testid=\"qa-tech-notes\"><strong>Technician QA notes:</strong> ").Append(E(notes)).Append("</div>");
        }

        sb.Append("<div class=\"footer\"><div>");
        if (b?.WarrantyFooter is { Length: > 0 } warranty)
            sb.Append("<div data-testid=\"qa-warranty\"><strong>").Append(E(warranty)).Append("</strong></div>");
        sb.Append("<div>Generated locally on ").Append(E(s.OperatingSystem)).Append(" by ")
          .Append(E(b?.ShopName is { Length: > 0 } shop ? $"{shop} (Remote PC Diagnostics)" : "Remote PC Diagnostics")).Append(".</div></div>")
          .Append("<div class=\"hash\">Digest: ").Append(E(s.VerificationHash[..24])).Append("…</div></div>")
          .Append("</div></body></html>");

        return sb.ToString();
    }

    internal static List<string> BuildContactParts(ShopBranding? b)
    {
        var parts = new List<string>(4);
        if (b is null) return parts;
        if (!string.IsNullOrWhiteSpace(b.Phone)) parts.Add(E(b.Phone));
        if (!string.IsNullOrWhiteSpace(b.Email)) parts.Add(E(b.Email));
        if (b.SafeWebsiteHref is { } href && !string.IsNullOrWhiteSpace(b.Website))
            parts.Add($"<a href=\"{E(href)}\" style=\"color:inherit\">{E(b.Website.Trim())}</a>");
        if (!string.IsNullOrWhiteSpace(b.Address)) parts.Add(E(b.Address));
        return parts;
    }

    private static HardwareQaVerdict ComputeVerdict(IReadOnlyList<HardwareQaItem> items)
    {
        var tested = items.Where(i => !i.Cancelled && i.Status is DiagnosticStatus.Ok or DiagnosticStatus.Warning or DiagnosticStatus.Error).ToList();
        if (tested.Any(i => i.Status == DiagnosticStatus.Error)) return HardwareQaVerdict.AttentionRequired;
        if (tested.Any(i => i.Status == DiagnosticStatus.Warning)) return HardwareQaVerdict.PassedWithNotes;
        return tested.Count >= 4 ? HardwareQaVerdict.CertifiedPass : HardwareQaVerdict.IntakeSnapshot;
    }

    private static string ComputeVerificationHash(
        DateTimeOffset when, string machine, string model, string serial, HardwareQaVerdict verdict, IReadOnlyList<HardwareQaItem> items)
    {
        var canonical = new StringBuilder(512);
        canonical.Append("RPD-QA-V1|")
                 .Append(when.UtcDateTime.ToString("O")).Append('|')
                 .Append(machine).Append('|')
                 .Append(model).Append('|')
                 .Append(serial).Append('|')
                 .Append(verdict);
        foreach (var item in items)
            canonical.Append('|').Append(item.Id).Append(':').Append(item.Cancelled ? "Cancelled" : item.Status.ToString()).Append(':').Append(item.Summary);

        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString()));
        return Convert.ToHexStringLower(bytes);
    }

    private static string BuildQrPayload(
        string certId, string shortHash, string model, string machine, string serial,
        HardwareQaVerdict verdict, DateTimeOffset when, ShopBranding? branding)
    {
        if (branding?.SafeVerificationBaseUrl is { } baseUrl)
        {
            var url = $"{baseUrl}/{Uri.EscapeDataString(certId)}?h={shortHash}";
            if (Encoding.UTF8.GetByteCount(url) <= QrCodeSvg.MaxUtf8Bytes)
                return url;
        }

        var vCode = verdict switch
        {
            HardwareQaVerdict.CertifiedPass => "PASS",
            HardwareQaVerdict.PassedWithNotes => "WARN",
            HardwareQaVerdict.AttentionRequired => "FAIL",
            _ => "INTAKE",
        };
        var hwLabel = TruncateAsciiSafe(model != "Not reported" ? model : machine, 42);
        var snLabel = TruncateAsciiSafe(serial, 32);
        var payload = $"RPD-QA|{certId}|{hwLabel}|SN:{snLabel}|{vCode}|{when.UtcDateTime:yyyy-MM-dd}|{shortHash}";
        if (Encoding.UTF8.GetByteCount(payload) <= QrCodeSvg.MaxUtf8Bytes)
            return payload;

        return $"RPD-QA|{certId}|{vCode}|{shortHash}";
    }

    private static string TruncateAsciiSafe(string value, int maxChars)
    {
        var clean = value.Replace('|', '/').Trim();
        return clean.Length <= maxChars ? clean : clean[..maxChars].TrimEnd();
    }

    private static bool IsPlaceholderSerial(string s)
    {
        var t = s.Trim();
        return t.Length == 0
            || t.Equals("To be filled by O.E.M.", StringComparison.OrdinalIgnoreCase)
            || t.Equals("Default string", StringComparison.OrdinalIgnoreCase)
            || t.Equals("System Serial Number", StringComparison.OrdinalIgnoreCase)
            || t.Equals("None", StringComparison.OrdinalIgnoreCase)
            || t.Equals("0", StringComparison.OrdinalIgnoreCase);
    }

    private static string FormatMemorySpec(HardwareInventory? inv)
    {
        if (inv is null || inv.TotalMemoryBytes is not > 0) return "Not reported";
        var total = HardwareInventory.FormatBytes(inv.TotalMemoryBytes);
        var sticks = inv.Memory.Items.Where(m => m.IsPopulated).ToList();
        if (sticks.Count == 0) return total;
        var speed = sticks.Select(s => s.ConfiguredClockSpeedMts ?? s.MaxSpeedMts).FirstOrDefault(v => v is > 0);
        var memType = sticks.Select(s => s.MemoryType).FirstOrDefault(t => !string.IsNullOrWhiteSpace(t) && !t.Equals("Unknown", StringComparison.OrdinalIgnoreCase));
        var extra = new List<string> { $"{sticks.Count} DIMM{(sticks.Count == 1 ? "" : "s")}" };
        if (!string.IsNullOrWhiteSpace(memType)) extra.Add(memType);
        if (speed is > 0) extra.Add($"{speed} MT/s");
        return $"{total} ({string.Join(", ", extra)})";
    }

    private static string FormatStorageSpec(HardwareInventory? inv)
    {
        if (inv is null || inv.Disks.Items.Count == 0) return "Not reported";
        var parts = inv.Disks.Items.Take(2).Select(d =>
        {
            var name = !string.IsNullOrWhiteSpace(d.HardwareModel) ? d.HardwareModel
                : !string.IsNullOrWhiteSpace(d.Name) ? d.Name : "Drive";
            return d.SizeBytes is > 0 ? $"{name} ({HardwareInventory.FormatBytes(d.SizeBytes)})" : name;
        }).ToList();
        if (inv.Disks.Items.Count > 2) parts.Add($"+{inv.Disks.Items.Count - 2} more");
        return string.Join("; ", parts);
    }

    private static HardwareQaItem BuildSimpleItem(string id, string label, DiagnosticResult r, string? okOverride = null)
    {
        var summary = r.Status == DiagnosticStatus.NotRun ? "Not run yet"
            : r.Status == DiagnosticStatus.Ok && !string.IsNullOrWhiteSpace(okOverride) ? okOverride
            : string.IsNullOrWhiteSpace(r.Message) ? r.Status.ToString() : r.Message;
        return new HardwareQaItem(id, label, r.Status, summary, r.Cancelled);
    }

    private static HardwareQaItem BuildAreaItem(string id, string label, DiagnosticResult r)
    {
        if (r.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem(id, label, DiagnosticStatus.NotRun, "Not run yet");
        var summary = r.Report() is AreaReport ar && !string.IsNullOrWhiteSpace(ar.Summary) ? ar.Summary : r.Message;
        return new HardwareQaItem(id, label, r.Status, summary, r.Cancelled);
    }

    private static HardwareQaItem BuildSensorsItem(DiagnosticResult r)
    {
        if (r.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem("sensors", "Thermal & cooling sensors", DiagnosticStatus.NotRun, "Not run yet");
        if (r.Report() is SensorReport sr)
        {
            var cpu = sr.Groups.FirstOrDefault(g => g.Id == "cpu")?.Hottest;
            var gpu = sr.Groups.FirstOrDefault(g => g.Id == "gpu")?.Hottest;
            var temps = new List<string>();
            if (cpu is { } c) temps.Add($"CPU {c:0.#} °C");
            if (gpu is { } g) temps.Add($"GPU {g:0.#} °C");
            if (temps.Count > 0)
                return new HardwareQaItem("sensors", "Thermal & cooling sensors", r.Status, $"{string.Join(" · ", temps)} ({r.Message})", r.Cancelled);
        }
        return new HardwareQaItem("sensors", "Thermal & cooling sensors", r.Status, r.Message, r.Cancelled);
    }

    private static HardwareQaItem BuildDiskSpeedItem(DiagnosticResult r)
    {
        if (r.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem("disk-speed", "Storage read/write verification", DiagnosticStatus.NotRun, "Not run yet");
        if (r.Report() is DiskSpeedReport dr && dr.SequentialReadMBps is { } sr && dr.SequentialWriteMBps is { } sw)
            return new HardwareQaItem("disk-speed", "Storage read/write verification", r.Status,
                $"Seq read {sr:0} MB/s · Seq write {sw:0} MB/s · {dr.DataErrors} data errors", r.Cancelled);
        return new HardwareQaItem("disk-speed", "Storage read/write verification", r.Status, r.Message, r.Cancelled);
    }

    private static HardwareQaItem BuildAudioItem(DiagnosticResult spkToMic, DiagnosticResult micToSpk)
    {
        if (spkToMic.Status == DiagnosticStatus.NotRun && micToSpk.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem("audio", "Audio loopback (speaker & mic)", DiagnosticStatus.NotRun, "Not run yet (dongle-free WASAPI check)");

        if (spkToMic.Status != DiagnosticStatus.NotRun && micToSpk.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem("audio", "Audio loopback (speaker & mic)", spkToMic.Status, spkToMic.Message, spkToMic.Cancelled);
        if (micToSpk.Status != DiagnosticStatus.NotRun && spkToMic.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem("audio", "Audio loopback (speaker & mic)", micToSpk.Status, micToSpk.Message, micToSpk.Cancelled);

        var worst = CombineStatus(spkToMic.Status, micToSpk.Status);
        var cancelled = spkToMic.Cancelled && micToSpk.Cancelled;
        return new HardwareQaItem("audio", "Audio loopback (speaker & mic)", worst,
            $"Speaker→Mic: {spkToMic.Message} · Mic→Speaker: {micToSpk.Message}", cancelled);
    }

    private static HardwareQaItem BuildIntegrityItem(DiagnosticResult dism, DiagnosticResult sfc)
    {
        if (dism.Status == DiagnosticStatus.NotRun && sfc.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem("integrity", "Windows image & SFC integrity", DiagnosticStatus.NotRun, "Not run yet");
        if (dism.Status != DiagnosticStatus.NotRun && sfc.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem("integrity", "Windows image & SFC integrity", dism.Status, $"DISM: {dism.Message}", dism.Cancelled);
        if (sfc.Status != DiagnosticStatus.NotRun && dism.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem("integrity", "Windows image & SFC integrity", sfc.Status, $"SFC: {sfc.Message}", sfc.Cancelled);

        var worst = CombineStatus(dism.Status, sfc.Status);
        return new HardwareQaItem("integrity", "Windows image & SFC integrity", worst,
            $"DISM: {dism.Message} · SFC: {sfc.Message}", dism.Cancelled && sfc.Cancelled);
    }

    private static HardwareQaItem BuildStabilityItem(ResultStore store)
    {
        const string id = "stability";
        const string label = "Crash & WHEA hardware log (30d)";

        var crashes = store.Get(ModuleSlugs.Crashes);
        if (crashes.Status != DiagnosticStatus.NotRun && crashes.Report() is AreaReport crashRep)
        {
            var sysCards = crashRep.Cards.Where(c => c.Id is "bsods" or "power" or "whea").ToList();
            if (sysCards.Count > 0)
            {
                if (sysCards.All(c => c.ErrorText is not null))
                    return new HardwareQaItem(id, label, DiagnosticStatus.Warning, "Couldn't read blue screen and WHEA history", crashes.Cancelled);

                var readable = sysCards.Where(c => c.ErrorText is null).ToList();
                var status = AreaReport.Worst(readable.Select(c => c.Level));
                if (sysCards.Any(c => c.ErrorText is not null) && status == DiagnosticStatus.Ok)
                    status = DiagnosticStatus.Warning;
                return new HardwareQaItem(id, label, status, SummarizeStabilityCards(sysCards), crashes.Cancelled);
            }
        }

        var bsod = store.Get(ModuleSlugs.BsodHistory);
        if (bsod.Status == DiagnosticStatus.NotRun)
            return new HardwareQaItem(id, label, DiagnosticStatus.NotRun, "Not run yet");
        if (bsod.Report() is AreaReport bsodRep)
        {
            var sysCards = bsodRep.Cards.Where(c => c.Id is "bsods" or "power" or "whea").ToList();
            if (sysCards.Count > 0)
            {
                var readable = sysCards.Where(c => c.ErrorText is null).ToList();
                var status = readable.Count > 0 ? AreaReport.Worst(readable.Select(c => c.Level)) : bsod.Status;
                return new HardwareQaItem(id, label, status, SummarizeStabilityCards(sysCards), bsod.Cancelled);
            }
            return BuildAreaItem(id, label, bsod);
        }
        return BuildSimpleItem(id, label, bsod);
    }

    private static string SummarizeStabilityCards(IReadOnlyList<AreaCard> sysCards)
    {
        var bsod = sysCards.FirstOrDefault(c => c.Id == "bsods");
        var power = sysCards.FirstOrDefault(c => c.Id == "power");
        var whea = sysCards.FirstOrDefault(c => c.Id == "whea");
        var parts = new List<string>(3);
        if (bsod is { Rows.Count: > 0 }) parts.Add(bsod.Headline);
        if (power is { Rows.Count: > 0 }) parts.Add(power.Headline);
        if (whea is { Rows.Count: > 0 }) parts.Add($"WHEA: {whea.Headline}");
        return parts.Count == 0
            ? "No BSODs, unexpected power losses, or WHEA hardware errors"
            : string.Join(" · ", parts);
    }

    private static HardwareQaItem BuildKeyboardItem(PhysicalBenchQaSnapshot? qa)
    {
        const string id = "keyboard";
        const string label = "Keyboard matrix & rollover";
        var outcome = qa?.KeyboardOutcome ?? PhysicalCheckOutcome.NotRun;
        var status = MapPhysicalOutcome(outcome);
        if (status == DiagnosticStatus.NotRun)
        {
            var summary = qa is { UniqueKeysPressed: > 0 }
                ? $"In progress ({qa.UniqueKeysPressed} {(qa.UniqueKeysPressed == 1 ? "key" : "keys")} pressed · {qa.PeakKeyRollover}-key rollover) — mark Pass or Fail"
                : "Not run yet (interactive bench check)";
            return new HardwareQaItem(id, label, DiagnosticStatus.NotRun, summary);
        }

        var parts = new List<string>(3);
        if (qa is { UniqueKeysPressed: > 0 })
            parts.Add($"{qa.UniqueKeysPressed} {(qa.UniqueKeysPressed == 1 ? "key" : "keys")} verified");
        if (qa is { PeakKeyRollover: > 0 })
            parts.Add($"{qa.PeakKeyRollover}-key rollover");
        if (!string.IsNullOrWhiteSpace(qa?.KeyboardNotes))
            parts.Add(qa.KeyboardNotes.Trim());
        if (parts.Count == 0)
            parts.Add(status == DiagnosticStatus.Ok ? "Verified by technician" : status == DiagnosticStatus.Warning ? "Passed with note" : "Failed inspection");

        return new HardwareQaItem(id, label, status, string.Join(" · ", parts));
    }

    private static HardwareQaItem BuildDisplayItem(PhysicalBenchQaSnapshot? qa)
    {
        const string id = "display";
        const string label = "Display dead-pixel & touch check";
        var outcome = qa?.DisplayOutcome ?? PhysicalCheckOutcome.NotRun;
        var status = MapPhysicalOutcome(outcome);
        if (status == DiagnosticStatus.NotRun)
        {
            var summary = qa is { SolidColorsInspected: > 0 }
                ? $"In progress ({qa.SolidColorsInspected} test {(qa.SolidColorsInspected == 1 ? "pattern" : "patterns")} inspected) — mark Pass or Fail"
                : "Not run yet (interactive bench check)";
            return new HardwareQaItem(id, label, DiagnosticStatus.NotRun, summary);
        }

        var parts = new List<string>(3);
        if (qa is { SolidColorsInspected: > 0 })
            parts.Add($"{qa.SolidColorsInspected} test {(qa.SolidColorsInspected == 1 ? "pattern" : "patterns")} inspected");
        if (qa is { MaxTouchPoints: > 0 })
            parts.Add($"{qa.MaxTouchPoints}-point touch verified");
        if (!string.IsNullOrWhiteSpace(qa?.DisplayNotes))
            parts.Add(qa.DisplayNotes.Trim());
        if (parts.Count == 0)
            parts.Add(status == DiagnosticStatus.Ok ? "Panel verified clean" : status == DiagnosticStatus.Warning ? "Minor blemish noted" : "Panel defect detected");

        return new HardwareQaItem(id, label, status, string.Join(" · ", parts));
    }

    private static DiagnosticStatus MapPhysicalOutcome(PhysicalCheckOutcome outcome) => outcome switch
    {
        PhysicalCheckOutcome.Passed => DiagnosticStatus.Ok,
        PhysicalCheckOutcome.PassedWithNote => DiagnosticStatus.Warning,
        PhysicalCheckOutcome.Failed => DiagnosticStatus.Error,
        _ => DiagnosticStatus.NotRun,
    };

    private static DiagnosticStatus CombineStatus(DiagnosticStatus a, DiagnosticStatus b)
    {
        if (a == DiagnosticStatus.Error || b == DiagnosticStatus.Error) return DiagnosticStatus.Error;
        if (a == DiagnosticStatus.Warning || b == DiagnosticStatus.Warning) return DiagnosticStatus.Warning;
        if (a == DiagnosticStatus.Running || b == DiagnosticStatus.Running) return DiagnosticStatus.Running;
        if (a == DiagnosticStatus.Ok || b == DiagnosticStatus.Ok) return DiagnosticStatus.Ok;
        return DiagnosticStatus.NotRun;
    }
}
