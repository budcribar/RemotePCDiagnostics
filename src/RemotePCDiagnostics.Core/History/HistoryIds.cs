using System.Security.Cryptography;
using System.Text;

namespace RemotePCDiagnostics.Core.History;

/// <summary>
/// The "Module id" written with every History event. Modules use their own <see cref="IDiagnosticModule.Id"/>; the fix and service
/// records that History also shows get fixed ids here. Like module ids, these never change.
/// </summary>
public static class HistoryIds
{
    /// <summary>Automated fixes (<see cref="HistorySummary.RemediationModuleId"/>).</summary>
    public static readonly Guid Remediation = new("14b93733-0680-46f4-a10e-8926b844d4e7");
    /// <summary>Service start/stop/restart (<see cref="HistorySummary.ServiceFixModuleId"/>).</summary>
    public static readonly Guid ServiceAction = new("1138e226-eb52-477c-8771-da1134132898");
    /// <summary>Applied memory suggestions (<see cref="HistorySummary.MemoryFixModuleId"/>).</summary>
    public static readonly Guid MemoryOptimization = new("c78cd524-47fe-4172-9f7a-8dc796f8d5db");

    /// <summary>Namespace for ids made from an unknown slug (a module no catalog knows any more), so the same slug always gets the same id.</summary>
    private static readonly Guid UnknownNamespace = new("26bb3567-feea-481e-98de-163f5eb351b3");

    /// <summary>The id for a slug: the catalog's (or built-in) module id, a fixed record id, or a stable id made from the slug.</summary>
    public static Guid For(string slug, ModuleCatalog? catalog = null)
    {
        if (catalog?.Find(slug) is { } d) return d.Id;
        if (ModuleIds.FromSlug(slug) is { } id) return id;
        if (string.Equals(slug, HistorySummary.RemediationModuleId, StringComparison.OrdinalIgnoreCase)) return Remediation;
        if (string.Equals(slug, HistorySummary.ServiceFixModuleId, StringComparison.OrdinalIgnoreCase)) return ServiceAction;
        if (string.Equals(slug, HistorySummary.MemoryFixModuleId, StringComparison.OrdinalIgnoreCase)) return MemoryOptimization;
        return FromName(slug);
    }

    /// <summary>RFC 4122 version 5 (SHA-1, name-based) id of <paramref name="name"/> in this app's namespace.</summary>
    public static Guid FromName(string name)
    {
        var ns = UnknownNamespace.ToByteArray(bigEndian: true);
        var bytes = SHA1.HashData([.. ns, .. Encoding.UTF8.GetBytes(name.ToLowerInvariant())]);
        var g = bytes.AsSpan(0, 16).ToArray();
        g[6] = (byte)((g[6] & 0x0F) | 0x50);
        g[8] = (byte)((g[8] & 0x3F) | 0x80);
        return new Guid(g, bigEndian: true);
    }
}
