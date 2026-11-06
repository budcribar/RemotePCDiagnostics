using System.Security.Cryptography;
using System.Text;

namespace RemotePCDiagnostics.Agent.Core.Tests;

public class AppCacheVersionTests
{
    [Theory]
    [InlineData("1.10.0", "1.9.0", 1)]
    [InlineData("1.2.0", "1.2.0-beta", 1)]
    [InlineData("1.2.0-beta", "1.2.0", -1)]
    [InlineData("1.2", "1.2.0", 0)]
    [InlineData("2.0.0", "10.0.0", -1)]
    [InlineData("1.2.0-alpha", "1.2.0-beta", -1)]
    public void Versions_compare_by_number_then_suffix(string a, string b, int sign) =>
        Assert.Equal(sign, Math.Sign(AppCache.CompareVersions(a, b)));

    [Fact]
    public void The_reported_cached_version_is_the_highest_complete_one()
    {
        var folders = new[]
        {
            new CachedFolder("1.9.0", true, "z", "e"),
            new CachedFolder("1.10.0", true, "z", "e"),
            new CachedFolder("2.0.0", false, "z", "e"),          // program missing
            new CachedFolder("3.0.0.partial", true, "z", "e"),   // staging folder, not a version
            new CachedFolder("1.11.0", true, null, "e"),         // no zip record
        };
        Assert.Equal("1.10.0", AppCache.PickCachedVersion(folders));
        Assert.Equal("", AppCache.PickCachedVersion([]));
    }

    [Fact]
    public void Records_round_trip_and_reject_other_files()
    {
        var hash = new string('A', 64);
        var record = AppCache.FormatRecord(hash, "app.zip");
        Assert.Equal(new string('a', 64) + " *app.zip\n", record);
        Assert.Equal(new string('a', 64), AppCache.ParseRecord(record, "APP.zip"));
        Assert.Null(AppCache.ParseRecord(record, "other.zip"));
        Assert.Null(AppCache.ParseRecord("abc *app.zip", "app.zip"));
        Assert.Null(AppCache.ParseRecord(null, "app.zip"));
    }

    [Fact]
    public void A_cached_folder_is_used_only_for_the_manifest_release()
    {
        var m = Manifests.Valid();
        var zip = AppCache.FormatRecord(m.Sha256, m.File);
        var entry = AppCache.FormatRecord(new string('b', 64), m.Entry);
        Assert.True(AppCache.IsUsable(m, new CachedFolder(m.Version, true, zip, entry)));
        Assert.False(AppCache.IsUsable(m, new CachedFolder("1.0.0", true, zip, entry)));
        Assert.False(AppCache.IsUsable(m, new CachedFolder(m.Version, false, zip, entry)));
        Assert.False(AppCache.IsUsable(m, new CachedFolder(m.Version, true, AppCache.FormatRecord(new string('c', 64), m.File), entry)));
        Assert.False(AppCache.IsUsable(m, null));
        Assert.Equal(["1.0.0", "1.2.3.partial"], AppCache.FoldersToDelete(["1.0.0", m.Version, "1.2.3.partial"], m.Version));
    }
}

internal static class Manifests
{
    public static ReleaseManifest Valid() => new()
    {
        Product = ReleaseManifest.ProductName, Version = "1.2.3", File = "RemotePCDiagnostics-1.2.3.zip",
        Url = ReleaseUrls.DownloadPrefix + "v1.2.3/RemotePCDiagnostics-1.2.3.zip", Size = 1234, Sha256 = new string('d', 64),
        Entry = "RemotePCDiagnostics.Host.exe",
    };

    public static string Json(ReleaseManifest m) =>
        "{\"product\":\"" + m.Product + "\",\"version\":\"" + m.Version + "\",\"file\":\"" + m.File + "\",\"url\":\"" + m.Url
        + "\",\"size\":" + m.Size + ",\"sha256\":\"" + m.Sha256 + "\",\"entry\":\"" + m.Entry + "\"}";
}

public class ReleaseManifestTests
{
    [Fact]
    public void A_valid_manifest_parses_and_lowercases_its_hash()
    {
        var m = Manifests.Valid();
        m.Sha256 = new string('D', 64);
        var parsed = ReleaseManifest.Parse(Encoding.UTF8.GetBytes(Manifests.Json(m)), out var error);
        Assert.True(parsed is not null, error);
        Assert.Equal("", error);
        Assert.Equal(new string('d', 64), parsed!.Sha256);
        Assert.Equal("1.2.3", parsed.Version);
    }

    [Theory]
    [InlineData("{\"product\":\"Other\"}", "is for 'Other'")]
    [InlineData("not json", "isn't valid JSON")]
    public void Bad_json_or_product_is_refused_in_plain_words(string json, string expected)
    {
        Assert.Null(ReleaseManifest.Parse(Encoding.UTF8.GetBytes(json), out var error));
        Assert.Contains(expected, error);
    }

    [Theory]
    [InlineData("version", "../1.0", "invalid version")]
    [InlineData("file", "..\\evil.zip", "invalid download file")]
    [InlineData("entry", "run.bat", "invalid program file")]
    [InlineData("size", "0", "invalid size")]
    [InlineData("sha256", "xyz", "invalid SHA-256")]
    [InlineData("url", "https://example.com/RemotePCDiagnostics-1.2.3.zip", "outside the RemotePCDiagnostics GitHub releases")]
    public void Each_field_is_checked(string field, string value, string expected)
    {
        var m = Manifests.Valid();
        switch (field)
        {
            case "version": m.Version = value; break;
            case "file": m.File = value; break;
            case "entry": m.Entry = value; break;
            case "size": m.Size = long.Parse(value); break;
            case "sha256": m.Sha256 = value; break;
            case "url": m.Url = value; break;
        }
        Assert.Contains(expected, ReleaseManifest.Validate(m));
    }

    [Fact]
    public void The_url_must_end_with_the_file_name()
    {
        var m = Manifests.Valid();
        m.Url = ReleaseUrls.DownloadPrefix + "v1.2.3/Other.zip";
        Assert.Contains("doesn't match its file name", ReleaseManifest.Validate(m));
    }

    [Theory]
    [InlineData("1.2", true)]
    [InlineData("1.2.3.4", true)]
    [InlineData("1.2.3-beta.1", true)]
    [InlineData("1", false)]
    [InlineData("1.2.3.4.5", false)]
    [InlineData("1.2.3-", false)]
    [InlineData("1.2.3-a..b", false)]
    [InlineData("1.2/3", false)]
    public void Versions_must_be_safe_folder_names(string v, bool ok) => Assert.Equal(ok, ReleaseManifest.IsSafeVersion(v));
}

public class ManifestSignatureTests
{
    [Fact]
    public void A_signature_verifies_only_over_the_exact_bytes_with_the_right_key()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = key.ExportSubjectPublicKeyInfoPem();
        var bytes = Encoding.UTF8.GetBytes(Manifests.Json(Manifests.Valid()));
        var sig = Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        Assert.True(ManifestSignature.Verify(bytes, "  " + sig + "\n", pem));
        var changed = (byte[])bytes.Clone();
        changed[^2] ^= 1;
        Assert.False(ManifestSignature.Verify(changed, sig, pem));
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.False(ManifestSignature.Verify(bytes, sig, other.ExportSubjectPublicKeyInfoPem()));
        Assert.False(ManifestSignature.Verify(bytes, "not base64!", pem));
        Assert.False(ManifestSignature.Verify(bytes, Convert.ToBase64String(new byte[10]), pem));
        Assert.False(ManifestSignature.Verify(bytes, sig, ""));      // no key configured yet
    }

    [Fact]
    public void A_key_on_another_curve_is_refused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var bytes = Encoding.UTF8.GetBytes("x");
        var sig = Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.False(ManifestSignature.Verify(bytes, sig, key.ExportSubjectPublicKeyInfoPem()));
    }
}

public class BackoffTests
{
    [Fact]
    public void Delays_double_up_to_a_minute_and_reset_after_a_healthy_connection()
    {
        var b = new Backoff();
        var seen = Enumerable.Range(0, 7).Select(_ => b.Next().TotalSeconds).ToList();
        Assert.Equal([2, 4, 8, 16, 32, 60, 60], seen);
        b.ConnectionEnded(TimeSpan.FromSeconds(5));
        Assert.Equal(60, b.Next().TotalSeconds);                    // a short connection doesn't count
        b.ConnectionEnded(Backoff.HealthyConnection);
        Assert.Equal(2, b.Next().TotalSeconds);
    }
}
