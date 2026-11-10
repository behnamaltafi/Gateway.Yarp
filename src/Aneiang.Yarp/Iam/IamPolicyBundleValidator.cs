using System.Security.Cryptography;
using System.Text.Json;

namespace Aneiang.Yarp.Iam;

public static class IamPolicyBundleValidator
{
    public const string SupportedSchemaVersion = "1.0";

    public static bool TryValidate(IamPolicyBundle? bundle, DateTimeOffset now, out string reason)
    {
        if (bundle is null) { reason = "bundle_missing"; return false; }
        if (!string.Equals(bundle.SchemaVersion, SupportedSchemaVersion, StringComparison.Ordinal)) { reason = "bundle_schema"; return false; }
        if (bundle.Revision <= 0 || bundle.PublishedAt > now.AddMinutes(1)) { reason = "bundle_revision_or_time"; return false; }
        if (bundle.ValidatedUntil <= now) { reason = "bundle_expired"; return false; }
        if (bundle.Policies.IsDefault || bundle.Policies.Any(p => !IsPolicyValid(p))) { reason = "bundle_policy_invalid"; return false; }
        if (bundle.Policies.GroupBy(p => (p.RouteId, Method: p.HttpMethod.ToUpperInvariant()), StringTupleComparer.OrdinalIgnoreCase).Any(g => g.Count() != 1))
        { reason = "bundle_duplicate_policy"; return false; }
        if (!string.Equals(bundle.RouteManifestHash, ComputeRouteManifestHash(bundle.Policies), StringComparison.Ordinal))
        { reason = "route_manifest_hash"; return false; }
        var actual = ComputeHash(bundle);
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual), TryHex(bundle.Hash, out var supplied) ? supplied : []))
        { reason = "bundle_hash"; return false; }
        reason = "valid";
        return true;
    }

    public static string ComputeHash(IamPolicyBundle bundle)
    {
        var canonical = new
        {
            bundle.SchemaVersion,
            bundle.Revision,
            bundle.RouteManifestHash,
            bundle.PublishedAt,
            bundle.ValidatedUntil,
            Policies = bundle.Policies.OrderBy(x => x.RouteId, StringComparer.Ordinal).ThenBy(x => x.HttpMethod, StringComparer.Ordinal).ThenBy(x => x.OperationKey, StringComparer.Ordinal)
        };
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical))).ToLowerInvariant();
    }

    public static string ComputeRouteManifestHash(IEnumerable<IamOperationPolicy> policies)
    {
        var manifest = policies.OrderBy(x => x.RouteId, StringComparer.Ordinal).ThenBy(x => x.HttpMethod, StringComparer.Ordinal)
            .Select(x => new { x.OperationKey, x.RouteId, Method = x.HttpMethod.ToUpperInvariant(), x.RouteFingerprint }).ToArray();
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(manifest))).ToLowerInvariant();
    }

    private static bool IsPolicyValid(IamOperationPolicy p)
        => !string.IsNullOrWhiteSpace(p.OperationKey) && !string.IsNullOrWhiteSpace(p.RouteId)
           && !string.IsNullOrWhiteSpace(p.HttpMethod) && !string.IsNullOrWhiteSpace(p.RouteFingerprint)
           && !string.IsNullOrWhiteSpace(p.ApplicationId) && p.PolicyRevision > 0
           && p.AuthMode != IamAuthMode.Unconfigured
           && (p.AuthMode != IamAuthMode.Permission || !p.RequiredPermissions.IsDefaultOrEmpty)
           && (p.AuthMode == IamAuthMode.Anonymous || !string.IsNullOrWhiteSpace(p.RequiredAudience));

    private static bool TryHex(string value, out byte[] bytes)
    {
        try { bytes = Convert.FromHexString(value); return bytes.Length == 32; }
        catch { bytes = []; return false; }
    }

    private sealed class StringTupleComparer : IEqualityComparer<(string RouteId, string Method)>
    {
        public static readonly StringTupleComparer OrdinalIgnoreCase = new();
        public bool Equals((string RouteId, string Method) x, (string RouteId, string Method) y) =>
            StringComparer.Ordinal.Equals(x.RouteId, y.RouteId) && StringComparer.OrdinalIgnoreCase.Equals(x.Method, y.Method);
        public int GetHashCode((string RouteId, string Method) obj) => HashCode.Combine(StringComparer.Ordinal.GetHashCode(obj.RouteId), StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Method));
    }
}
