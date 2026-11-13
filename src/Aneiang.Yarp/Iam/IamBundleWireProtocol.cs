using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Aneiang.Yarp.Iam;

public static class IamBundleWireProtocol
{
    public static JsonSerializerOptions JsonOptions { get; } = CreateOptions();
    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web) { MaxDepth = 32 };
        options.Converters.Add(new JsonStringEnumConverter(allowIntegerValues: false));
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
    public static IamPolicyBundle Decode(IamBundleEnvelope envelope, DateTimeOffset now)
    {
        if (envelope.SchemaVersion != 1 || envelope.Revision <= 0 || envelope.ValidatedUntil <= now
            || envelope.ValidatedUntil > now.AddHours(24) || envelope.PolicyContentBase64.Length > 3 * 1024 * 1024)
            throw new IamContractException("bundle_schema_revision_or_lease");
        var content = Convert.FromBase64String(envelope.PolicyContentBase64);
        if (content.Length is 0 or > 2 * 1024 * 1024 || !HashEquals(content, envelope.ContentHash))
            throw new IamContractException("bundle_hash");
        using var document = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 32 });
        RejectDuplicateProperties(document.RootElement);
        var root = document.RootElement;
        if (root.GetProperty("schemaVersion").GetInt32() != 1 || root.GetProperty("revision").GetInt64() != envelope.Revision)
            throw new IamContractException("bundle_content_binding");
        var publishedAt = root.GetProperty("publishedAt").GetDateTimeOffset();
        if (publishedAt > now.AddMinutes(1)) throw new IamContractException("bundle_published_time");
        var manifest = Convert.FromBase64String(root.GetProperty("routeManifestBase64").GetString()!);
        var manifestHash = root.GetProperty("routeManifestHash").GetString()!;
        if (manifest.Length is 0 or > 1024 * 1024 || !HashEquals(manifest, manifestHash)) throw new IamContractException("manifest_hash");
        using var manifestDocument = JsonDocument.Parse(manifest, new JsonDocumentOptions { MaxDepth = 32 });
        RejectDuplicateProperties(manifestDocument.RootElement);
        if (manifestDocument.RootElement.GetProperty("schemaVersion").GetInt32() != 1) throw new IamContractException("manifest_schema");
        var routes = manifestDocument.RootElement.GetProperty("routes").EnumerateArray().ToDictionary(
            r => r.GetProperty("routeId").GetString()!, StringComparer.OrdinalIgnoreCase);
        if (routes.Count > 2048) throw new IamContractException("manifest_limit");
        var policies = ImmutableArray.CreateBuilder<IamOperationPolicy>();
        foreach (var value in root.GetProperty("policies").EnumerateArray())
        {
            var wire = value.Deserialize<WirePolicy>(JsonOptions) ?? throw new IamContractException("policy_malformed");
            if (!Guid.TryParse(wire.ApplicationId, out var app) || app == Guid.Empty || string.IsNullOrWhiteSpace(wire.ApplicationCode)
                || !routes.TryGetValue(wire.GatewayRouteId, out var route)
                || route.GetProperty("fingerprint").GetString() != wire.GatewayRouteFingerprint
                || !route.GetProperty("methods").EnumerateArray().Any(m => m.GetString() == wire.HttpMethod))
                throw new IamContractException("policy_manifest_binding");
            if (route.GetProperty("path").GetString()!.IndexOfAny(['*', '?']) >= 0
                || route.GetProperty("transforms").EnumerateArray().Any(t => t.EnumerateObject().Count() != 1
                    || t.EnumerateObject().Any(p => p.Name is not ("PathRemovePrefix" or "PathPrefix"))))
                throw new IamContractException("unsupported_core_route");
            if (string.IsNullOrWhiteSpace(wire.OperationKey) || wire.OperationKey.Length > 120
                || string.IsNullOrWhiteSpace(wire.BackendServiceCode) || wire.AllowedPrincipalKinds.IsDefaultOrEmpty
                || wire.RequiredOAuthScopes.IsDefault || wire.RequiredPermissions.IsDefault
                || !Enum.IsDefined(wire.AuthMode) || wire.AuthMode == IamAuthMode.Unconfigured
                || !Enum.IsDefined(wire.RequirementMode) || wire.EnforcementMode != IamEnforcementMode.GatewayOnly
                || wire.AllowedPrincipalKinds.Any(k => !Enum.IsDefined(k))
                || wire.AuthMode != IamAuthMode.Anonymous && string.IsNullOrWhiteSpace(wire.RequiredAudience)
                || wire.AuthMode == IamAuthMode.Permission && wire.RequiredPermissions.IsEmpty
                || wire.AuthMode == IamAuthMode.InternalOnly && wire.AllowedPrincipalKinds.Any(k => k != IamPrincipalKind.Service))
                throw new IamContractException("policy_invalid");
            if (wire.AuthMode == IamAuthMode.Anonymous && (wire.ApplicationCode == "iam"
                || route.GetProperty("path").GetString()!.StartsWith("/internal", StringComparison.OrdinalIgnoreCase)))
                throw new IamContractException("sensitive_anonymous_policy");
            policies.Add(new(wire.OperationKey, wire.GatewayRouteId, wire.HttpMethod, wire.GatewayRouteFingerprint, app.ToString("D"),
                wire.BackendServiceCode, wire.RequiredAudience, wire.AuthMode, wire.AllowedPrincipalKinds, wire.RequiredOAuthScopes,
                wire.RequiredPermissions, wire.RequirementMode, wire.EnforcementMode, envelope.Revision));
            if (policies.Count > 2048) throw new IamContractException("policy_limit");
        }
        if (policies.Count == 0 || policies.GroupBy(p => p.RouteId.ToUpperInvariant() + "\n" + p.HttpMethod).Any(g => g.Count() > 1))
            throw new IamContractException("policy_empty_or_ambiguous");
        return new("1.0", envelope.Revision, envelope.ContentHash, manifestHash, publishedAt, envelope.ValidatedUntil,
            policies.ToImmutable(), Convert.ToBase64String(content));
    }
    public static bool HashEquals(ReadOnlySpan<byte> bytes, string hash)
        => hash?.Length == 64 && hash.All(char.IsAsciiHexDigitLower)
            && CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), Convert.FromHexString(hash));
    public static void RejectDuplicateProperties(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in value.EnumerateObject())
            { if (!names.Add(property.Name)) throw new IamContractException("duplicate_json_property"); RejectDuplicateProperties(property.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) RejectDuplicateProperties(item);
    }
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed record WirePolicy(string ApplicationId, string ApplicationCode, string BackendServiceCode, string OperationKey,
        string GatewayRouteId, string HttpMethod, string GatewayRouteFingerprint, IamAuthMode AuthMode, string RequiredAudience,
        ImmutableArray<IamPrincipalKind> AllowedPrincipalKinds, ImmutableArray<string> RequiredOAuthScopes,
        ImmutableArray<string> RequiredPermissions, IamRequirementMode RequirementMode,
        [property: JsonRequired] IamEnforcementMode EnforcementMode);
}
