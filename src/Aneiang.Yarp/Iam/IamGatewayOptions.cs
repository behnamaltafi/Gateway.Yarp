namespace Aneiang.Yarp.Iam;

public sealed class IamGatewayOptions
{
    public const string SectionName = "Gateway:Iam";
    public bool Enabled { get; set; }
    public string Authority { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string[] AllowedAlgorithms { get; set; } = ["RS256"];
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
    public Uri? PolicyBundleEndpoint { get; set; }
    public Uri? EntitlementEndpoint { get; set; }
    public string InternalApiToken { get; set; } = string.Empty;
    public Uri? InternalTokenEndpoint { get; set; }
    public string InternalClientId { get; set; } = string.Empty;
    public string InternalClientSecret { get; set; } = string.Empty;
    public string[] InternalOnlyRemoteAddresses { get; set; } = [];
    public string ManifestExportAudience { get; set; } = "gateway-manifest";
    public string[] ManifestExportSubjects { get; set; } = [];
    public string[] ManifestExportRemoteAddresses { get; set; } = [];
    public TimeSpan EntitlementMaxAge { get; set; } = TimeSpan.FromSeconds(120);
    public TimeSpan NegativeCacheMaxAge { get; set; } = TimeSpan.FromSeconds(15);
    public int EntitlementCacheSize { get; set; } = 10_000;
    public int MaxConcurrentEntitlementFetches { get; set; } = 64;
    public int MaxPendingEntitlementFetches { get; set; } = 128;
    public int MaxEntitlementPayloadBytes { get; set; } = 256 * 1024;
    public int MaxBundlePayloadBytes { get; set; } = 2 * 1024 * 1024;
    public TimeSpan IamTimeout { get; set; } = TimeSpan.FromSeconds(3);
    public TimeSpan BundleRefreshInterval { get; set; } = TimeSpan.FromSeconds(30);
}

internal sealed class IamGatewayOptionsValidator : Microsoft.Extensions.Options.IValidateOptions<IamGatewayOptions>
{
    public Microsoft.Extensions.Options.ValidateOptionsResult Validate(string? name, IamGatewayOptions value)
    {
        if (!value.Enabled) return Microsoft.Extensions.Options.ValidateOptionsResult.Success;
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(value.Authority) && string.IsNullOrWhiteSpace(value.Issuer)) errors.Add("Authority or Issuer is required.");
        if (string.IsNullOrWhiteSpace(value.Audience)) errors.Add("Audience is required.");
        if (value.PolicyBundleEndpoint is null) errors.Add("PolicyBundleEndpoint is required.");
        if (value.EntitlementEndpoint is null) errors.Add("EntitlementEndpoint is required.");
        if (value.EntitlementMaxAge <= TimeSpan.Zero || value.EntitlementMaxAge > TimeSpan.FromSeconds(120)) errors.Add("EntitlementMaxAge must be in (0,120s].");
        if (value.NegativeCacheMaxAge <= TimeSpan.Zero || value.NegativeCacheMaxAge > TimeSpan.FromSeconds(15)) errors.Add("NegativeCacheMaxAge must be in (0,15s].");
        if (value.EntitlementCacheSize is < 1 or > 1_000_000) errors.Add("EntitlementCacheSize is invalid.");
        if (value.MaxConcurrentEntitlementFetches is < 1 or > 4096) errors.Add("MaxConcurrentEntitlementFetches is invalid.");
        if (value.MaxPendingEntitlementFetches is < 1 or > 4096) errors.Add("MaxPendingEntitlementFetches is invalid.");
        if (value.PolicyBundleEndpoint?.Scheme != "https" || value.EntitlementEndpoint?.Scheme != "https") errors.Add("IAM endpoints require direct HTTPS.");
        if (value.IamTimeout <= TimeSpan.Zero || value.IamTimeout > TimeSpan.FromSeconds(30)) errors.Add("IAM timeout is invalid.");
        if (value.BundleRefreshInterval <= TimeSpan.Zero || value.BundleRefreshInterval > TimeSpan.FromHours(12)) errors.Add("Bundle refresh interval is invalid.");
        return errors.Count == 0 ? Microsoft.Extensions.Options.ValidateOptionsResult.Success : Microsoft.Extensions.Options.ValidateOptionsResult.Fail(errors);
    }
}
