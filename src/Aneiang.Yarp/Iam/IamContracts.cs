using System.Collections.Immutable;
using Microsoft.AspNetCore.Http;

namespace Aneiang.Yarp.Iam;

public enum IamAuthMode { Unconfigured, Anonymous, Authenticated, Permission, InternalOnly }
public enum IamPrincipalKind { User, Service }
public enum IamRequirementMode { Any, All }
public enum IamEnforcementMode { GatewayOnly }
public enum IamScopeKind { Global, System }

public sealed record IamGrant(string PermissionCode, IamScopeKind ScopeKind, string? ScopeId, DateTimeOffset? ExpiresAt, string Source);

public sealed record IamEntitlementSnapshot(
    int SchemaVersion,
    string PrincipalId,
    string Issuer,
    string Subject,
    string ApplicationId,
    long Revision,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    bool IsActive,
    IamPrincipalKind PrincipalKind,
    ImmutableArray<IamGrant> Grants,
    string? ClientId = null);

public sealed record IamOperationPolicy(
    string OperationKey,
    string RouteId,
    string HttpMethod,
    string RouteFingerprint,
    string ApplicationId,
    string BackendServiceCode,
    string RequiredAudience,
    IamAuthMode AuthMode,
    ImmutableArray<IamPrincipalKind> AllowedPrincipalKinds,
    ImmutableArray<string> RequiredOAuthScopes,
    ImmutableArray<string> RequiredPermissions,
    IamRequirementMode RequirementMode,
    IamEnforcementMode EnforcementMode,
    long PolicyRevision);

public sealed record IamPolicyBundle(
    string SchemaVersion,
    long Revision,
    string Hash,
    string RouteManifestHash,
    DateTimeOffset PublishedAt,
    DateTimeOffset ValidatedUntil,
    ImmutableArray<IamOperationPolicy> Policies,
    string PolicyContentBase64 = "");

public sealed record IamBundleEnvelope(int SchemaVersion, long Revision, string ContentHash,
    DateTimeOffset ValidatedUntil, string PolicyContentBase64);

public sealed record IamDecision(bool Allowed, string ReasonCode, int StatusCode)
{
    public static IamDecision Allow() => new(true, "allowed", StatusCodes.Status200OK);
    public static IamDecision Deny(string reason, int status = StatusCodes.Status403Forbidden) => new(false, reason, status);
}

public interface IIamPolicyBundleProvider
{
    IamPolicyBundle? Current { get; }
    bool IsReady { get; }
}

public interface IIamEntitlementSource
{
    Task<IamEntitlementSnapshot> FetchAsync(string issuer, string subject, string applicationId, CancellationToken cancellationToken, string? clientId = null);
}
