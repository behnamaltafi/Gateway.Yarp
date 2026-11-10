using System.Collections.Immutable;
using Microsoft.AspNetCore.Http;

namespace Aneiang.Yarp.Iam;

public enum IamAuthMode { Unconfigured, Anonymous, Authenticated, Permission, InternalOnly }
public enum IamPrincipalKind { User, Service }
public enum IamRequirementMode { Any, All }
public enum IamEnforcementMode { GatewayOnly, GatewayAndResource }

public sealed record IamGrant(string Permission, string Scope, DateTimeOffset? ExpiresAt, string Source);

public sealed record IamEntitlementSnapshot(
    string SchemaVersion,
    string PrincipalId,
    string Issuer,
    string Subject,
    string ApplicationId,
    long Revision,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    bool IsActive,
    IamPrincipalKind PrincipalKind,
    ImmutableArray<IamGrant> Grants);

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
    ImmutableArray<string> RequiredBusinessScopes,
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
    ImmutableArray<IamOperationPolicy> Policies);

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
    Task<IamEntitlementSnapshot> FetchAsync(string issuer, string subject, string applicationId, CancellationToken cancellationToken);
}
