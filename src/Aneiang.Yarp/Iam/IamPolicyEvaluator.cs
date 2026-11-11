using System.Security.Claims;

namespace Aneiang.Yarp.Iam;

public sealed class IamPolicyEvaluator(TimeProvider clock)
{
    public IamDecision Evaluate(IamOperationPolicy policy, ClaimsPrincipal principal, IamEntitlementSnapshot entitlement)
    {
        var now = clock.GetUtcNow();
        if (!entitlement.IsActive || entitlement.ExpiresAt <= now || entitlement.IssuedAt > now)
            return IamDecision.Deny("principal_inactive_or_expired");
        if (!policy.AllowedPrincipalKinds.Contains(entitlement.PrincipalKind)) return IamDecision.Deny("principal_kind");
        if (!HasAudience(principal, policy.RequiredAudience)) return IamDecision.Deny("audience");
        if (!HasScopes(principal, policy.RequiredOAuthScopes)) return IamDecision.Deny("oauth_scope");
        // No token/header claim can attest a private transport. InternalOnly is additionally guarded in the middleware.
        if (policy.AuthMode == IamAuthMode.InternalOnly && entitlement.PrincipalKind != IamPrincipalKind.Service)
            return IamDecision.Deny("internal_kind");
        if (policy.AuthMode is IamAuthMode.Authenticated or IamAuthMode.InternalOnly) return IamDecision.Allow();
        if (policy.AuthMode != IamAuthMode.Permission || policy.RequiredPermissions.IsDefaultOrEmpty)
            return IamDecision.Deny("policy_mode");
        var grants = entitlement.Grants.Where(g => g.ExpiresAt is null || g.ExpiresAt > now).ToArray();
        bool InContext(IamGrant grant, string? system) => grant.ScopeKind == IamScopeKind.Global && grant.ScopeId is null
            || system is not null && grant.ScopeKind == IamScopeKind.System && grant.ScopeId == system;
        bool Allows(string? system)
        {
            bool Has(string code) => grants.Any(g => g.PermissionCode == code && InContext(g, system));
            return policy.RequirementMode == IamRequirementMode.All ? policy.RequiredPermissions.All(Has)
                : policy.RequirementMode == IamRequirementMode.Any && policy.RequiredPermissions.Any(Has);
        }
        // GatewayOnly cannot consume a scoped grant without a destination resource check.
        if (Allows(null)) return IamDecision.Allow();
        if (policy.EnforcementMode == IamEnforcementMode.GatewayAndResource && policy.ResourceScopeRequired
            && grants.Where(g => g.ScopeKind == IamScopeKind.System).Select(g => g.ScopeId).Distinct().Any(Allows))
            return IamDecision.Allow(); // pre-check only; destination independently checks the actual resource's context
        return IamDecision.Deny("permission");
    }

    public static bool HasAudience(ClaimsPrincipal principal, string required)
        => !string.IsNullOrWhiteSpace(required) && principal.FindAll("aud").Any(c => c.Value == required);
    private static bool HasScopes(ClaimsPrincipal principal, IEnumerable<string> required)
    {
        var actual = principal.FindAll("scope").SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToHashSet(StringComparer.Ordinal);
        return required.All(actual.Contains);
    }
}
