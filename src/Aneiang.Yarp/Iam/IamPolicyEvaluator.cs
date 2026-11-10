using System.Security.Claims;

namespace Aneiang.Yarp.Iam;

public sealed class IamPolicyEvaluator(TimeProvider clock)
{
    public IamDecision Evaluate(IamOperationPolicy policy, ClaimsPrincipal principal, IamEntitlementSnapshot entitlement)
    {
        if (!entitlement.IsActive) return IamDecision.Deny("principal_inactive");
        if (!policy.AllowedPrincipalKinds.Contains(entitlement.PrincipalKind)) return IamDecision.Deny("principal_kind");
        if (!HasAudience(principal, policy.RequiredAudience)) return IamDecision.Deny("audience");
        if (!HasScopes(principal, policy.RequiredOAuthScopes)) return IamDecision.Deny("oauth_scope");
        if (policy.AuthMode == IamAuthMode.InternalOnly &&
            (entitlement.PrincipalKind != IamPrincipalKind.Service || !principal.HasClaim("trusted_channel", "true")))
            return IamDecision.Deny("internal_channel");
        if (policy.AuthMode is IamAuthMode.Authenticated or IamAuthMode.InternalOnly) return IamDecision.Allow();
        if (policy.AuthMode != IamAuthMode.Permission) return IamDecision.Deny("policy_mode");

        var now = clock.GetUtcNow();
        var effective = entitlement.Grants
            .Where(g => g.ExpiresAt is null || g.ExpiresAt > now)
            .Where(g => policy.RequiredBusinessScopes.IsDefaultOrEmpty
                        || policy.RequiredBusinessScopes.Contains(g.Scope, StringComparer.Ordinal))
            .ToArray();
        bool HasPermission(string permission) => effective.Any(g => string.Equals(g.Permission, permission, StringComparison.Ordinal));
        var allowed = policy.RequirementMode == IamRequirementMode.All
            ? policy.RequiredPermissions.All(HasPermission)
            : policy.RequiredPermissions.Any(HasPermission);
        return allowed ? IamDecision.Allow() : IamDecision.Deny("permission");
    }

    public static bool HasAudience(ClaimsPrincipal principal, string required)
        => principal.FindAll("aud").SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)).Contains(required, StringComparer.Ordinal);

    private static bool HasScopes(ClaimsPrincipal principal, IEnumerable<string> required)
    {
        var needed = required.ToArray();
        if (needed.Length == 0) return true;
        var actual = principal.FindAll("scope").SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToHashSet(StringComparer.Ordinal);
        return needed.All(actual.Contains);
    }
}
