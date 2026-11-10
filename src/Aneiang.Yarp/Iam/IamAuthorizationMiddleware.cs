using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Model;

namespace Aneiang.Yarp.Iam;

public sealed class IamAuthorizationMiddleware(RequestDelegate next, ILogger<IamAuthorizationMiddleware> logger)
{
    private static readonly string[] UntrustedHeaders =
    [
        "X-User-Id", "X-Principal-Id", "X-Principal", "X-Role", "X-Permission", "X-SystemId", "X-Operation-Key",
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"
    ];

    public async Task InvokeAsync(
        HttpContext context,
        IIamPolicyBundleProvider bundles,
        IIamEntitlementCache entitlements,
        IamPolicyEvaluator evaluator)
    {
        foreach (var header in UntrustedHeaders) context.Request.Headers.Remove(header);

        var route = context.Features.Get<IReverseProxyFeature>()?.Route?.Config;
        if (route is null) { await RejectAsync(context, StatusCodes.Status403Forbidden, "route_unmatched"); return; }
        var bundle = bundles.Current;
        if (!bundles.IsReady || bundle is null) { await RejectAsync(context, StatusCodes.Status503ServiceUnavailable, "bundle_unavailable"); return; }

        var policy = bundle.Policies.SingleOrDefault(p =>
            string.Equals(p.RouteId, route.RouteId, StringComparison.Ordinal)
            && string.Equals(p.HttpMethod, context.Request.Method, StringComparison.OrdinalIgnoreCase));
        if (policy is null) { await RejectAsync(context, StatusCodes.Status403Forbidden, "operation_unpublished"); return; }
        if (!string.Equals(policy.RouteFingerprint, IamRouteFingerprint.Compute(route), StringComparison.Ordinal))
        { await RejectAsync(context, StatusCodes.Status403Forbidden, "route_manifest_mismatch"); return; }
        if (policy.AuthMode == IamAuthMode.Anonymous) { await next(context); return; }

        if (context.User.Identity?.IsAuthenticated != true)
        { await RejectAsync(context, StatusCodes.Status401Unauthorized, "token_required"); return; }
        if (IsIdToken(context.User)) { await RejectAsync(context, StatusCodes.Status401Unauthorized, "token_type"); return; }

        var issuer = context.User.FindFirstValue("iss");
        var subject = context.User.FindFirstValue("sub");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        { await RejectAsync(context, StatusCodes.Status401Unauthorized, "token_identity"); return; }

        try
        {
            var snapshot = await entitlements.GetAsync(issuer, subject, policy.ApplicationId, context.RequestAborted).ConfigureAwait(false);
            var decision = evaluator.Evaluate(policy, context.User, snapshot);
            if (!decision.Allowed) { await RejectAsync(context, decision.StatusCode, decision.ReasonCode); return; }
            context.Items["Aneiang.Iam.OperationKey"] = policy.OperationKey;
            context.Items["Aneiang.Iam.PrincipalId"] = snapshot.PrincipalId;
            await next(context);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IamContractException)
        {
            logger.LogWarning(ex, "IAM entitlement unavailable for route {RouteId}; correlation {CorrelationId}", route.RouteId, context.TraceIdentifier);
            await RejectAsync(context, StatusCodes.Status503ServiceUnavailable, "entitlement_unavailable");
        }
    }

    private static bool IsIdToken(ClaimsPrincipal principal)
        => principal.FindAll("typ").Any(c => string.Equals(c.Value, "ID", StringComparison.OrdinalIgnoreCase)
                                             || string.Equals(c.Value, "ID_TOKEN", StringComparison.OrdinalIgnoreCase));

    private static async Task RejectAsync(HttpContext context, int statusCode, string reason)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/problem+json";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsJsonAsync(new
        {
            type = "about:blank",
            title = statusCode == 401 ? "Authentication required" : statusCode == 503 ? "Authorization service unavailable" : "Access denied",
            status = statusCode,
            correlationId = context.TraceIdentifier
        });
        // Deliberately keep the internal reason out of the response.
        _ = reason;
    }
}
