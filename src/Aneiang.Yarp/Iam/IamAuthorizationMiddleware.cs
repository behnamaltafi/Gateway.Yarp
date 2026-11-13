using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Model;
using Microsoft.Extensions.Options;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Aneiang.Yarp.Iam;

public sealed class IamAuthorizationMiddleware(RequestDelegate next, ILogger<IamAuthorizationMiddleware> logger)
{
    private static readonly string[] UntrustedHeaders =
    [
        "X-User-Id", "X-Principal-Id", "X-Principal", "X-Role", "X-Permission", "X-SystemId", "X-Operation-Key",
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-IAM-Resource-Proof"
    ];

    public async Task InvokeAsync(
        HttpContext context,
        IIamPolicyBundleProvider bundles,
        IIamEntitlementCache entitlements,
        IamPolicyEvaluator evaluator,
        IOptions<IamGatewayOptions> options,
        TimeProvider clock)
    {
        foreach (var header in UntrustedHeaders) context.Request.Headers.Remove(header);

        var route = context.Features.Get<IReverseProxyFeature>()?.Route?.Config;
        if (route is null) { await RejectAsync(context, StatusCodes.Status403Forbidden, "route_unmatched"); return; }
        var bundle = bundles.Current;
        if (bundle is null || !bundles.IsReady || bundle.ValidatedUntil <= clock.GetUtcNow())
        { await RejectAsync(context, StatusCodes.Status503ServiceUnavailable, "bundle_unavailable"); return; }

        var policy = bundle.Policies.SingleOrDefault(p =>
            string.Equals(p.RouteId, route.RouteId, StringComparison.Ordinal)
            && string.Equals(p.HttpMethod, context.Request.Method, StringComparison.OrdinalIgnoreCase));
        if (policy is null) { await RejectAsync(context, StatusCodes.Status403Forbidden, "operation_unpublished"); return; }
        if (!string.Equals(policy.RouteFingerprint, IamRouteFingerprint.Compute(route), StringComparison.Ordinal))
        { await RejectAsync(context, StatusCodes.Status403Forbidden, "route_manifest_mismatch"); return; }
        if (policy.AuthMode == IamAuthMode.Anonymous) { await next(context); return; }

        var authentication = await context.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
        if (!authentication.Succeeded || authentication.Principal is null)
        { await RejectAsync(context, StatusCodes.Status401Unauthorized, "token_required"); return; }
        context.User = authentication.Principal;
        if (IsIdToken(context.User)) { await RejectAsync(context, StatusCodes.Status401Unauthorized, "token_type"); return; }
        if (new[] { "iss", "sub", "client_id", "azp" }.Any(type => context.User.FindAll(type).Skip(1).Any()))
        { await RejectAsync(context, 401, "identity_claim_conflict"); return; }

        var issuer = context.User.FindFirstValue("iss");
        var subject = context.User.FindFirstValue("sub");
        var clientId = context.User.FindFirstValue("client_id");
        var azp = context.User.FindFirstValue("azp");
        if (clientId is not null && azp is not null && clientId != azp)
        { await RejectAsync(context, 401, "client_claim_conflict"); return; }
        clientId ??= azp;
        if (policy.AuthMode == IamAuthMode.InternalOnly && (!context.Request.IsHttps
            || !options.Value.InternalOnlyRemoteAddresses.Any(value => IPAddress.TryParse(value, out var address)
                && context.Connection.RemoteIpAddress?.MapToIPv6().Equals(address.MapToIPv6()) == true)))
        { await RejectAsync(context, 403, "internal_transport"); return; }
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        { await RejectAsync(context, StatusCodes.Status401Unauthorized, "token_identity"); return; }

        try
        {
            var snapshot = await entitlements.GetAsync(issuer, subject, policy.ApplicationId, context.RequestAborted, clientId).ConfigureAwait(false);
            if (bundle.ValidatedUntil <= clock.GetUtcNow())
            { await RejectAsync(context, StatusCodes.Status503ServiceUnavailable, "bundle_unavailable"); return; }
            var decision = evaluator.Evaluate(policy, context.User, snapshot);
            if (!decision.Allowed) { await RejectAsync(context, decision.StatusCode, decision.ReasonCode); return; }
            context.Items["Aneiang.Iam.OperationKey"] = policy.OperationKey;
            context.Items["Aneiang.Iam.PrincipalId"] = snapshot.PrincipalId;
            await next(context);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
        catch (IamIdentityNotFoundException) { await RejectAsync(context, 403, "principal_unknown"); }
        catch (IamIdentityConflictException) { await RejectAsync(context, 403, "identity_conflict"); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IamContractException)
        {
            logger.LogWarning("IAM entitlement unavailable for route {RouteId}; correlation {CorrelationId}", route.RouteId, context.TraceIdentifier);
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
