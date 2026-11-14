using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Model;

namespace Aneiang.Yarp.Iam;

public sealed class AccessAuthorizationMiddleware(RequestDelegate next, ILogger<AccessAuthorizationMiddleware> logger)
{
    private static readonly string[] UntrustedHeaders =
    [
        "X-User-Id", "X-Principal-Id", "X-Principal", "X-Role", "X-Permission",
        "X-Access", "X-SystemId", "X-Operation-Key", "X-IAM-Resource-Proof"
    ];

    public async Task InvokeAsync(HttpContext http, AccessPolicyStore policies,
        AccessEntitlementCache cache, IOptions<IamGatewayOptions> iam, TimeProvider clock)
    {
        foreach (var h in UntrustedHeaders) http.Request.Headers.Remove(h);
        var routeId = http.Features.Get<IReverseProxyFeature>()?.Route?.Config.RouteId;
        if (routeId is null) { await Reject(http, 403); return; }

        if (!policies.IsReady || policies.CurrentRevision is not long revision)
        { await Reject(http, 503); return; }
        var rule = policies.Find(routeId, http.Request.Method, http.Request.Path, out var ambiguous);
        if (ambiguous || rule is null || rule.AccessCodes.Length == 0)
        { await Reject(http, 403); return; }

        var auth = await http.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
        if (!auth.Succeeded || auth.Principal is null) { await Reject(http, 401); return; }
        var principal = auth.Principal;
        http.User = principal;
        if (principal.FindAll("iss").Count() != 1 || principal.FindAll("sub").Count() != 1
            || principal.FindAll("client_id").Count() > 1 || principal.FindAll("azp").Count() > 1
            || principal.FindAll("realm_access").Count() > 1 || principal.FindAll("resource_access").Count() > 1
            || principal.FindAll("typ").Any(x => x.Value is "ID" or "ID_TOKEN"))
        { await Reject(http, 401); return; }
        if (!principal.FindAll("aud").Any(x => x.Value == iam.Value.Audience))
        { await Reject(http, 403); return; }
        var issuer = principal.FindFirstValue("iss")!;
        var subject = principal.FindFirstValue("sub")!;
        var clientId = principal.FindFirstValue("client_id");
        var azp = principal.FindFirstValue("azp");
        if (clientId is not null && azp is not null && clientId != azp)
        { await Reject(http, 401); return; }
        clientId ??= azp;
        try
        {
            var realm = RealmRoles(principal);
            var clients = ClientRoles(principal);
            var request = new AccessResolveRequest(1, rule.ApplicationId, issuer, subject, clientId, realm, clients);
            var grants = await cache.GetAsync(request, revision, http.RequestAborted);
            if (!policies.IsReady || policies.CurrentRevision != revision)
            { await Reject(http, 503); return; }
            if (!grants.IsActive || !rule.AccessCodes.Any(grants.AccessCodes.Contains))
            { await Reject(http, 403); return; }
            http.Items["Aneiang.Iam.AccessCode"] = rule.AccessCodes.First(grants.AccessCodes.Contains);
            await next(http);
        }
        catch (OperationCanceledException) when (http.RequestAborted.IsCancellationRequested) { throw; }
        catch (Exception e) when (e is JsonException or HttpRequestException or TaskCanceledException
            or IamContractException or ArgumentException or InvalidOperationException)
        {
            logger.LogWarning("IAM access lookup failed for route {RouteId}, correlation {CorrelationId}",
                routeId, http.TraceIdentifier);
            await Reject(http, 503);
        }
    }

    private static string[] ParseRoleList(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 256)
            throw new IamContractException("token_roles_invalid");
        return value.EnumerateArray().Select(x =>
        {
            var name = x.ValueKind == JsonValueKind.String ? x.GetString() : null;
            if (string.IsNullOrEmpty(name) || name.Length > 200 || name.Any(char.IsControl))
                throw new IamContractException("token_role_invalid");
            return name;
        }).Distinct(StringComparer.Ordinal).ToArray();
    }
    private static string[] RealmRoles(ClaimsPrincipal principal)
    {
        var value = principal.FindFirstValue("realm_access");
        if (string.IsNullOrEmpty(value)) return [];
        if (value.Length > 8192) throw new IamContractException("token_roles_oversized");
        using var doc = JsonDocument.Parse(value);
        return doc.RootElement.TryGetProperty("roles", out var roles) ? ParseRoleList(roles) : [];
    }
    private static Dictionary<string,string[]> ClientRoles(ClaimsPrincipal principal)
    {
        var value = principal.FindFirstValue("resource_access");
        var result = new Dictionary<string,string[]>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(value)) return result;
        if (value.Length > 16384) throw new IamContractException("token_roles_oversized");
        using var doc = JsonDocument.Parse(value);
        if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new IamContractException("token_roles_invalid");
        if (doc.RootElement.EnumerateObject().Count() > 32) throw new IamContractException("token_roles_excessive");
        foreach (var pair in doc.RootElement.EnumerateObject())
            if (pair.Name.Length is > 0 and <= 200 && pair.Value.TryGetProperty("roles", out var roles))
                result.Add(pair.Name, ParseRoleList(roles));
        return result;
    }
    private static Task Reject(HttpContext context, int code)
    {
        context.Response.StatusCode = code;
        context.Response.ContentType = "application/problem+json";
        context.Response.Headers.CacheControl = "no-store";
        return context.Response.WriteAsJsonAsync(new {
            title = code == 401 ? "Authentication required" : code == 503
                ? "Authorization temporarily unavailable" : "Forbidden",
            status = code, correlationId = context.TraceIdentifier
        });
    }
}
