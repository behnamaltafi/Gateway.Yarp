using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Aneiang.Yarp.Iam;

public sealed class IamManagementAuthorization(string applicationId, string authority, TimeProvider clock, IIamEntitlementCache cache, bool allowLocalHttp = false)
{
    public const string BrowserScheme = "GatewayDashboardCookie";
    public const string ServiceScheme = "GatewayManagementBearer";
    public const string AdminPermission = "gateway.admin";
    public const string BrowserCookieName = "__Host-GatewayDashboard";
    public const string CsrfCookieName = "__Host-GatewayDashboardCsrf";
    public const string LocalBrowserCookieName = "GatewayDashboardLocalHttp";
    public const string LocalCsrfCookieName = "GatewayDashboardLocalHttpCsrf";

    public bool AllowsTransport(HttpContext context) => IamTransport.Allows(context, allowLocalHttp);

    public async Task<int> AuthenticateBrowserAsync(HttpContext context)
    {
        if (!AllowsTransport(context)) return StatusCodes.Status403Forbidden;
        var ticket = await context.AuthenticateAsync(BrowserScheme);
        if (!ticket.Succeeded || ticket.Principal is null) return StatusCodes.Status401Unauthorized;
        context.User = ticket.Principal;
        return StatusCodes.Status200OK;
    }

    public async Task<int> AuthorizeAsync(HttpContext context, bool service)
    {
        if (!AllowsTransport(context)) return StatusCodes.Status403Forbidden;
        var result = await context.AuthenticateAsync(service ? ServiceScheme : BrowserScheme);
        if (!result.Succeeded || result.Principal is null) return StatusCodes.Status401Unauthorized;
        var user = result.Principal;
        var issuer = user.FindFirstValue("iss");
        var subject = user.FindFirstValue("sub");
        var client = service ? user.FindFirstValue("client_id") ?? user.FindFirstValue("azp") : null;
        if (issuer != authority || string.IsNullOrWhiteSpace(subject) || service && string.IsNullOrWhiteSpace(client))
            return StatusCodes.Status403Forbidden;
        context.User = user;
        try
        {
            var snapshot = await cache.GetAsync(issuer, subject, applicationId, context.RequestAborted, client);
            var now = clock.GetUtcNow();
            return snapshot.IsActive && snapshot.ExpiresAt > now
                && snapshot.PrincipalKind == (service ? IamPrincipalKind.Service : IamPrincipalKind.User)
                && snapshot.Grants.Any(grant => grant.PermissionCode == AdminPermission && grant.ScopeKind == IamScopeKind.Global
                    && grant.ScopeId is null && (grant.ExpiresAt is null || grant.ExpiresAt > now))
                ? StatusCodes.Status200OK : StatusCodes.Status403Forbidden;
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is IamIdentityNotFoundException or IamIdentityConflictException or IamContractException
            or HttpRequestException or OperationCanceledException or System.Text.Json.JsonException)
        {
            return StatusCodes.Status403Forbidden;
        }
    }

    public static void AddServiceBearer(IServiceCollection services, string authority, string audience, bool allowLocalHttp = false)
    {
        services.AddAuthentication().AddJwtBearer(ServiceScheme, options =>
        {
            options.Authority = authority;
            options.Audience = audience;
            options.RequireHttpsMetadata = !allowLocalHttp;
            options.MapInboundClaims = false;
            options.IncludeErrorDetails = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = authority, ValidAudience = audience, ValidateIssuer = true, ValidateAudience = true,
                RequireSignedTokens = true, ValidateIssuerSigningKey = true, ValidateLifetime = true,
                RequireExpirationTime = true, ClockSkew = TimeSpan.FromSeconds(30),
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
            };
            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = context =>
                {
                    var principal = context.Principal!;
                    var type = principal.FindFirstValue("typ");
                    var atJwt = context.SecurityToken is Microsoft.IdentityModel.JsonWebTokens.JsonWebToken { Typ: "at+jwt" };
                    var clientId = principal.FindFirstValue("client_id");
                    var azp = principal.FindFirstValue("azp");
                    if ((type is not null ? type != "Bearer" : !atJwt) || principal.HasClaim(c => c.Type == "act")
                        || new[] { "iss", "sub", "client_id", "azp", "typ" }.Any(name => principal.FindAll(name).Skip(1).Any())
                        || clientId is not null && azp is not null && clientId != azp)
                        context.Fail("Invalid management access-token binding.");
                    return Task.CompletedTask;
                }
            };
        });
    }
}
