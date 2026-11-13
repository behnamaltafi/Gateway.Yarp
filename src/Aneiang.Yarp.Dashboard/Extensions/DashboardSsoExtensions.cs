using Aneiang.Yarp.Iam;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Aneiang.Yarp.Dashboard.Infrastructure.Deployment;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Aneiang.Yarp.Dashboard.Extensions;

public static class DashboardSsoExtensions
{
    public const string SectionName = "Gateway:Dashboard:Sso";
    public const string OidcScheme = "GatewayDashboardOidc";
    public const string CsrfHeader = "X-Gateway-CSRF";

    public static IApplicationBuilder UseAneiangDashboardSsoCallbacks(this IApplicationBuilder app)
    {
        var oidc = app.ApplicationServices.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(OidcScheme);
        var deployment = app.ApplicationServices.GetService<IOptions<DeploymentOptions>>();
        var resolver = app.ApplicationServices.GetService<EndpointRoleResolver>();
        var management = app.ApplicationServices.GetRequiredService<IamManagementAuthorization>();
        return app.Use(async (context, next) =>
        {
            if (context.Request.Path == oidc.CallbackPath || context.Request.Path == oidc.SignedOutCallbackPath)
            {
                if (deployment?.Value.Mode == DeploymentMode.ProxyOnly || deployment?.Value.Mode == DeploymentMode.Split
                    && resolver?.GetByPort(context.Connection.LocalPort)?.Role is not ("Dashboard" or "All"))
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }
                if (!management.AllowsTransport(context))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return;
                }
            }
            await next(context);
        });
    }

    public static IServiceCollection AddAneiangDashboardSso(this IServiceCollection services, IConfiguration configuration)
        => AddAneiangDashboardSso(services, configuration, false);

    public static IServiceCollection AddAneiangDashboardSso(this IServiceCollection services, IConfiguration configuration, bool allowLocalHttp)
    {
        var sso = configuration.GetSection(SectionName);
        var authority = sso["Authority"]?.TrimEnd('/');
        var clientId = sso["ClientId"];
        var clientSecret = Environment.GetEnvironmentVariable("GATEWAY_DASHBOARD_OIDC_CLIENT_SECRET");
        var audience = sso["ManagementAudience"];
        var keys = sso["DataProtectionKeyPath"];
        var callback = sso["CallbackPath"] ?? "/signin-gateway-dashboard";
        var signedOutCallback = sso["SignedOutCallbackPath"] ?? "/signout-gateway-dashboard";
        var minutes = sso.GetValue("SessionMinutes", 30);
        if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri) || !IamTransport.Allows(uri, allowLocalHttp)
            || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.UserInfo.Length != 0
            || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret)
            || string.IsNullOrWhiteSpace(audience) || audience == clientId || string.IsNullOrWhiteSpace(keys)
            || !Path.IsPathFullyQualified(keys) || !Guid.TryParse(sso["ApplicationId"], out var app) || app == Guid.Empty
            || !ValidPath(callback) || !ValidPath(signedOutCallback) || callback.Equals(signedOutCallback, StringComparison.OrdinalIgnoreCase)
            || minutes is < 5 or > 60)
            throw new InvalidOperationException("Gateway Dashboard SSO requires valid HTTPS authority, client, secret, management audience, IAM application UUID, callback paths and key directory.");

        services.AddSingleton(sp => new IamManagementAuthorization(app.ToString("D"), authority!,
            sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<IIamEntitlementCache>(), allowLocalHttp));
        IamManagementAuthorization.AddServiceBearer(services, authority!, audience, allowLocalHttp);
        var protection = services.AddDataProtection().SetApplicationName("Aneiang.Yarp.Dashboard." + app.ToString("D") + (allowLocalHttp ? ".LocalHttp" : ""))
            .PersistKeysToFileSystem(new DirectoryInfo(keys));
        if (OperatingSystem.IsWindows()) protection.ProtectKeysWithDpapi();
        services.AddAntiforgery(options =>
        {
            options.HeaderName = CsrfHeader;
            options.Cookie.Name = allowLocalHttp ? IamManagementAuthorization.LocalCsrfCookieName : IamManagementAuthorization.CsrfCookieName;
            options.Cookie.Path = "/";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = allowLocalHttp ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
        });
        services.AddAuthentication()
            .AddCookie(IamManagementAuthorization.BrowserScheme, cookie =>
            {
                cookie.Cookie.Name = allowLocalHttp ? IamManagementAuthorization.LocalBrowserCookieName : IamManagementAuthorization.BrowserCookieName;
                cookie.Cookie.Path = "/";
                cookie.Cookie.HttpOnly = true;
                cookie.Cookie.SecurePolicy = allowLocalHttp ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
                cookie.Cookie.SameSite = SameSiteMode.Lax;
                cookie.ExpireTimeSpan = TimeSpan.FromMinutes(minutes);
                cookie.SlidingExpiration = false;
            })
            .AddOpenIdConnect(OidcScheme, oidc =>
            {
                oidc.SignInScheme = IamManagementAuthorization.BrowserScheme;
                oidc.SignOutScheme = IamManagementAuthorization.BrowserScheme;
                oidc.Authority = authority;
                oidc.ClientId = clientId;
                oidc.ClientSecret = clientSecret;
                oidc.CallbackPath = callback;
                oidc.SignedOutCallbackPath = signedOutCallback;
                oidc.RemoteSignOutPath = PathString.Empty;
                oidc.ResponseType = OpenIdConnectResponseType.Code;
                oidc.UsePkce = true;
                oidc.SaveTokens = false;
                oidc.RequireHttpsMetadata = !allowLocalHttp;
                if (allowLocalHttp)
                {
                    oidc.ResponseMode = OpenIdConnectResponseMode.Query;
                    oidc.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    oidc.CorrelationCookie.SameSite = SameSiteMode.Lax;
                    oidc.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                    oidc.NonceCookie.SameSite = SameSiteMode.Lax;
                }
                oidc.MapInboundClaims = false;
                oidc.ClaimActions.Remove("iss");
                oidc.GetClaimsFromUserInfoEndpoint = false;
                oidc.Scope.Clear();
                oidc.Scope.Add("openid");
                oidc.TokenValidationParameters.ValidIssuer = authority;
                oidc.TokenValidationParameters.ValidAudience = clientId;
                oidc.TokenValidationParameters.ValidateIssuer = true;
                oidc.TokenValidationParameters.ValidateAudience = true;
                oidc.TokenValidationParameters.RequireSignedTokens = true;
                oidc.TokenValidationParameters.ValidateIssuerSigningKey = true;
                oidc.TokenValidationParameters.ValidAlgorithms = [Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256];
                oidc.TokenValidationParameters.ValidateLifetime = true;
                oidc.Events.OnTicketReceived = context =>
                {
                    context.Properties!.IsPersistent = false;
                    return Task.CompletedTask;
                };
                oidc.Events.OnRemoteFailure = context =>
                {
                    context.HandleResponse();
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
                oidc.Events.OnRedirectToIdentityProviderForSignOut = context =>
                {
                    context.ProtocolMessage.ClientId = clientId;
                    return Task.CompletedTask;
                };
            });
        return services;
    }

    private static bool ValidPath(string path) => path.Length > 1 && path[0] == '/' && path[1] != '/'
        && path.IndexOfAny(['\\', '?', '#', '%']) < 0;
}
