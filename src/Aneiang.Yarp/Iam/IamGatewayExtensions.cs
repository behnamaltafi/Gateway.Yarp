using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Http;
using System.Net;

namespace Aneiang.Yarp.Iam;

public sealed class IamGatewayMarker;

public static class IamGatewayExtensions
{
    public static IServiceCollection AddAneiangIamGateway(this IServiceCollection services, IConfiguration configuration, Action<IamGatewayOptions>? configure = null)
        => AddAneiangIamGateway(services, configuration, false, configure);

    public static IServiceCollection AddAneiangIamGateway(this IServiceCollection services, IConfiguration configuration, bool allowLocalHttp, Action<IamGatewayOptions>? configure = null)
    {
        services.AddOptions<IamGatewayOptions>().Bind(configuration.GetSection(IamGatewayOptions.SectionName));
        if (configure is not null) services.Configure(configure);
        services.Configure<IamGatewayOptions>(options => options.AllowLocalHttp = allowLocalHttp);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<IamGatewayOptions>, IamGatewayOptionsValidator>());
        services.AddOptions<IamGatewayOptions>().ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IamGatewayMarker>();
        services.TryAddSingleton<IamPolicyBundleStore>();
        services.TryAddSingleton<IIamPolicyBundleProvider>(sp => sp.GetRequiredService<IamPolicyBundleStore>());
        services.TryAddSingleton<IamPolicyEvaluator>();
        services.TryAddSingleton<IIamEntitlementCache, IamEntitlementCache>();
        services.TryAddSingleton<IIamEntitlementSource>(sp => sp.GetRequiredService<IamHttpEntitlementSource>());
        services.TryAddSingleton<IIamServiceTokenProvider, IamServiceTokenProvider>();
        services.AddHttpClient<IamHttpEntitlementSource>((sp, client) => client.Timeout = sp.GetRequiredService<IOptions<IamGatewayOptions>>().Value.IamTimeout)
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
        services.AddHttpClient("Aneiang.Iam.Bundle", (sp, client) => client.Timeout = sp.GetRequiredService<IOptions<IamGatewayOptions>>().Value.IamTimeout)
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
        services.AddHttpClient("Aneiang.Iam.ServiceAuth", (sp, client) => client.Timeout = sp.GetRequiredService<IOptions<IamGatewayOptions>>().Value.IamTimeout)
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
        services.AddHostedService<IamPolicyBundleRefreshService>();
        services.AddHealthChecks().AddCheck<IamPolicyBundleHealthCheck>("iam-policy-bundle", tags: ["ready"]);

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<IamGatewayOptions>>((jwt, configured) =>
            {
                var options = configured.Value;
                jwt.Authority = string.IsNullOrWhiteSpace(options.Authority) ? null : options.Authority;
                jwt.RequireHttpsMetadata = !options.AllowLocalHttp;
                jwt.MapInboundClaims = false;
                jwt.IncludeErrorDetails = false;
                jwt.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        var type = context.Principal?.FindFirst("typ")?.Value;
                        var headerType = context.SecurityToken is Microsoft.IdentityModel.JsonWebTokens.JsonWebToken token ? token.Typ : null;
                        if ((type != "Bearer" && headerType != "at+jwt") || context.Principal?.HasClaim(c => c.Type == "act") == true)
                            context.Fail("Unsupported access-token binding.");
                        return Task.CompletedTask;
                    }
                };
                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = string.IsNullOrWhiteSpace(options.Issuer) ? null : options.Issuer,
                    ValidateAudience = false, // exact operation audience is checked after matching its immutable policy
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ClockSkew = options.ClockSkew,
                    ValidAlgorithms = options.AllowedAlgorithms
                };
            });
        services.AddAuthorization(options => options.AddPolicy("IamManifestExport", policy =>
        {
            policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme).RequireAuthenticatedUser();
            policy.RequireAssertion(context =>
            {
                if (context.Resource is not HttpContext http) return false;
                var settings = http.RequestServices.GetRequiredService<IOptions<IamGatewayOptions>>().Value;
                return IamTransport.Allows(http, settings.AllowLocalHttp)
                    && context.User.FindAll("sub").Count() == 1 && settings.ManifestExportSubjects.Contains(context.User.FindFirst("sub")?.Value, StringComparer.Ordinal)
                    && context.User.FindAll("aud").Any(c => c.Value == settings.ManifestExportAudience)
                    && settings.ManifestExportRemoteAddresses.Any(v => IPAddress.TryParse(v, out var ip)
                        && http.Connection.RemoteIpAddress?.MapToIPv6().Equals(ip.MapToIPv6()) == true);
            });
        }));
        return services;
    }

    public static IReverseProxyApplicationBuilder UseAneiangIamGateway(this IReverseProxyApplicationBuilder proxyPipeline)
    {
        proxyPipeline.UseMiddleware<IamAuthorizationMiddleware>();
        return proxyPipeline;
    }
}

internal sealed class IamPolicyBundleHealthCheck(IIamPolicyBundleProvider provider) : Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck
{
    public Task<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult> CheckHealthAsync(
        Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext context, CancellationToken cancellationToken = default)
        => Task.FromResult(provider.IsReady
            ? Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy("A valid published IAM policy bundle is active.")
            : Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Unhealthy("No valid unexpired IAM policy bundle is active."));
}
