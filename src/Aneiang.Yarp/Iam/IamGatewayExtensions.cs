using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Aneiang.Yarp.Iam;

public sealed class IamGatewayMarker;

public static class IamGatewayExtensions
{
    public static IServiceCollection AddAneiangIamGateway(this IServiceCollection services, IConfiguration configuration, Action<IamGatewayOptions>? configure = null)
    {
        services.AddOptions<IamGatewayOptions>().Bind(configuration.GetSection(IamGatewayOptions.SectionName));
        if (configure is not null) services.Configure(configure);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<IamGatewayOptions>, IamGatewayOptionsValidator>());
        services.AddOptions<IamGatewayOptions>().ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IamGatewayMarker>();
        services.TryAddSingleton<IamPolicyBundleStore>();
        services.TryAddSingleton<IIamPolicyBundleProvider>(sp => sp.GetRequiredService<IamPolicyBundleStore>());
        services.TryAddSingleton<IamPolicyEvaluator>();
        services.TryAddSingleton<IIamEntitlementCache, IamEntitlementCache>();
        services.TryAddSingleton<IIamEntitlementSource, IamHttpEntitlementSource>();
        services.AddHttpClient<IamHttpEntitlementSource>((sp, client) => client.Timeout = sp.GetRequiredService<IOptions<IamGatewayOptions>>().Value.IamTimeout);
        services.AddHttpClient("Aneiang.Iam.Bundle", (sp, client) => client.Timeout = sp.GetRequiredService<IOptions<IamGatewayOptions>>().Value.IamTimeout);
        services.AddHostedService<IamPolicyBundleRefreshService>();
        services.AddHealthChecks().AddCheck<IamPolicyBundleHealthCheck>("iam-policy-bundle", tags: ["ready"]);

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<IamGatewayOptions>>((jwt, configured) =>
            {
                var options = configured.Value;
                jwt.Authority = string.IsNullOrWhiteSpace(options.Authority) ? null : options.Authority;
                jwt.RequireHttpsMetadata = true;
                jwt.MapInboundClaims = false;
                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = string.IsNullOrWhiteSpace(options.Issuer) ? null : options.Issuer,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ClockSkew = options.ClockSkew,
                    ValidAlgorithms = options.AllowedAlgorithms
                };
            });
        services.AddAuthorization();
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
