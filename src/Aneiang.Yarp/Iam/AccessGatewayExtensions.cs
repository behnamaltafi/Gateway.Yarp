using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Aneiang.Yarp.Iam;

public sealed class AccessGatewayMarker;

public static class AccessGatewayExtensions
{
    // New simple Access mode. Legacy IAM service registration remains available during migration
    // for Dashboard SSO, but never executes a second proxy authorization decision.
    public static IServiceCollection AddAneiangAccessGateway(this IServiceCollection services,
        IConfiguration configuration, bool allowLocalHttp = false)
    {
        services.AddOptions<AccessGatewayOptions>().Bind(configuration.GetSection(AccessGatewayOptions.SectionName));
        services.Configure<AccessGatewayOptions>(x => x.AllowLocalHttp = allowLocalHttp);
        services.AddOptions<AccessGatewayOptions>()
            .Validate(x => !x.Enabled || (
                IamTransport.Allows(x.RoutesEndpoint, x.AllowLocalHttp)
                && IamTransport.Allows(x.ResolveEndpoint, x.AllowLocalHttp)
                && x.RefreshInterval >= TimeSpan.FromSeconds(5) && x.RefreshInterval <= TimeSpan.FromMinutes(2)
                && x.RequestTimeout >= TimeSpan.FromMilliseconds(100) && x.RequestTimeout <= TimeSpan.FromSeconds(10)),
                "Invalid or insecure Gateway:Access configuration.")
            .ValidateOnStart();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<AccessGatewayMarker>();
        services.AddMemoryCache();
        services.AddSingleton<AccessPolicyStore>();
        services.AddSingleton<AccessEntitlementCache>();
        services.AddHttpClient("Aneiang.Access", (sp, client) =>
        {
            client.Timeout = sp.GetRequiredService<IOptions<AccessGatewayOptions>>().Value.RequestTimeout;
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
        services.AddHostedService<AccessRouteRefreshService>();
        services.AddHealthChecks().AddCheck<AccessReadyHealthCheck>("iam-access-ready", tags: ["ready"]);
        return services;
    }

    public static IReverseProxyApplicationBuilder UseAneiangAccessGateway(this IReverseProxyApplicationBuilder proxy)
    {
        proxy.UseMiddleware<AccessAuthorizationMiddleware>();
        return proxy;
    }
}

internal sealed class AccessReadyHealthCheck(AccessPolicyStore store) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
        => Task.FromResult(store.IsReady ? HealthCheckResult.Healthy("Valid IAM access rules are cached.")
            : HealthCheckResult.Unhealthy("IAM access rules are missing or expired."));
}
