using Aneiang.Yarp.Dashboard.Infrastructure;
using Aneiang.Yarp.Dashboard.Infrastructure.Auth;
using Aneiang.Yarp.Dashboard.Infrastructure.Deployment;
using Aneiang.Yarp.OpenApi;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Aneiang.Yarp.Dashboard.Extensions;

public static class DashboardOpenApiExtensions
{
    /// <summary>Reuse Dashboard authentication and restrict docs to management listeners in Split mode.</summary>
    public static IServiceCollection AddAneiangOpenApiDashboard(this IServiceCollection services)
    {
        services.Configure<AneiangOpenApiOptions>(options =>
        {
            options.AuthorizeRequest ??= context =>
            {
                var auth = context.RequestServices.GetRequiredService<IOptions<DashboardOptions>>().Value.Auth;
                // Dashboard's None mode is deliberately insufficient for protected documentation.
                if (auth.AuthMode == DashboardAuthMode.None && auth.AuthorizeRequest == null)
                    return Task.FromResult(false);
                return context.RequestServices.GetRequiredService<IDashboardAuthorizationService>().IsAuthorizedAsync(context);
            };
            options.IsAvailableOnEndpoint ??= context =>
            {
                var deployment = context.RequestServices.GetService<IOptions<DeploymentOptions>>()?.Value;
                if (deployment?.Mode is DeploymentMode.DashboardOnly or DeploymentMode.ProxyOnly) return false;
                if (deployment?.Mode != DeploymentMode.Split) return true;
                var resolver = context.RequestServices.GetService<EndpointRoleResolver>();
                return resolver?.GetByPort(context.Connection.LocalPort)?.Role is "Dashboard" or "All";
            };
        });
        return services;
    }
}
