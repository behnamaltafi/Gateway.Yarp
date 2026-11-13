using Aneiang.Yarp.Dashboard.Modules.Dashboard.Controllers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Aneiang.Yarp.Iam;

namespace Aneiang.Yarp.Dashboard.Infrastructure.Auth;

/// <summary>
/// Configures MVC conventions and filters for the Dashboard:
/// - Sets <see cref="DashboardPagesController.RoutePrefix"/> from options
/// - Resolves JWT secret via <see cref="JwtSecretProvider"/>
/// - Adds <see cref="DashboardRouteConvention"/> for route prefix
/// - Adds <see cref="DashboardAuthFilter"/> when auth is enabled
/// </summary>
internal sealed class DashboardMvcOptionsSetup : IConfigureOptions<MvcOptions>
{
    private readonly IOptions<DashboardOptions> _dashboardOptions;
    private readonly JwtSecretProvider _jwtSecretProvider;
    private readonly IDashboardAuthorizationService _authService;
    private readonly IamManagementAuthorization? _management;

    public DashboardMvcOptionsSetup(
        IOptions<DashboardOptions> dashboardOptions,
        JwtSecretProvider jwtSecretProvider,
        IDashboardAuthorizationService authService,
        IamManagementAuthorization? management = null)
    {
        _dashboardOptions = dashboardOptions;
        _jwtSecretProvider = jwtSecretProvider;
        _authService = authService;
        _management = management;
    }

    public void Configure(MvcOptions mvcOptions)
    {
        var opts = _dashboardOptions.Value;
        var prefix = opts.RoutePrefix.Trim('/');

        DashboardPagesController.RoutePrefix = prefix;
        if (_management is null)
            opts.Auth.JwtSecret = _jwtSecretProvider.GetSecret(opts.Auth.JwtSecret);

        mvcOptions.Conventions.Add(new DashboardRouteConvention(prefix));

        if (_management is not null || opts.Auth.AuthMode != DashboardAuthMode.None || opts.Auth.AuthorizeRequest != null)
        {
            var authFilter = new DashboardAuthFilter(_authService, prefix);
            mvcOptions.Filters.Add(authFilter);
        }
    }
}
