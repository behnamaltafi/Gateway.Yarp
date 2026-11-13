using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Aneiang.Yarp.Dashboard.Extensions;
using Aneiang.Yarp.Dashboard.Modules.Dashboard.Controllers;
using Aneiang.Yarp.Iam;

namespace Aneiang.Yarp.Dashboard.Infrastructure.Auth;

/// <summary>
/// Async auth filter for Dashboard controllers.
/// Applies to all controllers under the Aneiang.Yarp.Dashboard namespace.
/// Skips login/logout actions. Redirects browser to login; returns 401 JSON for API calls.
/// Uses IDashboardAuthorizationService for unified authorization check.
/// </summary>
internal sealed class DashboardAuthFilter : IAsyncAuthorizationFilter
{
    private readonly IDashboardAuthorizationService _authService;
    private readonly string _routePrefix;

    public DashboardAuthFilter(IDashboardAuthorizationService authService, string routePrefix)
    {
        _authService = authService;
        _routePrefix = routePrefix;
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        if (context.ActionDescriptor is not ControllerActionDescriptor { ControllerTypeInfo: var ci })
            return;

        if (context.HttpContext.RequestServices.GetService<IamManagementAuthorization>() is { } management)
        {
            var type = ci.AsType();
            if (ci.Assembly != typeof(DashboardAuthController).Assembly
                && ci.Assembly.GetName().Name?.StartsWith("Aneiang.Yarp.Plugin.", StringComparison.Ordinal) != true)
                return;
            await AuthorizeSsoAsync(context, management, type);
            return;
        }

        if (!ci.Namespace?.StartsWith("Aneiang.Yarp.Dashboard.", StringComparison.Ordinal) == true)
            return;

        // Skip login/logout actions - they are public
        var actionName = ((ControllerActionDescriptor)context.ActionDescriptor).ActionName;
        if (string.Equals(actionName, "Login", StringComparison.OrdinalIgnoreCase)
            || string.Equals(actionName, "Logout", StringComparison.OrdinalIgnoreCase))
            return;

        // Use authorization service for unified check
        if (await _authService.IsAuthorizedAsync(context.HttpContext)) return;

        var request = context.HttpContext.Request;
        var isApi = (request.Headers["Accept"].FirstOrDefault()?.Contains("application/json") == true)
            || request.Path.StartsWithSegments($"/{_routePrefix}/api");

        if (isApi)
            context.Result = new JsonResult(new { code = 401, message = "Unauthorized" }) { StatusCode = 401 };
        else
            context.Result = new RedirectResult($"/{_routePrefix}/login");
    }

    private async Task AuthorizeSsoAsync(AuthorizationFilterContext context, IamManagementAuthorization management, Type type)
    {
        var http = context.HttpContext;
        var request = http.Request;
        var action = ((ControllerActionDescriptor)context.ActionDescriptor).ActionName;
        var page = request.Path.StartsWithSegments($"/{_routePrefix}", out var remaining) && !remaining.StartsWithSegments("/api")
            && type == typeof(DashboardPagesController) && HttpMethods.IsGet(request.Method);
        var authController = type == typeof(DashboardAuthController);
        if (authController && (remaining.StartsWithSegments("/api/2fa") || action == "Login" && !HttpMethods.IsGet(request.Method)))
        {
            context.Result = new NotFoundResult();
            return;
        }
        if (!management.AllowsTransport(http))
        {
            context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
            return;
        }
        if (authController && action is "Login" or "SignedOut") return;

        var service = type.Assembly != typeof(DashboardAuthController).Assembly
            && request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
        var logout = authController && action == "Logout";
        var status = logout ? await management.AuthenticateBrowserAsync(http) : await management.AuthorizeAsync(http, service);
        if (status != 200)
        {
            context.Result = status == 401 && page
                ? new ChallengeResult(DashboardSsoExtensions.OidcScheme, new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                {
                    RedirectUri = request.PathBase + "/" + _routePrefix + remaining + request.QueryString
                })
                : new StatusCodeResult(status);
            return;
        }
        if (!service && !HttpMethods.IsGet(request.Method) && !HttpMethods.IsHead(request.Method) && !HttpMethods.IsOptions(request.Method)
            && !await http.RequestServices.GetRequiredService<IAntiforgery>().IsRequestValidAsync(http))
            context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
    }
}
