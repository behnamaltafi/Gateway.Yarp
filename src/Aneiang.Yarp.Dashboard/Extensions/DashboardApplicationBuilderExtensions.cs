using Aneiang.Yarp.Dashboard.Infrastructure;
using Aneiang.Yarp.Dashboard.Infrastructure.Deployment;
using Aneiang.Yarp.Dashboard.Infrastructure.Middleware;
using Aneiang.Yarp.Dashboard.Infrastructure.Plugin;
using Aneiang.Yarp.Dashboard.Infrastructure.Realtime;
using Aneiang.Yarp.Dashboard.Infrastructure.Yarp;
using Aneiang.Yarp.Iam;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Model;

namespace Aneiang.Yarp.Dashboard.Extensions;

/// <summary>
/// IApplicationBuilder and IEndpointRouteBuilder extensions for Aneiang.Yarp.Dashboard.
/// </summary>
public static class DashboardApplicationBuilderExtensions
{
    private const string DashboardConfiguredKey = "__AneiangYarpDashboard_Configured";

    /// <summary>Controls which built-in middleware is automatically mounted by <see cref="UseAneiangYarpDashboard(IApplicationBuilder, DashboardUseOptions?, Action{IReverseProxyApplicationBuilder}?)"/>.</summary>
    public sealed class DashboardUseOptions
    {
        /// <summary>Override <see cref="DeploymentOptions.AutoUseMiddleware"/>. Null means use deployment configuration.</summary>
        public bool? AutoUseMiddleware { get; set; }

        /// <summary>Mount deployment endpoint-router and health-check middleware when auto-use is enabled.</summary>
        public bool UseDeploymentMiddleware { get; set; } = true;

        /// <summary>Mount proxy request/response capture middleware when auto-use is enabled.</summary>
        public bool UseProxyRequestCapture { get; set; } = true;

        /// <summary>Mount built-in proxy branch middleware when auto-use is enabled.</summary>
        public bool UseBuiltInProxyPipeline { get; set; } = true;

        /// <summary>
        /// Automatically register a default permissive CORS middleware (AllowAnyOrigin/Method/Header).
        /// Set to <c>false</c> and call <c>app.UseCors(...)</c> yourself before <c>app.UseAneiangYarpDashboard(...)</c>
        /// to use a custom CORS policy.
        /// </summary>
        public bool AutoUseCors { get; set; } = true;

        /// <summary>
        /// Automatically register authorization middleware (<c>UseAuthorization()</c>).
        /// Required for YARP routes with non-<c>Anonymous</c> <c>AuthorizationPolicy</c>.
        /// Set to <c>false</c> if you call <c>app.UseAuthorization()</c> yourself.
        /// Call <c>app.UseAuthentication()</c> before <c>UseAneiangYarpDashboard()</c> if your
        /// auth policies require authenticated users.
        /// </summary>
        public bool AutoUseAuthorization { get; set; } = true;
    }

    /// <summary>
    /// Register Dashboard middleware and map the YARP proxy endpoint with core middleware
    /// in the correct pipeline order. When <see cref="DeploymentOptions.Mode"/> is set,
    /// this method intelligently mounts only the components needed for the current mode
    /// (AllInOne / Split / ProxyOnly / DashboardOnly).
    /// </summary>
    public static IApplicationBuilder UseAneiangYarpDashboard(
        this IApplicationBuilder app,
        Action<IReverseProxyApplicationBuilder>? configureProxyPipeline = null)
        => app.UseAneiangYarpDashboard(useOptions: null, configureProxyPipeline);

    /// <summary>
    /// Register Dashboard middleware with explicit opt-out controls for advanced custom pipelines.
    /// </summary>
    public static IApplicationBuilder UseAneiangYarpDashboard(
        this IApplicationBuilder app,
        DashboardUseOptions? useOptions,
        Action<IReverseProxyApplicationBuilder>? configureProxyPipeline = null)
    {
        if (app.Properties.TryGetValue(DashboardConfiguredKey, out _))
        {
            return app;
        }
        app.Properties[DashboardConfiguredKey] = true;

        useOptions ??= new DashboardUseOptions();
        var mode = DeploymentMode.AllInOne;
        var autoUseMiddleware = true;
        try
        {
            var options = app.ApplicationServices.GetService<IOptions<DeploymentOptions>>();
            if (options != null)
            {
                mode = options.Value.Mode;
                autoUseMiddleware = options.Value.AutoUseMiddleware;
            }
        }
        catch
        {
            // Fall back to AllInOne if DeploymentOptions is not registered (backward compat)
        }

        autoUseMiddleware = useOptions.AutoUseMiddleware ?? autoUseMiddleware;

        var dashboardActive = mode != DeploymentMode.ProxyOnly;
        var proxyActive = mode != DeploymentMode.DashboardOnly;
        var management = app.ApplicationServices.GetService<IamManagementAuthorization>();
        var dashOpts = app.ApplicationServices.GetService<IOptions<DashboardOptions>>()?.Value;
        var routePrefix = (dashOpts?.RoutePrefix ?? "apigateway").Trim('/');

        // CORS middleware must appear after UseRouting() but before endpoint execution.
        // YARP routes may carry CorsPolicy metadata (set via appsettings or Dashboard),
        // which requires an active CORS middleware in the pipeline.
        // Set AutoUseCors = false and call app.UseCors(...) yourself for a custom policy.
        if (useOptions.AutoUseCors)
        {
            app.UseCors(policy => policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
        }

        // Authorization middleware — same rationale as CORS above.
        // YARP routes may carry AuthorizationPolicy metadata; without UseAuthorization()
        // in the pipeline, ASP.NET Core will throw InvalidOperationException at runtime.
        // Set AutoUseAuthorization = false if you already call UseAuthorization() before
        // UseAneiangYarpDashboard(), or if you need UseAuthentication() before it.
        if (useOptions.AutoUseAuthorization)
        {
            app.UseAuthorization();
        }

        if (autoUseMiddleware && useOptions.UseDeploymentMiddleware)
        {
            UseDeploymentMiddlewareIfAvailable(app);
        }

        if (management is not null)
        {
            app.Use(async (context, next) =>
            {
                var path = context.Request.Path;
                if (path.StartsWithSegments($"/{routePrefix}/hubs"))
                {
                    // Cross-origin browser connections must not inherit a dashboard session.
                    var origin = context.Request.Headers.Origin.ToString();
                    if (origin.Length != 0 && !origin.Equals($"{context.Request.Scheme}://{context.Request.Host}", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        return;
                    }
                    var status = await management.AuthorizeAsync(context, service: false);
                    if (status != StatusCodes.Status200OK)
                    {
                        context.Response.StatusCode = status;
                        return;
                    }
                }
                await next(context);
            });
        }

        if (dashboardActive || proxyActive)
        {
            app.UseResponseCompression();
        }

        if (dashboardActive)
        {
            app.UseStaticFiles();
        }

        var iamEnabled = app.ApplicationServices.GetService<IamGatewayMarker>() is not null;
        if (autoUseMiddleware)
        {
            app.Use((context, next) => iamEnabled && proxyActive && context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>() is not null
                ? next(context)
                : context.RequestServices.GetRequiredService<PluginRuntimeDomainManager>().InvokeMiddlewareAsync(context, next));
        }

        if (app is IEndpointRouteBuilder endpoints)
        {
            if (dashboardActive)
            {
                endpoints.Map("/_content/Aneiang.Yarp.Dashboard/{**path}", async context =>
                {
                    var path = context.Request.RouteValues["path"]?.ToString() ?? "";
                    var filePath = $"_content/Aneiang.Yarp.Dashboard/{path}";

                    var fileInfo = context.RequestServices
                        .GetRequiredService<IWebHostEnvironment>()
                        .WebRootFileProvider
                        .GetFileInfo(filePath);

                    if (fileInfo.Exists)
                    {
                        context.Response.ContentType = GetContentType(filePath);
                        await context.Response.SendFileAsync(fileInfo);
                    }
                    else
                    {
                        context.Response.StatusCode = StatusCodes.Status404NotFound;
                    }
                });

                endpoints.MapHub<TrafficHub>($"/{routePrefix}/hubs/traffic", options => options.CloseOnAuthenticationExpiration = true);
                endpoints.MapHub<OverviewHub>($"/{routePrefix}/hubs/overview", options => options.CloseOnAuthenticationExpiration = true);
            }

            if (proxyActive)
            {
                endpoints.MapReverseProxy(proxyPipeline =>
                {
                    // Mandatory IAM PEP is deliberately outside Plugin Center and runs before
                    // transforms/plugins. Its service marker is registered only for IAM-enabled hosts.
                    if (iamEnabled)
                    {
                        proxyPipeline.UseAneiangIamGateway();
                        if (management is not null)
                            proxyPipeline.Use((context, next) =>
                            {
                                var request = context.Request;
                                request.Headers.Remove(DashboardSsoExtensions.CsrfHeader);
                                var cookies = request.Headers.Cookie.ToString().Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                                    .Where(cookie => !IsDashboardCookie(cookie)).ToArray();
                                if (cookies.Length == 0) request.Headers.Remove("Cookie");
                                else request.Headers.Cookie = string.Join("; ", cookies);
                                return next(context);
                            });
                        if (autoUseMiddleware)
                            proxyPipeline.Use((context, next) => context.RequestServices
                                .GetRequiredService<PluginRuntimeDomainManager>().InvokeMiddlewareAsync(context, next));
                    }
                    if (autoUseMiddleware && useOptions.UseBuiltInProxyPipeline)
                    {
                        proxyPipeline.UseMiddleware<BuiltinTransformMiddleware>();
                        proxyPipeline.Use((context, next) => context.RequestServices
                            .GetRequiredService<PluginRuntimeDomainManager>()
                            .InvokeProxyPipelineAsync(context, next));
                    }
                    configureProxyPipeline?.Invoke(proxyPipeline);
                });
            }
        }

        return app;
    }

    private static bool IsDashboardCookie(string cookie)
    {
        var name = cookie.Split('=', 2)[0].Trim();
        return name.StartsWith(IamManagementAuthorization.BrowserCookieName, StringComparison.Ordinal)
            || name.StartsWith(IamManagementAuthorization.CsrfCookieName, StringComparison.Ordinal)
            || name.StartsWith(IamManagementAuthorization.LocalBrowserCookieName, StringComparison.Ordinal)
            || name == "dashboard_token";
    }

    private static void UseDeploymentMiddlewareIfAvailable(IApplicationBuilder app)
    {
        var services = app.ApplicationServices;
        var resolver = services.GetService<EndpointRoleResolver>();
        var deploymentOptions = services.GetService<IOptions<DeploymentOptions>>()?.Value;

        if (resolver != null && deploymentOptions != null && deploymentOptions.Mode != DeploymentMode.AllInOne)
        {
            app.UseMiddleware<EndpointRouterMiddleware>();
        }

        if (deploymentOptions?.HealthCheck.Enabled == true)
        {
            app.UseMiddleware<HealthCheckMiddleware>();
        }
    }

    private static string GetContentType(string filePath)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        return ext switch
        {
            ".js" => "application/javascript",
            ".css" => "text/css",
            ".html" => "text/html",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".svg" => "image/svg+xml",
            ".woff" => "font/woff",
            ".woff2" => "font/woff2",
            ".ttf" => "font/ttf",
            ".eot" => "application/vnd.ms-fontobject",
            _ => "application/octet-stream"
        };
    }
}
