using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Template;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MMLib.OpenApiForYarp;
using MMLib.OpenApiForYarp.Configuration;

namespace Aneiang.Yarp.OpenApi;

public static class AneiangOpenApiExtensions
{
    /// <summary>Call inside AddAneiangYarp's configureReverseProxy callback.</summary>
    public static IReverseProxyBuilder AddAneiangOpenApi(this IReverseProxyBuilder proxy,
        Action<AneiangOpenApiOptions>? configure = null, Action<YarpOpenApiOptions>? configureDocuments = null)
    {
        if (proxy.Services.Any(s => s.ServiceType == typeof(AneiangOpenApiCatalog))) return proxy;
        var options = proxy.Services.AddOptions<AneiangOpenApiOptions>().BindConfiguration("Gateway:OpenApi");
        if (configure != null) options.Configure(configure);
        options.Validate(o => o.MaxClusters is > 0 and <= 1024 && o.MaxDocumentBytes is > 0 and <= 64 * 1024 * 1024,
            "OpenAPI resource limits are out of range.").ValidateOnStart();
        proxy.AddOpenApiForYarp(configureDocuments).AddDocumentTransformer<GatewayDocumentTransformer>();
        proxy.Services.AddHttpContextAccessor();
        proxy.Services.AddSingleton<AneiangOpenApiCatalog>();
        proxy.Services.Replace(ServiceDescriptor.Singleton<IClusterDocumentSource>(sp => sp.GetRequiredService<AneiangOpenApiCatalog>()));
        proxy.Services.Replace(ServiceDescriptor.Singleton<IOptions<YarpOpenApiOptions>, LiveOpenApiOptions>());
        proxy.Services.AddTransient<DocumentationFetchHandler>();
        proxy.Services.AddHttpClient("MMLib.OpenApiForYarp", (sp, client) =>
        {
            client.MaxResponseContentBufferSize = sp.GetRequiredService<IOptions<AneiangOpenApiOptions>>().Value.MaxDocumentBytes;
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false })
            .AddHttpMessageHandler<DocumentationFetchHandler>();
        return proxy;
    }

    /// <summary>
    /// Mount before UseAneiangYarpDashboard. Owns documentation middleware and endpoints only;
    /// the host continues to own authentication, deployment routing and MapReverseProxy.
    /// </summary>
    public static WebApplication UseAneiangOpenApi(this WebApplication app)
    {
        const string key = "Aneiang.OpenApi.Mapped";
        if (((IApplicationBuilder)app).Properties.ContainsKey(key)) return app;
        ((IApplicationBuilder)app).Properties[key] = true;
        var options = app.Services.GetRequiredService<IOptions<AneiangOpenApiOptions>>().Value;
        var upstream = app.Services.GetRequiredService<IOptionsMonitor<YarpOpenApiOptions>>().CurrentValue;
        ValidatePaths(options, upstream);
        if (options.Enabled && !(app.Environment.IsDevelopment() && options.AllowAnonymousInDevelopment)
            && options.AuthorizeRequest == null && string.IsNullOrWhiteSpace(options.AuthorizationPolicy))
            throw new InvalidOperationException("OpenAPI requires an authorization policy or AuthorizeRequest callback. Anonymous documentation is allowed only explicitly in Development.");

        var gate = new DocumentationGate(options, upstream, app.Environment);
        app.Use((context, next) => gate.InvokeAsync(context, next));
        if (!options.Enabled) return app;
        if (options.JsonEnabled) app.MapOpenApiForYarp();
        app.MapGet(options.CatalogPath, (AneiangOpenApiCatalog catalog) => Results.Json(new
        {
            documents = catalog.GetDocuments(), mergedDocument = catalog.MergedDocument,
            swagger = options.SwaggerEnabled ? options.SwaggerPath : null,
            scalar = options.ScalarEnabled ? options.ScalarPath : null
        }));
        if (options.SwaggerEnabled)
        {
            // The upstream adapter captures its selector at registration. A tiny per-request branch
            // reuses the adapter and embedded assets while rebuilding only its options on page load.
            app.Use(async (context, next) =>
            {
                if (!context.Request.Path.StartsWithSegments(options.SwaggerPath)) { await next(context); return; }
                var branch = new ApplicationBuilder(app.Services);
                branch.MapSwaggerUIForYarp(options.SwaggerPath.Trim('/'), ui =>
                {
                    if (context.Request.PathBase.HasValue)
                        foreach (var url in ui.ConfigObject.Urls ?? [])
                            url.Url = context.Request.PathBase + url.Url;
                });
                await branch.Build()(context);
            });
        }
        // Scalar evaluates the adapter's options callback per request, so the live source suffices.
        if (options.ScalarEnabled) app.MapScalarForYarp(options.ScalarPath);
        return app;
    }

    private static void ValidatePaths(AneiangOpenApiOptions options, YarpOpenApiOptions upstream)
    {
        var paths = new[] { options.SwaggerPath, options.ScalarPath, options.CatalogPath,
            upstream.DocumentRoutePattern, upstream.MergedDocument.RoutePattern };
        if (paths.Any(p => string.IsNullOrWhiteSpace(p) || !p.StartsWith('/') || p.StartsWith("//") ||
                p.EndsWith('/') || p.IndexOfAny(['?', '#', '\\']) >= 0) || paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length ||
            paths.Any(p => p != upstream.DocumentRoutePattern && p.Contains('{')) ||
            !upstream.DocumentRoutePattern.Contains("{cluster}", StringComparison.Ordinal) ||
            upstream.DocumentRoutePattern.Replace("{cluster}", "").IndexOfAny(['{', '}']) >= 0 ||
            paths.Where(p => p != options.SwaggerPath).Any(p => p.StartsWith(options.SwaggerPath + "/", StringComparison.OrdinalIgnoreCase)) ||
            paths.Where(p => p != options.ScalarPath).Any(p => p.StartsWith(options.ScalarPath + "/", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("OpenAPI paths must be distinct absolute local paths; DocumentRoutePattern must contain only the {cluster} parameter.");
        if (upstream.CacheDuration <= TimeSpan.Zero || upstream.CacheDuration > TimeSpan.FromHours(1) ||
            upstream.FetchTimeout <= TimeSpan.Zero || upstream.FetchTimeout > TimeSpan.FromMinutes(1))
            throw new InvalidOperationException("OpenAPI cache duration must be within one hour and fetch timeout within one minute.");
    }
}

internal sealed class DocumentationGate(AneiangOpenApiOptions options, YarpOpenApiOptions upstream, IHostEnvironment environment)
{
    private readonly SemaphoreSlim _buildLock = new(1, 1);
    private readonly TemplateMatcher _documentMatcher = new(TemplateParser.Parse(upstream.DocumentRoutePattern), new());
    private CatalogSnapshot? _last;

    internal async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        var path = context.Request.Path;
        var swagger = path.StartsWithSegments(options.SwaggerPath);
        var scalar = path.StartsWithSegments(options.ScalarPath);
        var values = new RouteValueDictionary();
        var document = _documentMatcher.TryMatch(path, values);
        var merged = path.Equals(new PathString(upstream.MergedDocument.RoutePattern));
        var catalogRequest = path.Equals(new PathString(options.CatalogPath));
        if (!(swagger || scalar || document || merged || catalogRequest)) { await next(context); return; }
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        if (!options.Enabled || (swagger && !options.SwaggerEnabled) || (scalar && !options.ScalarEnabled) ||
            ((document || merged) && !options.JsonEnabled) || (merged && !upstream.MergeDocuments) ||
            options.IsAvailableOnEndpoint?.Invoke(context) == false)
        { context.Response.StatusCode = 404; return; }

        var management = context.RequestServices.GetService<Aneiang.Yarp.Iam.IamManagementAuthorization>();
        var allowed = management is null
            ? environment.IsDevelopment() && options.AllowAnonymousInDevelopment
            : await management.AuthorizeAsync(context, service: false) == 200;
        if (management is null && !allowed && options.AuthorizeRequest != null) allowed = await options.AuthorizeRequest(context);
        if (management is null && !allowed && options.AuthorizationPolicy is { Length: > 0 } policy)
        {
            var authorization = context.RequestServices.GetService<IAuthorizationService>();
            var policies = context.RequestServices.GetService<IAuthorizationPolicyProvider>();
            if (authorization != null && policies != null && await policies.GetPolicyAsync(policy) != null)
                allowed = (await authorization.AuthorizeAsync(context.User, context, policy)).Succeeded;
        }
        if (!allowed) { context.Response.StatusCode = context.User.Identity?.IsAuthenticated == true ? 403 : 401; return; }
        context.Items[typeof(AneiangOpenApiOptions)] = true;

        // Serialize document builds to prevent an old in-flight build from repopulating a cache
        // after invalidation. UI/assets/catalog requests do not wait on document retrieval.
        var locked = false;
        try
        {
            if (document || merged)
            {
                locked = await _buildLock.WaitAsync(TimeSpan.FromSeconds(1), context.RequestAborted);
                if (!locked) { context.Response.StatusCode = 429; return; }
            }
            var snapshot = context.RequestServices.GetRequiredService<AneiangOpenApiCatalog>().Capture();
            context.Items[AneiangOpenApiCatalog.RequestSnapshotKey] = snapshot;
            if (snapshot.Clusters.Length > options.MaxClusters) { context.Response.StatusCode = 503; return; }
            if (document && !merged)
            {
                var cluster = snapshot.Options.Clusters.Keys.FirstOrDefault(c => string.Equals(c, values["cluster"]?.ToString(), StringComparison.OrdinalIgnoreCase));
                if (cluster == null) { context.Response.StatusCode = 404; return; }
                context.Request.RouteValues["cluster"] = cluster;
            }
            if (locked && (_last == null || !ReferenceEquals(snapshot.Root, _last.Root) ||
                !snapshot.Configs.SequenceEqual(_last.Configs, ReferenceEqualityComparer.Instance)))
            {
                var cache = context.RequestServices.GetRequiredService<IMemoryCache>();
                foreach (var id in snapshot.Clusters.Select(c => c.ClusterId).Concat(_last?.Clusters.Select(c => c.ClusterId) ?? []).Distinct())
                    // Version-pinned MMLib v1.1.0 cache key. Covered by destination/route/disable tests.
                    cache.Remove("MMLib.OpenApiForYarp:cluster:" + id);
                _last = snapshot;
            }
            await next(context);
        }
        catch (Exception exception) when (!context.Response.HasStarted && !context.RequestAborted.IsCancellationRequested)
        {
            // Do not include downstream content, URLs or credentials in the response or log.
            context.RequestServices.GetRequiredService<ILogger<DocumentationGate>>()
                .LogWarning("OpenAPI request failed ({ExceptionType}).", exception.GetType().Name);
            context.Response.Clear();
            context.Response.Headers.CacheControl = "no-store";
            context.Response.StatusCode = 502;
        }
        finally { if (locked) _buildLock.Release(); }
    }
}
