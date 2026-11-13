using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Aneiang.Yarp.Extensions;
using Aneiang.Yarp.OpenApi;
using Aneiang.Yarp.Models;
using Aneiang.Yarp.Services;
using Aneiang.Yarp.Storage;
using Aneiang.Yarp.Storage.Sqlite;
using Aneiang.Yarp.Dashboard.Modules.GatewayConfig.Services;
using Aneiang.Yarp.Dashboard.Infrastructure.I18n;
using Aneiang.Yarp.Dashboard.Extensions;
using Aneiang.Yarp.Dashboard.Infrastructure;
using Aneiang.Yarp.Dashboard.Infrastructure.Auth;
using Aneiang.Yarp.Dashboard.Infrastructure.Deployment;
using Aneiang.Yarp.Dashboard.Infrastructure.Middleware;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;
using MMLib.OpenApiForYarp.Configuration;
using Yarp.ReverseProxy.Configuration;

var failures = new List<string>();
var passed = 0;
var apiToken = Guid.NewGuid().ToString("N");
var fetches = 0;
await using var backend = EmptyHost();
backend.MapGet("/openapi/v1.json", () => { Interlocked.Increment(ref fetches); return Results.Text(Spec("Alpha", "string"), "application/json"); });
backend.MapGet("/invalid.json", () => Results.Text("{broken json"));
backend.MapGet("/slow.json", async (HttpContext context) => { await Task.Delay(3000, context.RequestAborted); return Results.Text(Spec("slow", "string")); });
backend.MapGet("/large.json", () => Results.Text(new string('x', 8192)));
backend.MapGet("/redirect.json", () => Results.Redirect("/openapi/v1.json"));
backend.MapGet("/items/{id}", (HttpContext context, string id) =>
    context.Request.Headers.Authorization == "Bearer " + apiToken ? Results.Ok(new { id }) : Results.Unauthorized());
await backend.StartAsync();
await using var second = EmptyHost();
second.MapGet("/openapi/v1.json", () => Results.Text(Spec("Beta", "integer"), "application/json"));
await second.StartAsync();
var address = backend.Urls.Single();
var secondAddress = second.Urls.Single();

await using var app = Gateway();
app.UseRouting();
app.UseAneiangOpenApi();
app.MapReverseProxy();
var provider = app.Services.GetRequiredService<AneiangProxyConfigProvider>();
var clusters = new List<ClusterConfig> { Cluster("alpha", address), Cluster("private", secondAddress, enabled: false) };
var routes = new List<RouteConfig> { Route("alpha", "/api/{**rest}", "PathRemovePrefix", "/api"), Route("private", "/private/{**rest}", "PathRemovePrefix", "/private") };
provider.Update(routes, clusters);
await app.StartAsync();
using var client = new HttpClient { BaseAddress = new Uri(app.Urls.Single()) };
client.DefaultRequestHeaders.Add("X-Docs-Key", apiToken);

await Check("Single service, gateway paths, methods, parameters, bodies and response schemas", async () =>
{
    var doc = await Document("alpha");
    var paths = doc.RootElement.GetProperty("paths");
    var item = paths.GetProperty("/api/items/{id}");
    Assert(item.GetProperty("get").GetProperty("parameters")[0].GetProperty("name").GetString() == "id");
    Assert(item.GetProperty("post").TryGetProperty("requestBody", out _));
    Assert(doc.RootElement.GetProperty("components").GetProperty("schemas").TryGetProperty("Item", out _));
});
await Check("Internal endpoints are excluded", async () => Assert(!(await Document("alpha")).RootElement.GetProperty("paths").TryGetProperty("/api/internal", out _)));
await Check("All server levels target the gateway and security definitions survive", async () =>
{
    var json = await client.GetStringAsync("/openapi/alpha.json");
    Assert(!json.Contains("internal.example"));
    var doc = JsonDocument.Parse(json).RootElement;
    Assert(doc.GetProperty("servers")[0].GetProperty("url").GetString() == "/");
    Assert(doc.GetProperty("components").GetProperty("securitySchemes").GetProperty("bearer").GetProperty("scheme").GetString() == "bearer");
    Assert(doc.GetProperty("paths").GetProperty("/api/items/{id}").GetProperty("get").GetProperty("security")[0].TryGetProperty("bearer", out _));
});
await Check("Swagger UI and Scalar coexist and use gateway JSON", async () =>
{
    Assert((await client.GetStringAsync("/swagger/index.js")).Contains("swagger-ui"));
    var swagger = await client.GetStringAsync("/swagger/index.js");
    var scalar = await client.GetStringAsync("/scalar");
    Assert(swagger.Contains("/openapi/alpha.json"), swagger);
    Assert(scalar.Contains("openapi/alpha.json"), scalar);
    Assert(!swagger.Contains("/openapi/private.json") && !scalar.Contains("openapi/private.json"));
    Assert(swagger.Contains("/openapi/all.json") && scalar.Contains("openapi/all.json"));
});
await Check("Swagger embedded assets load", async () => Assert((await client.GetAsync("/swagger/swagger-ui-bundle.js")).IsSuccessStatusCode));
await Check("Unknown and opted-out documents return 404", async () =>
{
    Assert((await client.GetAsync("/openapi/missing.json")).StatusCode == HttpStatusCode.NotFound);
    Assert((await client.GetAsync("/openapi/private.json")).StatusCode == HttpStatusCode.NotFound);
});
await Check("Disabled cluster contributes no paths or schemas to merged document", async () =>
{
    var doc = await Json("/openapi/all.json");
    Assert(doc.RootElement.GetProperty("paths").EnumerateObject().All(p => !p.Name.StartsWith("/private/")));
    Assert(doc.RootElement.GetProperty("components").GetProperty("schemas").GetProperty("Item").GetProperty("properties").GetProperty("id").GetProperty("type").GetString() == "string");
});
await Check("Built-in document caching avoids repeated downstream requests", async () =>
{
    var before = fetches;
    await Document("alpha"); await Document("alpha");
    Assert(fetches == before);
});
await Check("Case-insensitive requests share canonical invalidated cache entries", async () => Assert((await client.GetAsync("/openapi/ALPHA.json")).IsSuccessStatusCode));
await Check("Documentation authorization covers both UIs, assets, catalog and all JSON", async () =>
{
    using var anonymous = new HttpClient { BaseAddress = client.BaseAddress };
    foreach (var path in new[] { "/swagger", "/swagger/index.html", "/swagger/swagger-ui-bundle.js", "/scalar", "/scalar/scalar.js", "/openapi/catalog", "/openapi/alpha.json", "/openapi/all.json" })
        Assert((await anonymous.GetAsync(path)).StatusCode == HttpStatusCode.Unauthorized, path);
});
await Check("Actual API forwarding rejects missing credentials and accepts authorized calls", async () =>
{
    Assert((await client.GetAsync("/api/items/42")).StatusCode == HttpStatusCode.Unauthorized);
    using var request = new HttpRequestMessage(HttpMethod.Get, "/api/items/42");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);
    var response = await client.SendAsync(request);
    Assert(response.IsSuccessStatusCode && (await response.Content.ReadAsStringAsync()).Contains("42"));
});
await Check("Adding a cluster refreshes JSON, catalog, Swagger and Scalar without restart", async () =>
{
    clusters.Add(Cluster("beta", secondAddress));
    routes.Add(Route("beta", "/other/{**rest}", "PathRemovePrefix", "/other"));
    provider.Update(routes, clusters);
    Assert((await Document("beta")).RootElement.GetProperty("paths").TryGetProperty("/other/items/{id}", out _));
    Assert((await client.GetStringAsync("/openapi/catalog")).Contains("beta"));
    Assert((await client.GetStringAsync("/swagger/index.js")).Contains("/openapi/beta.json"));
    Assert((await client.GetStringAsync("/scalar")).Contains("openapi/beta.json"));
});
await Check("Multiple services merge with renamed duplicate schemas and valid references", async () =>
{
    var doc = await Json("/openapi/all.json");
    Assert(doc.RootElement.GetProperty("paths").TryGetProperty("/api/items/{id}", out _));
    Assert(doc.RootElement.GetProperty("paths").TryGetProperty("/other/items/{id}", out _));
    Assert(doc.RootElement.GetProperty("components").GetProperty("schemas").EnumerateObject().Count() == 2);
    Assert(doc.RootElement.GetProperty("paths").GetProperty("/other/items/{id}").GetProperty("get").GetProperty("security")[0].TryGetProperty("bearer", out _));
});
await Check("Route changes invalidate cached gateway paths immediately", async () =>
{
    routes[0] = Route("alpha", "/new/{**rest}", "PathRemovePrefix", "/new");
    provider.Update(routes, clusters);
    var paths = (await Document("alpha")).RootElement.GetProperty("paths");
    Assert(paths.TryGetProperty("/new/items/{id}", out _) && !paths.TryGetProperty("/api/items/{id}", out _));
});
await Check("Destination changes invalidate cached schemas immediately", async () =>
{
    clusters[0] = Cluster("alpha", secondAddress);
    provider.Update(routes, clusters);
    Assert((await Document("alpha")).RootElement.GetProperty("components").GetProperty("schemas").GetProperty("Item").GetProperty("properties").GetProperty("id").GetProperty("type").GetString() == "integer");
});
await Check("Disabling a cluster removes cached JSON and both UI entries", async () =>
{
    clusters[1] = Cluster("private", secondAddress, enabled: false);
    clusters[2] = Cluster("beta", secondAddress, enabled: false);
    provider.Update(routes, clusters);
    Assert((await client.GetAsync("/openapi/beta.json")).StatusCode == HttpStatusCode.NotFound);
    Assert(!(await client.GetStringAsync("/swagger/index.js")).Contains("/openapi/beta.json"));
    Assert(!(await client.GetStringAsync("/scalar")).Contains("openapi/beta.json"));
    Assert(!(await Json("/openapi/all.json")).RootElement.GetProperty("paths").TryGetProperty("/other/items/{id}", out _));
});
await Check("Cluster deletion removes previously cached document and catalog", async () =>
{
    clusters.RemoveAt(2); routes.RemoveAt(2);
    provider.Update(routes, clusters);
    Assert((await client.GetAsync("/openapi/beta.json")).StatusCode == HttpStatusCode.NotFound);
    Assert(!(await client.GetStringAsync("/openapi/catalog")).Contains("beta"));
});
foreach (var transform in new[] { "PathPattern", "PathPrefix", "PathRemovePrefix", "PathSet", "passthrough" })
await Check($"Path transform: {transform}", async () =>
{
    clusters[0] = Cluster("alpha", address);
    routes[0] = transform switch
    {
        "PathPattern" => Route("alpha", "/edge/{**rest}", transform, "/{**rest}"),
        "PathPrefix" => Route("alpha", "/{**rest}", transform, "/backend"),
        "PathRemovePrefix" => Route("alpha", "/edge/{**rest}", transform, "/edge"),
        "PathSet" => Route("alpha", "/one", transform, "/fixed"),
        _ => Route("alpha", "/{**rest}")
    };
    // Prefix's downstream document includes /backend/items; PathSet's document includes /fixed.
    clusters[0] = Cluster("alpha", address, settings: new() { ExcludePaths = ["internal"] });
    provider.Update(routes, clusters);
    var paths = (await Document("alpha")).RootElement.GetProperty("paths");
    var expected = transform switch { "PathPattern" or "PathRemovePrefix" => "/edge/items/{id}", "PathSet" => "/one", _ => "/items/{id}" };
    Assert(paths.TryGetProperty(expected, out _), paths.ToString());
});
await Check("Multiple routes select a canonical path and honor its HTTP method restrictions", async () =>
{
    routes[0] = Route("alpha", "/api/{**rest}", "PathRemovePrefix", "/api") with { Match = new() { Path = "/api/{**rest}", Methods = ["GET"] } };
    routes.Add(Route("alpha", "/v2/{**rest}", "PathRemovePrefix", "/v2") with { RouteId = "alpha-v2" });
    provider.Update(routes, clusters);
    var paths = (await Document("alpha")).RootElement.GetProperty("paths");
    Assert(paths.TryGetProperty("/api/items/{id}", out _), paths.ToString());
    Assert(paths.GetProperty("/api/items/{id}").TryGetProperty("get", out _) && !paths.GetProperty("/api/items/{id}").TryGetProperty("post", out _));
});
await Check("Runtime include/exclude filters and display titles apply", async () =>
{
    clusters[0] = Cluster("alpha", address, settings: new() { Title = "Updated API", IncludePaths = ["^/v2/"], ExcludePaths = ["internal"] });
    provider.Update(routes, clusters);
    var doc = await Document("alpha");
    Assert(doc.RootElement.GetProperty("info").GetProperty("title").GetString() == "Updated API");
    Assert(doc.RootElement.GetProperty("paths").EnumerateObject().All(p => p.Name.StartsWith("/v2/")));
});
await Check("Native metadata editing and persistence/rollback representation are lossless", () =>
{
    var json = Aneiang.Yarp.Serialization.YarpJsonConfig.SerializeCluster(clusters[0]);
    var edited = Aneiang.Yarp.Serialization.YarpJsonConfig.DeserializeCluster(json)!;
    var entity = new DynamicClusterConfig { Config = edited }.ToEntity();
    var restored = entity.ToClusterConfig();
    Assert(restored.Config.Metadata!["OpenApi.Settings"] == clusters[0].Metadata!["OpenApi.Settings"]);
    Assert(restored.Config.Metadata["OpenApi.Enabled"] == "true");
    return Task.CompletedTask;
});
foreach (var documentPath in new[] { "/invalid.json", "/slow.json", "/large.json", "/redirect.json" })
await Check($"Downstream failure stays contained: {documentPath}", async () =>
{
    clusters[0] = Cluster("alpha", address, settings: new() { OpenApiPath = documentPath });
    provider.Update(routes, clusters);
    var response = await client.GetAsync("/openapi/alpha.json");
    Assert(response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadGateway, response.StatusCode.ToString());
    Assert((await client.GetAsync("/openapi/catalog")).IsSuccessStatusCode);
});
await Check("Unavailable downstream does not stop gateway", async () =>
{
    clusters[0] = Cluster("alpha", "http://127.0.0.1:1"); provider.Update(routes, clusters);
    Assert((await client.GetAsync("/openapi/alpha.json")).StatusCode == HttpStatusCode.NotFound);
    Assert((await client.GetAsync("/scalar")).IsSuccessStatusCode);
});
await Check("Missing authorization fails closed at startup in Production", async () =>
{
    await using var host = Gateway(configure: o => o.AuthorizeRequest = null);
    try { host.UseAneiangOpenApi(); throw new Exception("Expected access configuration failure"); }
    catch (InvalidOperationException e) { Assert(e.Message.Contains("authorization")); }
});
await Check("Production ignores the Development anonymous opt-in", async () =>
{
    await using var host = Gateway(configure: o => { o.AuthorizeRequest = null; o.AllowAnonymousInDevelopment = true; });
    try { host.UseAneiangOpenApi(); throw new Exception("Expected production access failure"); }
    catch (InvalidOperationException e) { Assert(e.Message.Contains("authorization")); }
});
await Check("Documentation disabled in Production remains inaccessible while proxy works", async () =>
{
    await using var host = Gateway(configure: o => { o.Enabled = false; o.AuthorizeRequest = null; });
    host.UseRouting(); host.UseAneiangOpenApi(); host.MapReverseProxy();
    host.Services.GetRequiredService<AneiangProxyConfigProvider>().Update([Route("alpha", "/api/{**rest}", "PathRemovePrefix", "/api")], [Cluster("alpha", address)]);
    await host.StartAsync();
    using var http = new HttpClient { BaseAddress = new Uri(host.Urls.Single()) };
    foreach (var path in new[] { "/swagger", "/scalar", "/openapi/alpha.json", "/openapi/all.json", "/openapi/catalog" })
        Assert((await http.GetAsync(path)).StatusCode == HttpStatusCode.NotFound);
    Assert((await http.GetAsync("/api/items/42")).StatusCode == HttpStatusCode.Unauthorized);
});
await Check("Configurable endpoint paths and disabled merging", async () =>
{
    await using var host = Gateway(configure: o => { o.SwaggerPath = "/docs/swagger"; o.ScalarPath = "/docs/scalar"; o.CatalogPath = "/docs/catalog"; }, documents: o => { o.DocumentRoutePattern = "/specs/{cluster}.json"; o.MergeDocuments = false; });
    host.UseRouting(); host.UseAneiangOpenApi(); host.MapReverseProxy();
    host.Services.GetRequiredService<AneiangProxyConfigProvider>().Update([Route("alpha", "/{**rest}")], [Cluster("alpha", address)]);
    await host.StartAsync();
    using var http = new HttpClient { BaseAddress = new Uri(host.Urls.Single()) };
    http.DefaultRequestHeaders.Add("X-Docs-Key", apiToken);
    Assert((await http.GetStringAsync("/docs/swagger/index.js")).Contains("/specs/alpha.json"));
    Assert((await http.GetStringAsync("/docs/scalar")).Contains("specs/alpha.json"));
    Assert((await http.GetAsync("/specs/alpha.json")).IsSuccessStatusCode);
    Assert((await http.GetAsync("/openapi/all.json")).StatusCode == HttpStatusCode.NotFound);
});
await Check("Dashboard adapter rejects AuthMode.None and accepts existing API-key authentication", async () =>
{
    foreach (var mode in new[] { DashboardAuthMode.None, DashboardAuthMode.ApiKey })
    {
        await using var host = Gateway(configure: o => o.AuthorizeRequest = null, services: services =>
        {
            services.Configure<DashboardOptions>(o => { o.Auth.AuthMode = mode; o.Auth.ApiKey = apiToken; });
            services.AddSingleton<IDashboardAuthorizationService, DashboardAuthorizationService>();
            services.AddAneiangOpenApiDashboard();
        });
        host.UseAneiangOpenApi(); await host.StartAsync();
        using var http = new HttpClient { BaseAddress = new Uri(host.Urls.Single()) };
        http.DefaultRequestHeaders.Add("X-Api-Key", apiToken);
        Assert((await http.GetAsync("/scalar")).StatusCode == (mode == DashboardAuthMode.None ? HttpStatusCode.Unauthorized : HttpStatusCode.OK));
    }
});
await Check("Named authorization policies deny missing claims and permit authorized principals", async () =>
{
    await using var host = Gateway(configure: o => { o.AuthorizeRequest = null; o.AuthorizationPolicy = "Documentation"; },
        services: services => services.AddAuthorization(o => o.AddPolicy("Documentation", p => p.RequireClaim("docs", "read"))));
    host.Use(async (context, next) =>
    {
        if (context.Request.Headers["X-Identity"] is { Count: > 0 } identity)
            context.User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
                [new System.Security.Claims.Claim("docs", identity.ToString())], "integration"));
        await next(context);
    });
    host.UseAneiangOpenApi(); await host.StartAsync();
    using var http = new HttpClient { BaseAddress = new Uri(host.Urls.Single()) };
    Assert((await http.GetAsync("/scalar")).StatusCode == HttpStatusCode.Unauthorized);
    http.DefaultRequestHeaders.Add("X-Identity", "denied");
    Assert((await http.GetAsync("/scalar")).StatusCode == HttpStatusCode.Forbidden);
    http.DefaultRequestHeaders.Remove("X-Identity"); http.DefaultRequestHeaders.Add("X-Identity", "read");
    Assert((await http.GetAsync("/scalar")).IsSuccessStatusCode);
});
await Check("Application base paths keep server URLs and both UI sources on the gateway", async () =>
{
    await using var host = Gateway();
    host.UsePathBase("/gateway"); host.UseRouting(); host.UseAneiangOpenApi(); host.MapReverseProxy();
    host.Services.GetRequiredService<AneiangProxyConfigProvider>().Update([Route("alpha", "/{**rest}")], [Cluster("alpha", address)]);
    await host.StartAsync();
    using var http = new HttpClient { BaseAddress = new Uri(host.Urls.Single()) };
    http.DefaultRequestHeaders.Add("X-Docs-Key", apiToken);
    var doc = JsonDocument.Parse(await http.GetStringAsync("/gateway/openapi/alpha.json"));
    Assert(doc.RootElement.GetProperty("servers")[0].GetProperty("url").GetString() == "/gateway");
    Assert((await http.GetStringAsync("/gateway/swagger/index.js")).Contains("/gateway/openapi/alpha.json"));
    Assert((await http.GetStringAsync("/gateway/scalar/")).Contains("openapi/alpha.json"));
});
await Check("Swagger and Scalar visibility can be disabled independently", async () =>
{
    await using var host = Gateway(configure: o => o.SwaggerEnabled = false);
    host.UseAneiangOpenApi(); await host.StartAsync();
    using var http = new HttpClient { BaseAddress = new Uri(host.Urls.Single()) };
    http.DefaultRequestHeaders.Add("X-Docs-Key", apiToken);
    Assert((await http.GetAsync("/swagger/index.html")).StatusCode == HttpStatusCode.NotFound);
    Assert((await http.GetAsync("/swagger/index.js")).StatusCode == HttpStatusCode.NotFound);
    Assert((await http.GetAsync("/scalar")).IsSuccessStatusCode);
});
await Check("Deployment roles isolate documentation from public proxy/health listeners", async () =>
{
    foreach (var mode in new[] { DeploymentMode.AllInOne, DeploymentMode.Split, DeploymentMode.ProxyOnly, DeploymentMode.DashboardOnly })
    foreach (var role in new[] { "Dashboard", "Proxy", "Health" })
    {
        var services = new ServiceCollection();
        services.AddLogging(); services.AddOptions();
        services.Configure<DashboardOptions>(_ => { });
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["Kestrel:Endpoints:test:Url"] = "http://127.0.0.1:12345" }).Build();
        var deployment = new DeploymentOptions { Mode = mode, EndpointRoles = new() { ["test"] = role } };
        var resolver = new EndpointRoleResolver(config, deployment);
        services.AddSingleton(Options.Create(deployment)); services.AddSingleton(resolver);
        using var testHost = Host.CreateDefaultBuilder().ConfigureServices(s => { foreach (var service in services) s.Add(service); }).Build();
        var sp = testHost.Services;
        var context = new DefaultHttpContext { RequestServices = sp }; context.Connection.LocalPort = 12345;
        context.Items[typeof(AneiangOpenApiOptions)] = true;
        var reached = false;
        var middleware = ActivatorUtilities.CreateInstance<EndpointRouterMiddleware>(sp, (RequestDelegate)(_ => { reached = true; return Task.CompletedTask; }));
        await middleware.InvokeAsync(context);
        Assert(reached == (mode == DeploymentMode.AllInOne || (mode == DeploymentMode.Split && role == "Dashboard")), mode + "/" + role);
    }
});
await Check("Keycloak SSO and IAM management boundary", DashboardSsoFixture.RunAsync);
await Check("Only the existing Aneiang configuration provider is registered", () =>
{
    Assert(app.Services.GetServices<IProxyConfigProvider>().Single() == provider);
    return Task.CompletedTask;
});
await Check("Dashboard pages, native cluster editing, SQLite persistence and snapshot rollback", async () =>
{
    var directory = Path.Combine(Directory.GetCurrentDirectory(), ".gapcode", "integration", Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory);
    await using var host = Gateway(configure: o => o.AuthorizeRequest = null, services: services =>
    {
        services.AddAneiangStorage();
        services.Configure<StorageOptions>(o => o.Sqlite.ConnectionString = "Data Source=" + Path.Combine(directory, "gateway.db"));
        services.AddAneiangYarpDashboard(o => { o.RoutePrefix = "test-dashboard"; o.Auth.AuthMode = DashboardAuthMode.ApiKey; o.Auth.ApiKey = apiToken; o.Locale = "en-US"; });
        services.AddAneiangOpenApiDashboard();
    }, contentRoot: directory);
    host.UseRouting(); host.UseAneiangOpenApi(); host.UseAneiangYarpDashboard(); host.MapControllers();
    await host.StartAsync();
    using var http = new HttpClient { BaseAddress = new Uri(host.Urls.Single()) };
    http.DefaultRequestHeaders.Add("X-Api-Key", apiToken);
    var dynamic = host.Services.GetRequiredService<IDynamicYarpConfigService>();
    Assert((await dynamic.TryAddClusterConfig(Cluster("alpha", address))).Success);
    Assert((await dynamic.TryAddRouteConfig(Route("alpha", "/api/{**rest}", "PathRemovePrefix", "/api"))).Success);
    Assert((await http.GetAsync("/openapi/alpha.json")).IsSuccessStatusCode);
    var page = await http.GetStringAsync("/test-dashboard/documentation");
    Assert(page.Contains("/swagger") && page.Contains("/scalar") && page.Contains("alpha"));
    Assert(DashboardI18n.GetDict("zh-CN")["openapi.title"] == DashboardI18n.EnUS["openapi.title"]);
    var history = host.Services.GetRequiredService<IConfigPersistenceService>();
    var snapshot = await history.SaveSnapshotAsync("OpenAPI enabled");
    var disabled = Cluster("alpha", address, enabled: false);
    using var body = new StringContent(Aneiang.Yarp.Serialization.YarpJsonConfig.SerializeCluster(disabled), System.Text.Encoding.UTF8, "application/json");
    var save = await http.PutAsync("/test-dashboard/api/config/clusters/alpha", body);
    Assert(save.IsSuccessStatusCode, await save.Content.ReadAsStringAsync());
    Assert((await http.GetAsync("/openapi/alpha.json")).StatusCode == HttpStatusCode.NotFound);
    var persisted = await host.Services.GetRequiredService<IClusterRepository>().GetClusterAsync("alpha");
    Assert(persisted!.ToClusterConfig().Config.Metadata!["OpenApi.Enabled"] == "false");
    Assert(await history.RollbackAsync(snapshot.VersionId));
    Assert((await http.GetAsync("/openapi/alpha.json")).IsSuccessStatusCode);
    using var anonymous = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { BaseAddress = http.BaseAddress };
    Assert((await anonymous.GetAsync("/test-dashboard/documentation")).StatusCode == HttpStatusCode.Redirect);
});

Console.WriteLine($"OpenAPI integration: {passed} passed, {failures.Count} failed ({System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}).");
foreach (var failure in failures) Console.Error.WriteLine(failure);
return failures.Count == 0 ? 0 : 1;

async Task Check(string name, Func<Task> action)
{
    try { await action(); passed++; Console.WriteLine("PASS " + name); }
    catch (Exception e) { failures.Add(name + ": " + e); Console.WriteLine("FAIL " + name + ": " + e.Message); }
}
void Assert(bool value, string? message = null) { if (!value) throw new Exception(message ?? "Assertion failed"); }
async Task<JsonDocument> Document(string cluster) => await Json("/openapi/" + cluster + ".json");
async Task<JsonDocument> Json(string path)
{
    var json = await client.GetStringAsync(path);
    var result = OpenApiDocument.Parse(json, "json");
    Assert(result.Document != null && result.Diagnostic?.Errors.Count == 0, result.Diagnostic?.Errors.FirstOrDefault()?.Message);
    return JsonDocument.Parse(json);
}
WebApplication EmptyHost()
{
    var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production", Args = [] });
    builder.Logging.ClearProviders(); builder.WebHost.UseUrls("http://127.0.0.1:0");
    return builder.Build();
}
WebApplication Gateway(Action<AneiangOpenApiOptions>? configure = null, Action<YarpOpenApiOptions>? documents = null, Action<IServiceCollection>? services = null, string? contentRoot = null)
{
    var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production", Args = [], ContentRootPath = contentRoot });
    builder.Logging.ClearProviders(); builder.WebHost.UseUrls("http://127.0.0.1:0");
    builder.Services.AddAneiangYarp(proxy => proxy.AddAneiangOpenApi(o =>
    {
        o.Enabled = true; o.MaxDocumentBytes = 4096;
        o.AuthorizeRequest = c => Task.FromResult(c.Request.Headers["X-Docs-Key"] == apiToken);
        configure?.Invoke(o);
    }, o => { o.MergeDocuments = true; o.MergedDocument.RenameDuplicateSchemas = true; o.FetchTimeout = TimeSpan.FromMilliseconds(200); documents?.Invoke(o); }), enableRegistration: false);
    services?.Invoke(builder.Services);
    return builder.Build();
}
ClusterConfig Cluster(string id, string destination, bool enabled = true, YarpOpenApiClusterOptions? settings = null) => new()
{
    ClusterId = id, Destinations = new Dictionary<string, DestinationConfig> { ["main"] = new() { Address = destination } },
    Metadata = new Dictionary<string, string> { ["OpenApi.Enabled"] = enabled.ToString().ToLowerInvariant(),
        ["OpenApi.Settings"] = JsonSerializer.Serialize(settings ?? new YarpOpenApiClusterOptions { ExcludePaths = ["internal"] }) }
};
RouteConfig Route(string cluster, string path, string? transform = null, string? value = null) => new()
{
    RouteId = cluster, ClusterId = cluster, Match = new() { Path = path },
    Transforms = transform == null ? null : [new Dictionary<string, string> { [transform] = value! }]
};
string Spec(string title, string schemaType) => """
{
  "openapi":"3.0.3","info":{"title":"__TITLE__","version":"1.0"},
  "servers":[{"url":"http://internal.example"}],"security":[{"bearer":[]}],
  "paths":{
    "/items/{id}":{
      "servers":[{"url":"http://internal.example/path"}],
      "get":{"servers":[{"url":"http://internal.example/op"}],"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"OK","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}}}},
      "post":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Item"}}}},"responses":{"200":{"description":"OK"}}}
    },
    "/backend/items/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"OK"}}}},
    "/fixed":{"get":{"responses":{"200":{"description":"OK"}}}},
    "/internal":{"get":{"responses":{"200":{"description":"private"}}}}
  },
  "components":{"schemas":{"Item":{"type":"object","properties":{"id":{"type":"__TYPE__"}}}},"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}}
}
""".Replace("__TITLE__", title).Replace("__TYPE__", schemaType);
