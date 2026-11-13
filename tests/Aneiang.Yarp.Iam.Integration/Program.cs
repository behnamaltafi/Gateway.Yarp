using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using Aneiang.Yarp.Extensions;
using Aneiang.Yarp.Iam;
using Aneiang.Yarp.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Yarp.ReverseProxy.Configuration;
using Aneiang.Yarp.Storage.Sqlite;
using System.Security.Cryptography;
using System.Text.Json;

const string issuer = "https://keycloak.test/realms/core";
const string application = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const string audience = "orders-api";
var failures = new List<string>();
var passed = 0;
var forwards = 0;

var backendBuilder = WebApplication.CreateBuilder();
backendBuilder.Configuration.Sources.Clear();
backendBuilder.Configuration.AddInMemoryCollection();
backendBuilder.Logging.ClearProviders();
await using var backend = backendBuilder.Build();
backend.Urls.Add("http://127.0.0.1:0");
backend.MapMethods("/{**path}", ["GET", "DELETE"], (HttpContext context) =>
{
    Interlocked.Increment(ref forwards);
    return Results.Json(new { method = context.Request.Method, spoof = context.Request.Headers.ContainsKey("X-Role")
        || context.Request.Headers.ContainsKey("X-IAM-Resource-Proof") || context.Request.Headers.ContainsKey("X-SystemId") });
});
await backend.StartAsync();

var builder = WebApplication.CreateBuilder();
builder.Configuration.Sources.Clear();
builder.Configuration.AddInMemoryCollection();
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options => options.SingleLine = true);
builder.WebHost.UseUrls("http://127.0.0.1:0");
builder.Services.AddAneiangYarp(enableRegistration: false);
var testDatabase = Path.Combine(Path.GetTempPath(), "opencode", "gateway-iam-" + Guid.NewGuid().ToString("N") + ".db");
Directory.CreateDirectory(Path.GetDirectoryName(testDatabase)!);
builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Gateway:Storage:Sqlite:ConnectionString"] = "Data Source=" + testDatabase });
builder.Services.AddAneiangStorage();
var source = new FakeEntitlementSource();
var policies = new FakeBundleProvider();
builder.Services.AddSingleton<IIamEntitlementSource>(source);
builder.Services.AddSingleton<IIamPolicyBundleProvider>(policies);
builder.Services.AddAneiangIamGateway(builder.Configuration, options =>
{
    options.Enabled = true;
    options.Issuer = issuer;
    options.Audience = audience;
    options.AllowedAlgorithms = [SecurityAlgorithms.HmacSha256];
    options.PolicyBundleEndpoint = new Uri("https://localhost:1/iam/bundle");
    options.EntitlementEndpoint = new Uri("https://localhost:1/iam/entitlements");
    options.InternalApiToken = "component-test-only";
    options.BundleRefreshInterval = TimeSpan.FromHours(1);
});
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("test-only-signing-key-at-least-32-bytes-long"));
builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, jwt =>
{
    jwt.Authority = null;
    jwt.TokenValidationParameters.IssuerSigningKey = key;
    jwt.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
});

await using var app = builder.Build();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapReverseProxy(proxy => proxy.UseAneiangIamGateway());
var provider = app.Services.GetRequiredService<AneiangProxyConfigProvider>();
var cluster = new ClusterConfig
{
    ClusterId = "backend",
    Destinations = new Dictionary<string, DestinationConfig> { ["one"] = new() { Address = backend.Urls.Single() } }
};
var getRoute = Route("get", "GET");
var deleteRoute = Route("delete", "DELETE");
provider.Update([getRoute, deleteRoute], [cluster]);
await app.StartAsync();
using var client = new HttpClient { BaseAddress = new Uri(app.Urls.Single()) };

await Check("S18 bundle schema, manifest and SHA-256 validation fail closed", () =>
{
    var operation = Policy(getRoute, "GET", IamAuthMode.Anonymous);
    var candidate = Bundle(operation);
    Assert(IamPolicyBundleValidator.TryValidate(candidate, DateTimeOffset.UtcNow, out _));
    Assert(!IamPolicyBundleValidator.TryValidate(candidate with { RouteManifestHash = "bad" }, DateTimeOffset.UtcNow, out _));
    var store = new IamPolicyBundleStore(TimeProvider.System);
    store.Publish(candidate with { ValidatedUntil = DateTimeOffset.UtcNow.AddMinutes(1) });
    store.Publish(candidate);
    Assert(store.Current!.Hash == candidate.Hash && store.Current.Revision == candidate.Revision);
    Assert(store.Current.ValidatedUntil == candidate.ValidatedUntil);
    return Task.CompletedTask;
});

await Check("S01/S02/S03 unpublished and YARP anonymous/null never forward", async () =>
{
    policies.Bundle = null;
    var before = forwards;
    Assert((await client.GetAsync("/items/1")).StatusCode == HttpStatusCode.ServiceUnavailable);
    Assert(forwards == before);
});

await Check("S04 published anonymous forwards only exact operation", async () =>
{
    policies.Bundle = Bundle(Policy(getRoute, "GET", IamAuthMode.Anonymous));
    Assert((await client.GetAsync("/items/1")).IsSuccessStatusCode);
    Assert((await client.DeleteAsync("/items/1")).StatusCode == HttpStatusCode.Forbidden);
});

await Check("S05/S08 same path method policy and missing token", async () =>
{
    policies.Bundle = Bundle(
        Policy(getRoute, "GET", IamAuthMode.Anonymous),
        Policy(deleteRoute, "DELETE", IamAuthMode.Permission, ["orders.delete"]));
    Assert((await client.DeleteAsync("/items/1")).StatusCode == HttpStatusCode.Unauthorized);
});

await Check("S07/S10 valid direct grant forwards and spoofed identity header is stripped", async () =>
{
    using var request = new HttpRequestMessage(HttpMethod.Delete, "/items/1");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token("user-1", audience));
    request.Headers.Add("X-Role", "admin");
    request.Headers.Add("X-IAM-Resource-Proof", "client-supplied");
    request.Headers.Add("X-SystemId", "10");
    var response = await client.SendAsync(request);
    Assert(response.IsSuccessStatusCode);
    Assert(!(await response.Content.ReadAsStringAsync()).Contains("\"spoof\":true"));
});

await Check("S08 wrong operation audience is denied", async () =>
{
    using var request = new HttpRequestMessage(HttpMethod.Delete, "/items/1");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token("user-1", "other-api"));
    Assert((await client.SendAsync(request)).StatusCode == HttpStatusCode.Forbidden);
});

await Check("S09/S11 principal kind and business scope cannot borrow grants", () =>
{
    var evaluator = new IamPolicyEvaluator(TimeProvider.System);
    var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("aud", audience)], "fixture"));
    var scoped = Policy(deleteRoute, "DELETE", IamAuthMode.Permission, ["orders.delete"]) with
    {
        AllowedPrincipalKinds = [IamPrincipalKind.User]
    };
    var snapshot = new IamEntitlementSnapshot(1, Guid.NewGuid().ToString(), issuer, "user-1", application, 1,
        DateTimeOffset.UtcNow.AddSeconds(-1), DateTimeOffset.UtcNow.AddSeconds(119), true, IamPrincipalKind.User,
        [new IamGrant("orders.delete", IamScopeKind.System, "10", null, "Role"), new IamGrant("orders.approve", IamScopeKind.System, "20", null, "Direct")]);
    Assert(!evaluator.Evaluate(scoped, principal, snapshot).Allowed);
    var role = snapshot with { Grants = [new("orders.delete", IamScopeKind.Global, null, null, "Role")] };
    Assert(evaluator.Evaluate(scoped, principal, role).Allowed);
    Assert(!evaluator.Evaluate(scoped, principal, role with { PrincipalKind = IamPrincipalKind.Service }).Allowed);
    Assert(!evaluator.Evaluate(scoped, principal, role with { IsActive = false, Grants = [] }).Allowed);
    Assert(!evaluator.Evaluate(scoped, principal, role with { Grants = [] }).Allowed);
    Assert(!evaluator.Evaluate(scoped, principal, role with { Grants = [role.Grants[0] with { ExpiresAt = DateTimeOffset.UtcNow }] }).Allowed);
    var multiple = scoped with { RequiredPermissions = ["orders.delete", "orders.approve"] };
    Assert(!evaluator.Evaluate(multiple, principal, role).Allowed);
    Assert(evaluator.Evaluate(multiple with { RequirementMode = IamRequirementMode.Any }, principal, role).Allowed);
    return Task.CompletedTask;
});

await Check("invalid, expired and ID tokens never forward", async () =>
{
    var before = forwards;
    foreach (var token in new[] { "invalid", Token("user-1", audience, expired: true), Token("user-1", audience, type: "ID") })
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, "/items/1");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Assert((await client.SendAsync(request)).StatusCode == HttpStatusCode.Unauthorized);
    }
    Assert(forwards == before);
});

await Check("wrong entitlement application fails closed", async () =>
{
    var before = forwards;
    using var request = new HttpRequestMessage(HttpMethod.Delete, "/items/1");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token("wrong-app", audience));
    Assert((await client.SendAsync(request)).StatusCode == HttpStatusCode.ServiceUnavailable);
    Assert(forwards == before);
});

await Check("schema 1 rejects legacy enforcement, legacy fields and missing enforcement", () =>
{
    var candidate = Bundle(Policy(getRoute, "GET", IamAuthMode.Anonymous));
    var json = Encoding.UTF8.GetString(Convert.FromBase64String(candidate.PolicyContentBase64));
    const string mode = ",\"enforcementMode\":\"GatewayOnly\"";
    Assert(json.Contains(mode, StringComparison.Ordinal));
    foreach (var replacement in new[] { ",\"enforcementMode\":\"GatewayAndResource\"", mode + ",\"ResourceScopeRequired\":false", "" })
    {
        var bytes = Encoding.UTF8.GetBytes(json.Replace(mode, replacement, StringComparison.Ordinal));
        var invalid = candidate with
        {
            Hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            PolicyContentBase64 = Convert.ToBase64String(bytes)
        };
        Assert(!IamPolicyBundleValidator.TryValidate(invalid, DateTimeOffset.UtcNow, out _));
    }
    return Task.CompletedTask;
});

await Check("S12/S13 valid L1 hit has zero fetch and 20-way miss is single-flight", async () =>
{
    source.Reset();
    var cache = app.Services.GetRequiredService<IIamEntitlementCache>();
    await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => cache.GetAsync(issuer, "parallel", application, CancellationToken.None)));
    Assert(source.Fetches == 1, $"fetches={source.Fetches}");
    await cache.GetAsync(issuer, "parallel", application, CancellationToken.None);
    Assert(source.Fetches == 1);
});

await Check("S14 positive cache expiry is absolute and capped at 120 seconds", async () =>
{
    var manual = new ManualTimeProvider(DateTimeOffset.UtcNow);
    var localSource = new FakeEntitlementSource(manual);
    using var cache = new IamEntitlementCache(localSource, Options.Create(new IamGatewayOptions
    {
        EntitlementMaxAge = TimeSpan.FromSeconds(120), NegativeCacheMaxAge = TimeSpan.FromSeconds(15),
        EntitlementCacheSize = 10, MaxConcurrentEntitlementFetches = 2
    }), manual);
    await cache.GetAsync(issuer, "ttl", application, CancellationToken.None);
    manual.Advance(TimeSpan.FromSeconds(119));
    await cache.GetAsync(issuer, "ttl", application, CancellationToken.None);
    Assert(localSource.Fetches == 1);
    manual.Advance(TimeSpan.FromSeconds(2));
    await cache.GetAsync(issuer, "ttl", application, CancellationToken.None);
    Assert(localSource.Fetches == 2);
});

await Check("entitlement wire POST, coalesced miss and zero HTTP on cache hit", async () =>
{
    var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
    var options = Options.Create(new IamGatewayOptions { EntitlementEndpoint = new Uri("https://iam.test/internal/v1/entitlements/resolve") });
    var httpRequests = 0;
    using var http = new HttpClient(new FixtureHttpHandler(async (request, ct) =>
    {
        Interlocked.Increment(ref httpRequests);
        Assert(request.Method == HttpMethod.Post && request.RequestUri == options.Value.EntitlementEndpoint);
        Assert(request.Headers.Authorization?.ToString() == "Bearer fixture-service-token");
        using var payload = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
        var root = payload.RootElement;
        Assert(root.GetProperty("schemaVersion").GetInt32() == 1 && root.GetProperty("applicationId").GetString() == application);
        var identity = root.GetProperty("validatedIdentity");
        Assert(identity.GetProperty("issuer").GetString() == issuer && identity.GetProperty("subject").GetString() == "wire-user");
        await Task.Delay(30, ct);
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                schemaVersion = 1, principalId = Guid.NewGuid(), applicationId = application, issuer, subject = "wire-user",
                principalKind = "User", clientId = (string?)null, revision = 1, issuedAt = clock.GetUtcNow(),
                expiresAt = clock.GetUtcNow().AddMinutes(2), isActive = true,
                grants = new[] { new { permissionCode = "orders.delete", scopeKind = "System", scopeId = "10", expiresAt = (DateTimeOffset?)null, source = "Role" } }
            })
        };
    }));
    using var cache = new IamEntitlementCache(new IamHttpEntitlementSource(http, options, new FixtureServiceToken()), options, clock);
    await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => cache.GetAsync(issuer, "wire-user", application, CancellationToken.None)));
    var hit = await cache.GetAsync(issuer, "wire-user", application, CancellationToken.None);
    Assert(httpRequests == 1 && hit.Grants.Single().ScopeKind == IamScopeKind.System && hit.Grants.Single().ScopeId == "10");
});

await Check("S16 IAM down on cache miss returns 503 and never forwards", async () =>
{
    var before = forwards;
    using var request = new HttpRequestMessage(HttpMethod.Delete, "/items/1");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Token("down", audience));
    Assert((await client.SendAsync(request)).StatusCode == HttpStatusCode.ServiceUnavailable);
    Assert(forwards == before);
});

await Check("S19/S21 changed route fingerprint cannot borrow old policy", async () =>
{
    var changed = getRoute with { Transforms = [new Dictionary<string, string> { ["PathPrefix"] = "/v2" }] };
    provider.Update([changed, deleteRoute], [cluster]);
    var before = forwards;
    Assert((await client.GetAsync("/items/1")).StatusCode == HttpStatusCode.Forbidden);
    Assert(forwards == before);
    provider.Update([getRoute, deleteRoute], [cluster]);
});

await Check("S18/S22 expired bundle degrades readiness and blocks forwarding", async () =>
{
    policies.Bundle = Bundle(Policy(getRoute, "GET", IamAuthMode.Anonymous)) with { ValidatedUntil = DateTimeOffset.UtcNow.AddSeconds(-1) };
    var before = forwards;
    Assert((await client.GetAsync("/items/1")).StatusCode == HttpStatusCode.ServiceUnavailable);
    Assert(forwards == before);
});

Console.WriteLine($"IAM integration: {passed} passed, {failures.Count} failed (.NET {Environment.Version}).");
foreach (var failure in failures) Console.Error.WriteLine(failure);
if (failures.Count != 0) Environment.ExitCode = 1;

RouteConfig Route(string id, string method) => new()
{
    RouteId = id, ClusterId = "backend", Order = int.MaxValue, AuthorizationPolicy = method == "GET" ? null : "anonymous",
    Match = new RouteMatch { Path = "/items/{id}", Methods = [method] }
};

IamOperationPolicy Policy(RouteConfig route, string method, IamAuthMode mode, string[]? permissions = null) => new(
    $"orders.{method.ToLowerInvariant()}", route.RouteId, method, IamRouteFingerprint.Compute(route), application, "orders", audience, mode,
    [IamPrincipalKind.User, IamPrincipalKind.Service], [], (permissions ?? []).ToImmutableArray(), IamRequirementMode.All,
    IamEnforcementMode.GatewayOnly, 1);

IamPolicyBundle Bundle(params IamOperationPolicy[] values)
{
    var manifest = IamRouteManifestExporter.Export(provider.GetConfig());
    var manifestHash = Convert.ToHexString(SHA256.HashData(manifest)).ToLowerInvariant();
    var content = JsonSerializer.SerializeToUtf8Bytes(new
    {
        schemaVersion = 1, revision = 1, publishedAt = DateTimeOffset.UtcNow.AddMinutes(-1), routeManifestHash = manifestHash,
        routeManifestBase64 = Convert.ToBase64String(manifest), policies = values.Select(p => new
        {
            applicationId = p.ApplicationId, applicationCode = "orders", p.BackendServiceCode, p.OperationKey,
            gatewayRouteId = p.RouteId, p.HttpMethod, gatewayRouteFingerprint = p.RouteFingerprint, p.AuthMode, p.RequiredAudience,
            p.AllowedPrincipalKinds, p.RequiredOAuthScopes, p.RequiredPermissions, p.RequirementMode, p.EnforcementMode
        }).ToArray()
    }, IamBundleWireProtocol.JsonOptions);
    return IamBundleWireProtocol.Decode(new(1, 1, Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant(),
        DateTimeOffset.UtcNow.AddMinutes(5), Convert.ToBase64String(content)), DateTimeOffset.UtcNow);
}

string Token(string subject, string tokenAudience, bool expired = false, string type = "Bearer")
{
    var now = DateTime.UtcNow;
    var descriptor = new SecurityTokenDescriptor
    {
        Issuer = issuer, Audience = tokenAudience, Subject = new ClaimsIdentity([new Claim("sub", subject), new Claim("typ", type)]),
        NotBefore = now.AddMinutes(-10), IssuedAt = now.AddMinutes(-10), Expires = now.AddMinutes(expired ? -5 : 5),
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
    };
    return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityTokenHandler().CreateToken(descriptor));
}

async Task Check(string name, Func<Task> test)
{
    try { await test(); passed++; Console.WriteLine($"PASS {name}"); }
    catch (Exception ex) { failures.Add($"FAIL {name}: {ex.Message}"); }
}

static void Assert(bool condition, string? message = null)
{
    if (!condition) throw new InvalidOperationException(message ?? "Expected true.");
}

sealed class FakeBundleProvider : IIamPolicyBundleProvider
{
    public IamPolicyBundle? Bundle { get; set; }
    public IamPolicyBundle? Current => Bundle;
    public bool IsReady => IamPolicyBundleValidator.TryValidate(Bundle, DateTimeOffset.UtcNow, out _);
}

sealed class FakeEntitlementSource(TimeProvider? time = null) : IIamEntitlementSource
{
    public int Fetches;
    public void Reset() => Fetches = 0;
    public async Task<IamEntitlementSnapshot> FetchAsync(string actualIssuer, string subject, string actualApplication, CancellationToken cancellationToken, string? clientId = null)
    {
        Interlocked.Increment(ref Fetches);
        await Task.Delay(30, cancellationToken);
        if (subject == "down") throw new HttpRequestException("fixture down");
        var now = (time ?? TimeProvider.System).GetUtcNow();
        var id = new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(subject)).AsSpan(0, 16));
        var app = subject == "wrong-app" ? "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" : actualApplication;
        return new(1, id.ToString(), actualIssuer, subject, app, 1, now,
            now.AddSeconds(120), true, IamPrincipalKind.User,
            [new IamGrant("orders.delete", IamScopeKind.Global, null, null, "Direct")]);
    }
}

sealed class ManualTimeProvider(DateTimeOffset current) : TimeProvider
{
    private DateTimeOffset _current = current;
    public override DateTimeOffset GetUtcNow() => _current;
    public void Advance(TimeSpan value) => _current += value;
}

sealed class FixtureServiceToken : IIamServiceTokenProvider
{
    public Task<string> GetAsync(CancellationToken cancellationToken) => Task.FromResult("fixture-service-token");
}

sealed class FixtureHttpHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        send(request, cancellationToken);
}
