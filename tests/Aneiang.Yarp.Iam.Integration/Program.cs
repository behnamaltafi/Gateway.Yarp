using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Aneiang.Yarp.Extensions;
using Aneiang.Yarp.Iam;
using Aneiang.Yarp.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Yarp.ReverseProxy.Configuration;

const string issuer = "https://keycloak.test/realms/core";
const string application = "orders";
const string audience = "orders-api";
var failures = new List<string>();
var passed = 0;
var forwards = 0;

var backendBuilder = WebApplication.CreateBuilder();
backendBuilder.Logging.ClearProviders();
await using var backend = backendBuilder.Build();
backend.Urls.Add("http://127.0.0.1:0");
backend.MapMethods("/{**path}", ["GET", "DELETE"], (HttpContext context) =>
{
    Interlocked.Increment(ref forwards);
    return Results.Json(new { method = context.Request.Method, spoof = context.Request.Headers.ContainsKey("X-Role") });
});
await backend.StartAsync();

var builder = WebApplication.CreateBuilder();
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options => options.SingleLine = true);
builder.WebHost.UseUrls("http://127.0.0.1:0");
builder.Services.AddAneiangYarp(enableRegistration: false);
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
    options.PolicyBundleEndpoint = new Uri("http://127.0.0.1:1/iam/bundle");
    options.EntitlementEndpoint = new Uri("http://127.0.0.1:1/iam/entitlements");
    options.BundleRefreshInterval = TimeSpan.FromHours(1);
});
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("test-only-signing-key-at-least-32-bytes-long"));
builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, jwt =>
{
    jwt.Authority = null;
    jwt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, ValidIssuer = issuer, ValidateAudience = false, ValidateLifetime = true,
        ValidateIssuerSigningKey = true, IssuerSigningKey = key, RequireSignedTokens = true,
        RequireExpirationTime = true, ClockSkew = TimeSpan.Zero, ValidAlgorithms = [SecurityAlgorithms.HmacSha256]
    };
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
    var manifestHash = IamPolicyBundleValidator.ComputeRouteManifestHash([operation]);
    var candidate = new IamPolicyBundle("1.0", 7, string.Empty, manifestHash, DateTimeOffset.UtcNow.AddMinutes(-1),
        DateTimeOffset.UtcNow.AddMinutes(5), [operation]);
    candidate = candidate with { Hash = IamPolicyBundleValidator.ComputeHash(candidate) };
    Assert(IamPolicyBundleValidator.TryValidate(candidate, DateTimeOffset.UtcNow, out _));
    Assert(!IamPolicyBundleValidator.TryValidate(candidate with { RouteManifestHash = "bad" }, DateTimeOffset.UtcNow, out _));
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
        RequiredBusinessScopes = ["System20"], AllowedPrincipalKinds = [IamPrincipalKind.User]
    };
    var snapshot = new IamEntitlementSnapshot("1.0", "p1", issuer, "user-1", application, 1,
        DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5), true, IamPrincipalKind.User,
        [new IamGrant("orders.delete", "System10", null, "Role")]);
    Assert(!evaluator.Evaluate(scoped, principal, snapshot).Allowed);
    Assert(!evaluator.Evaluate(scoped, principal, snapshot with { PrincipalKind = IamPrincipalKind.Service }).Allowed);
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
    var localSource = new FakeEntitlementSource();
    var manual = new ManualTimeProvider(DateTimeOffset.UtcNow);
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
    RouteId = id, ClusterId = "backend", AuthorizationPolicy = method == "GET" ? null : "anonymous",
    Match = new RouteMatch { Path = "/items/{**rest}", Methods = [method] }
};

IamOperationPolicy Policy(RouteConfig route, string method, IamAuthMode mode, string[]? permissions = null) => new(
    $"orders.{method.ToLowerInvariant()}", route.RouteId, method, IamRouteFingerprint.Compute(route), application, "orders", audience, mode,
    [IamPrincipalKind.User, IamPrincipalKind.Service], [], (permissions ?? []).ToImmutableArray(), [], IamRequirementMode.All,
    IamEnforcementMode.GatewayOnly, 1);

IamPolicyBundle Bundle(params IamOperationPolicy[] values) => new(
    "1.0", 1, new string('0', 64), "fixture", DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5), values.ToImmutableArray());

string Token(string subject, string tokenAudience)
{
    var descriptor = new SecurityTokenDescriptor
    {
        Issuer = issuer, Audience = tokenAudience, Subject = new ClaimsIdentity([new Claim("sub", subject), new Claim("typ", "Bearer")]),
        Expires = DateTime.UtcNow.AddMinutes(5), SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
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
    public bool IsReady => Bundle is { ValidatedUntil: var expiry } && expiry > DateTimeOffset.UtcNow;
}

sealed class FakeEntitlementSource : IIamEntitlementSource
{
    public int Fetches;
    public void Reset() => Fetches = 0;
    public async Task<IamEntitlementSnapshot> FetchAsync(string actualIssuer, string subject, string actualApplication, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Fetches);
        await Task.Delay(30, cancellationToken);
        if (subject == "down") throw new HttpRequestException("fixture down");
        return new("1.0", $"principal-{subject}", actualIssuer, subject, actualApplication, 1, DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(5), true, IamPrincipalKind.User,
            [new IamGrant("orders.delete", "Global", null, "Direct")]);
    }
}

sealed class ManualTimeProvider(DateTimeOffset current) : TimeProvider
{
    private DateTimeOffset _current = current;
    public override DateTimeOffset GetUtcNow() => _current;
    public void Advance(TimeSpan value) => _current += value;
}
