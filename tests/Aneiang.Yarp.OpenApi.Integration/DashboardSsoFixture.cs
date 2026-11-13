using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Aneiang.Yarp.Dashboard.Extensions;
using Aneiang.Yarp.Dashboard.Infrastructure;
using Aneiang.Yarp.Extensions;
using Aneiang.Yarp.Iam;
using Aneiang.Yarp.Storage;
using Aneiang.Yarp.Storage.Sqlite;
using Aneiang.Yarp.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

internal static class DashboardSsoFixture
{
    private const string Issuer = "https://keycloak.test/realms/integration";
    private const string BrowserId = "dashboard-fixture";
    private const string Audience = "management-fixture";
    private const string ApplicationId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    public static async Task RunAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "gateway-sso-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        using var rsa = RSA.Create(2048);
        var signingKey = new RsaSecurityKey(rsa) { KeyId = "fixture" };
        var oidc = new OpenIdConnectConfiguration
        {
            Issuer = Issuer, AuthorizationEndpoint = Issuer + "/auth", TokenEndpoint = Issuer + "/token",
            EndSessionEndpoint = Issuer + "/logout"
        };
        oidc.SigningKeys.Add(signingKey);
        string? nonce = null;
        string? challenge = null;
        string subject = "admin";
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production", ContentRootPath = directory });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, 0, endpoint => endpoint.Protocols = HttpProtocols.Http1);
            options.Listen(IPAddress.Loopback, 0, endpoint => endpoint.Protocols = HttpProtocols.Http2);
        });
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Gateway:Dashboard:Sso:Authority"] = Issuer, ["Gateway:Dashboard:Sso:ClientId"] = BrowserId,
            ["Gateway:Dashboard:Sso:ManagementAudience"] = Audience, ["Gateway:Dashboard:Sso:ApplicationId"] = ApplicationId,
            ["Gateway:Dashboard:Sso:DataProtectionKeyPath"] = Path.Combine(directory, "keys")
        });
        builder.Services.AddAneiangYarp();
        builder.Services.AddAneiangStorage();
        builder.Services.Configure<StorageOptions>(o => o.Sqlite.ConnectionString = "Data Source=" + Path.Combine(directory, "gateway.db"));
        builder.Services.AddAneiangYarpDashboard(o => { o.RoutePrefix = "sso-dashboard"; o.Auth.AuthMode = DashboardAuthMode.None; });
        builder.Services.AddSingleton<IIamEntitlementSource, FixtureEntitlements>();
        builder.Services.AddAneiangIamGateway(builder.Configuration, options =>
        {
            options.Enabled = true;
            options.Issuer = Issuer;
            options.Audience = "fixture-business";
            options.PolicyBundleEndpoint = new Uri("https://127.0.0.1:1/bundle");
            options.EntitlementEndpoint = new Uri("https://127.0.0.1:1/resolve");
            options.InternalApiToken = "fixture-only";
        });
        var originalSecret = Environment.GetEnvironmentVariable("GATEWAY_DASHBOARD_OIDC_CLIENT_SECRET");
        try
        {
            Environment.SetEnvironmentVariable("GATEWAY_DASHBOARD_OIDC_CLIENT_SECRET", "fixture-only");
            builder.Services.AddAneiangDashboardSso(builder.Configuration);
        }
        finally { Environment.SetEnvironmentVariable("GATEWAY_DASHBOARD_OIDC_CLIENT_SECRET", originalSecret); }
        builder.Services.PostConfigure<OpenIdConnectOptions>(DashboardSsoExtensions.OidcScheme, options =>
        {
            options.ConfigurationManager = new Microsoft.IdentityModel.Protocols.StaticConfigurationManager<OpenIdConnectConfiguration>(oidc);
            options.Backchannel = new HttpClient(new TokenEndpoint(async request =>
            {
                var body = await request.Content!.ReadAsStringAsync();
                var parameters = QueryHelpers.ParseQuery(body);
                var verifier = parameters["code_verifier"].ToString();
                var actual = WebEncoders.Base64UrlEncode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)));
                Ensure(actual == challenge, "PKCE verifier");
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new
                    {
                        id_token = Token(subject, BrowserId, parameters["code"] == "bad-nonce" ? "bad" : nonce),
                        access_token = Token(subject, Audience, service: true), refresh_token = "fixture-refresh-token", token_type = "Bearer"
                    })
                };
            }));
        });
        builder.Services.PostConfigure<JwtBearerOptions>(IamManagementAuthorization.ServiceScheme, options =>
        {
            options.Authority = null;
            options.TokenValidationParameters.IssuerSigningKey = signingKey;
        });

        await using var app = builder.Build();
        // Loopback transport for the harness. The fixture marks its own requests HTTPS for secure-cookie handling.
        app.Use((context, next) => { context.Request.Scheme = "https"; return next(context); });
        app.UseRouting();
        app.UseAneiangDashboardSsoCallbacks();
        app.UseAuthentication();
        app.UseAneiangYarpDashboard();
        app.MapControllers();
        app.MapAneiangYarpGrpc();
        app.Services.GetRequiredService<AneiangProxyConfigProvider>().Update(
            [new Yarp.ReverseProxy.Configuration.RouteConfig
                { RouteId = "unpublished", ClusterId = "business", Match = new() { Path = "/business" } }],
            [new Yarp.ReverseProxy.Configuration.ClusterConfig { ClusterId = "business",
                Destinations = new Dictionary<string, Yarp.ReverseProxy.Configuration.DestinationConfig>
                { ["fixture"] = new() { Address = "http://127.0.0.1:1/" } } }]);
        await app.StartAsync();
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
        { BaseAddress = new Uri(app.Urls.First()) };

        await Expect(HttpMethod.Get, "/sso-dashboard/api/auth/status", 401);
        await Expect(HttpMethod.Post, "/sso-dashboard/login", 404, body: JsonContent.Create(new { username = "admin", password = "fixture-only" }));
        await Expect(HttpMethod.Get, "/sso-dashboard/api/auth/status", 401, "dashboard_token=legacy");
        await Expect(HttpMethod.Post, "/sso-dashboard/hubs/overview/negotiate?negotiateVersion=1", 401);
        await Expect(HttpMethod.Post, "/sso-dashboard/api/config/import", 401);
        await Expect(HttpMethod.Get, "/api/gateway/routes", 401, authorization: "Basic Zml4dHVyZTpmaXh0dXJl");
        using (var apiKeyRequest = new HttpRequestMessage(HttpMethod.Get, "/api/gateway/routes"))
        {
            apiKeyRequest.Headers.Add("X-Api-Key", "fixture-only");
            using var response = await http.SendAsync(apiKeyRequest);
            Ensure(response.StatusCode == HttpStatusCode.Unauthorized, "legacy API key rejection");
        }
        await Expect(HttpMethod.Get, "/api/gateway/routes", 401, authorization: "Bearer " + Token("admin", BrowserId));
        await Expect(HttpMethod.Get, "/api/gateway/routes", 403, authorization: "Bearer " + Token("admin", Audience, service: true));
        await Expect(HttpMethod.Get, "/api/gateway/routes", 200, authorization: "Bearer " + Token("machine", Audience, service: true));
        await ExpectGrpc("16");
        await ExpectGrpc("7", Token("admin", Audience, service: true));
        await ExpectGrpc("0", Token("machine", Audience, service: true));
        await Expect(HttpMethod.Get, "/signin-gateway-dashboard?state=invalid&code=ok", 401);
        using (var invalid = await Login("admin", "bad-nonce"))
            Ensure((int)invalid.StatusCode == 401 && Cookie(invalid, IamManagementAuthorization.BrowserCookieName) is null, "nonce rejection");

        foreach (var denied in new[] { "missing", "inactive", "expired", "system", "unavailable" })
        {
            using var callback = await Login(denied);
            Ensure((int)callback.StatusCode == 302, "authenticated user session");
            await Expect(HttpMethod.Get, "/sso-dashboard/api/auth/status", 403, Cookie(callback, IamManagementAuthorization.BrowserCookieName));
        }
        using var accepted = await Login("admin");
        var session = Cookie(accepted, IamManagementAuthorization.BrowserCookieName);
        Ensure((int)accepted.StatusCode == 302 && session is not null, "valid callback");
        var setCookies = accepted.Headers.GetValues("Set-Cookie");
        Ensure(setCookies.Any(value => value.StartsWith(session!, StringComparison.Ordinal)
            && value.Contains("secure") && value.Contains("httponly") && !value.Contains("expires=", StringComparison.OrdinalIgnoreCase)), "session cookie flags");
        await Expect(HttpMethod.Get, "/sso-dashboard/api/auth/status", 200, session);
        await Expect(HttpMethod.Get, "/business", 503, session);
        await Expect(HttpMethod.Get, "/api/gateway/routes", 401, session);
        await Expect(HttpMethod.Post, "/sso-dashboard/api/config/import", 403, session);
        await Expect(HttpMethod.Post, "/sso-dashboard/hubs/overview/negotiate?negotiateVersion=1", 200, session);
        using var csrfResponse = await Send(HttpMethod.Get, "/sso-dashboard/settings", session);
        var page = await csrfResponse.Content.ReadAsStringAsync();
        var csrf = System.Text.RegularExpressions.Regex.Match(page, "csrfToken: \"([A-Za-z0-9_-]+)\"").Groups[1].Value;
        Ensure(csrfResponse.IsSuccessStatusCode && csrf.Length > 0, "settings page renders the antiforgery token");
        Ensure(!page.Contains("dashboard-twofactor.js", StringComparison.Ordinal), "legacy TOTP controls hidden");
        var csrfCookie = Cookie(csrfResponse, IamManagementAuthorization.CsrfCookieName);
        await Expect(HttpMethod.Post, "/sso-dashboard/logout", 403, session);
        using var logout = await Send(HttpMethod.Post, "/sso-dashboard/logout", session + "; " + csrfCookie, csrf: csrf);
        Ensure((int)logout.StatusCode == 302 && logout.Headers.Location?.AbsolutePath.EndsWith("/logout") == true
            && Cookie(logout, IamManagementAuthorization.BrowserCookieName)?.EndsWith('=') == true, "local and OIDC logout");
        await Expect(HttpMethod.Get, "/sso-dashboard/api/auth/status", 401);

        async Task<HttpResponseMessage> Login(string user, string code = "ok")
        {
            subject = user;
            using var start = await Send(HttpMethod.Get, "/sso-dashboard/settings");
            Ensure((int)start.StatusCode == 302 && start.Headers.Location?.AbsoluteUri.StartsWith(Issuer + "/auth?", StringComparison.Ordinal) == true,
                $"Keycloak redirect: got HTTP {(int)start.StatusCode}");
            var fields = QueryHelpers.ParseQuery(start.Headers.Location!.Query);
            Ensure(fields["code_challenge_method"] == "S256" && fields["response_type"] == "code", "authorization code with S256");
            nonce = fields["nonce"];
            challenge = fields["code_challenge"];
            var cookies = string.Join("; ", start.Headers.GetValues("Set-Cookie").Select(value => value.Split(';')[0]));
            return await Send(HttpMethod.Post, "/signin-gateway-dashboard", cookies, body: new FormUrlEncodedContent(new Dictionary<string, string>
            { ["state"] = fields["state"].ToString(), ["code"] = code }));
        }

        string Token(string user, string audience, string? tokenNonce = null, bool service = false)
        {
            var claims = new List<Claim> { new("sub", user),
                new("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64) };
            if (tokenNonce is not null) claims.Add(new("nonce", tokenNonce));
            if (service) { claims.Add(new("azp", "fixture-machine")); claims.Add(new("typ", "Bearer")); }
            var token = new JwtSecurityToken(Issuer, audience, claims, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(3),
                new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256));
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        async Task<HttpResponseMessage> Send(HttpMethod method, string path, string? cookie = null,
            string? authorization = null, HttpContent? body = null, string? csrf = null)
        {
            using var request = new HttpRequestMessage(method, path) { Content = body };
            if (cookie is not null) request.Headers.Add("Cookie", cookie);
            if (authorization is not null) request.Headers.Authorization = AuthenticationHeaderValue.Parse(authorization);
            if (csrf is not null) request.Headers.Add(DashboardSsoExtensions.CsrfHeader, csrf);
            return await http.SendAsync(request);
        }

        async Task Expect(HttpMethod method, string path, int status, string? cookie = null, string? authorization = null, HttpContent? body = null)
        {
            using var response = await Send(method, path, cookie, authorization, body);
            Ensure((int)response.StatusCode == status, $"{method} {path}: expected {status}, got {(int)response.StatusCode}");
        }

        async Task ExpectGrpc(string status, string? token = null)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, app.Urls.Last() + "/aneiang.yarp.v1.GatewayRegistry/GetServices")
            {
                Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = new ByteArrayContent(new byte[5])
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
            request.Headers.TE.Add(new TransferCodingWithQualityHeaderValue("trailers"));
            if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await http.SendAsync(request);
            var actual = response.TrailingHeaders.TryGetValues("grpc-status", out var trailers) ? trailers.Single()
                : response.Headers.TryGetValues("grpc-status", out var headers) ? headers.Single() : null;
            Ensure(response.IsSuccessStatusCode && actual == status, $"gRPC expected {status}, got HTTP {(int)response.StatusCode} / {actual}");
        }
    }

    private static string? Cookie(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.FirstOrDefault(value => value.StartsWith(name + "=", StringComparison.Ordinal))?.Split(';')[0] : null;

    private static void Ensure(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class TokenEndpoint(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request);
    }

    private sealed class FixtureEntitlements : IIamEntitlementSource
    {
        public Task<IamEntitlementSnapshot> FetchAsync(string issuer, string subject, string applicationId, CancellationToken cancellationToken, string? clientId = null)
        {
            Ensure(issuer == Issuer && applicationId == ApplicationId, "IAM identity and application binding");
            if (subject == "unavailable") throw new HttpRequestException("fixture outage");
            var now = DateTimeOffset.UtcNow;
            var system = subject == "system";
            var active = subject != "inactive";
            return Task.FromResult(new IamEntitlementSnapshot(1, Guid.NewGuid().ToString(), issuer, subject,
                applicationId, 1, now, now.AddMinutes(1), active, subject == "machine" ? IamPrincipalKind.Service : IamPrincipalKind.User,
                !active || subject == "missing" ? [] : [new("gateway.admin", system ? IamScopeKind.System : IamScopeKind.Global,
                    system ? "10" : null, subject == "expired" ? now.AddSeconds(-1) : null, subject == "machine" ? "Direct" : "Role")], clientId));
        }
    }
}
