# Gateway Dashboard migration to Keycloak SSO

## Baseline

The change started on `feature/iam-local-pdp` at `fdabe7a` with the GatewayOnly refactoring already in the working tree. Dashboard MVC used a namespace-scoped filter, local password/TOTP and a locally issued JWT carried in a cookie, browser storage, bearer header or SignalR query. OpenAPI and hubs checked legacy authorization separately. Core REST and gRPC checked legacy credentials independently, including modes that permit requests without credentials. The Circuit Breaker controller sits outside the Dashboard namespace. The optional MCP listener exposes Dashboard tools on a separate host.

## Authentication and authorization

| Surface | Authentication | Authorization |
| --- | --- | --- |
| Dashboard pages, AJAX, config import/export, rollback, settings, logs and database download | `GatewayDashboardOidc` challenges on page navigation. `GatewayDashboardCookie` authenticates the session. | Active IAM User with an effective, unexpired Global `gateway.admin` grant. ASP.NET Core antiforgery validates unsafe browser requests. |
| Dashboard Swagger, Scalar, catalog and documents | `GatewayDashboardCookie` | Same IAM permission, plus the existing documentation and listener restrictions. |
| Dashboard SignalR negotiate and transport | `GatewayDashboardCookie` | Same IAM permission and a same-origin check for browser connections. |
| Core route-registration and configuration REST, GatewayRegistry gRPC | `GatewayManagementBearer`, Keycloak access token with the dedicated management audience | Active IAM Service bound to `issuer`, `subject` and client ID with an effective, unexpired Global `gateway.admin` grant. |
| Dashboard plugin MVC controllers, including circuits | Dashboard cookie for browser calls. Management bearer for automation. | Same IAM check for the selected principal kind. Antiforgery applies to unsafe browser calls. |
| Business YARP proxy | Explicit business `Bearer` scheme | Published matched-route policy, fingerprint, local PDP and entitlement L1. |
| IAM manifest export | Existing bearer and manifest audience | Existing service subject, source-network and HTTPS restrictions. |

The Dashboard uses the framework's Authorization Code flow, S256 PKCE, state, correlation, nonce and signed ID-token validation. The session uses a distinct HttpOnly, Secure, Lax cookie with a fixed maximum lifetime and no persistent login. `SaveTokens=false` keeps OIDC tokens out of the ticket and browser storage. Dashboard APIs return 401/403. Logout validates antiforgery, removes the local cookie and starts RP-initiated Keycloak logout with the OIDC client ID. Keycloak may prompt for confirmation. [ASP.NET Core OIDC configuration](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-oidc-web-authentication?view=aspnetcore-10.0) · [Keycloak logout](https://www.keycloak.org/docs/26.1.5/server_admin/index.html)

The management gate reuses the existing IAM entitlement client and bounded L1. Its Application UUID separates management entitlements from the business applications. IAM resolves Direct and Role grants. The Gateway checks principal kind, active status, snapshot expiry, Global scope and grant expiry on use. Failures to resolve on a cache miss deny access.

## Migration and local validation

1. In IAM, create a Gateway management application (for example code `gateway-management`) and configure its UUID as `Gateway:Dashboard:Sso:ApplicationId`. Register `gateway.admin` in that application. Provision explicit Global direct or role grants for approved Keycloak User and Service principals.
2. In the existing Keycloak realm, configure a confidential Dashboard client with Standard Flow and S256 PKCE. Register the exact HTTPS sign-in and post-logout callback URIs, including any external path base. Disable Direct Access Grants for the Dashboard client. Configure Keycloak authentication flows and MFA centrally.
3. Configure a separate confidential service client with Service Accounts and a management audience mapper. Set the audience to `ManagementAudience`. Bind each service account's issuer, subject and client ID in IAM, then use OAuth Client Credentials to send a Keycloak bearer token on REST or gRPC.
4. Merge [the non-secret SSO configuration](../samples/SampleGateway/appsettings.KeycloakSso.example.json) with the IAM endpoint, credentials and bundle settings. Inject `GATEWAY_DASHBOARD_OIDC_CLIENT_SECRET` from the process environment or your secret store. Use a restricted persistent Data Protection key directory with filesystem encryption or a protected volume. Keep the same key ring across replicas for the same application. Configure Trusted Proxies and AllowedHosts for TLS termination. Use trusted HTTPS locally as well.
5. Remove legacy Dashboard password, signing secret, API key, BasicAuth and TOTP settings from SSO deployments. SampleGateway requires SSO and IAM in every environment, including the default Visual Studio and `dotnet run` Development profile. The `*.example.json` files are templates. Merge them into the active configuration, or point `IAM_LOCAL_SETTINGS` at a complete local settings file. Library hosts register `AddAneiangDashboardSso` alongside IAM. Call `UseAneiangDashboardSsoCallbacks` before `UseAuthentication` so callbacks are bounded to the Dashboard listeners. In Split mode use HTTPS and assign the machine listener the Admin role. The public Proxy listener rejects core management REST and gRPC traffic.
6. Start Gateway, visit the Dashboard with and without an IAM grant, test logout, and run authenticated REST/gRPC calls using the management token. Confirm a Business API request continues to require its own bearer token and operation policy.

For local startup with `IAM_LOCAL_SETTINGS`, set the variable to the absolute path of the merged configuration before running `dotnet run --project samples/SampleGateway`. Inject the OIDC client secret into that process separately. Set a trusted HTTPS Dashboard endpoint and register its exact callback URLs in Keycloak. A launch with missing SSO settings exits with an error before serving requests.

On the provisioned Windows workspace, open `Aneiang.Yarp.sln` in Visual Studio, set `SampleGateway` as startup project and press F5 with Docker Desktop running. The `SampleGateway` launch profile reads `.gapcode/sso-local`, starts the existing Keycloak container and reuses or starts IAM before binding `https://localhost:17455/aneiang`. The example files contain the local addresses and IDs. Secrets are read from the existing local configuration. The IIS Express and independent IAM.Api startup paths are outside this profile.

The `SampleGateway Local HTTP` profile uses a separate local Keycloak container and IAM development database. Start Docker Desktop and select that profile before pressing F5. The command-line equivalent is `pwsh -NoProfile -File .\Start-LocalGateway.ps1 -Http`. Use either launch method for port 17465. The HTTP addresses are `http://localhost:17465/aneiang` for Gateway, `http://localhost:17464/` for IAM Admin, `http://localhost:17463/health/live` for IAM API, and Keycloak on `http://localhost:18445`. The HTTP launcher reads `.gapcode/sso-http` and uses the same named test users. Local IAM Admin uses a workspace copy of the IAM UI with HTTP transport options. Keep the profile on loopback in Development. Published business policies are configured independently of Dashboard permissions.

The library retains legacy types and configuration for existing non-SSO integrations. Under SSO the old POST login and TOTP endpoints are unavailable, legacy cookie and credentials are ignored, and the separate MCP listener is disabled because it has its own credentials. Existing registration clients using API keys, passwords or unauthenticated calls need client-credentials support before cutover. Repository clients and Microservices retain their existing implementation.

## Changed files

- `src/Aneiang.Yarp/Iam/IamManagementAuthorization.cs` and `src/Aneiang.Yarp.Dashboard/Extensions/DashboardSsoExtensions.cs` add the isolated schemes and shared management permission check.
- `DashboardMvcOptionsSetup.cs`, `DashboardAuthFilter.cs`, `DashboardAuthorizationService.cs`, `DashboardAuthController.cs`, `DashboardPagesController.cs` and `DashboardApplicationBuilderExtensions.cs` connect SSO to pages, APIs, plugins and hubs. `McpServerHost.cs` disables its legacy listener under SSO.
- Core and Dashboard `GatewayApiAuthFilter.cs`, `GrpcAuthInterceptor.cs`, the OpenAPI gate and `IamAuthorizationMiddleware.cs` enforce the corresponding boundary.
- `GatewayControlPlaneSecurityValidator.cs`, `DeploymentConfigValidator.cs` and `EndpointRouterMiddleware.cs` recognize configured SSO while retaining listener restrictions.
- Dashboard shared layout/page initialization, History and Settings views, and `dashboard-api.js`, `dashboard-ai.js` and `dashboard-routes.js` use the cookie and antiforgery token in the browser.
- Dashboard project references the OIDC handler. SampleGateway startup and example configuration wire the production setup. The OpenAPI integration runner includes an OIDC protocol fixture.

## Verification

| Command or runner | Observed result |
| --- | --- |
| `dotnet build Aneiang.Yarp.sln --no-restore -m:1 -v:q` | Pass. Incremental build reported 0 errors and 0 warnings. The prior compile surfaced the existing `CA2024`. Prior Gateway acceptance records the SQLite package advisory, which this incremental build did not re-audit. |
| `dotnet test Aneiang.Yarp.sln --no-build --no-restore -m:1 -v:minimal` | Exit 0. The executable integration suites were run directly for case counts. |
| `Aneiang.Yarp.OpenApi.Integration` | 42 passed, 0 failed. This includes 41 prior OpenAPI cases and the new SSO integration fixture. |
| `Aneiang.Yarp.Iam.Integration` | 16 passed, 0 failed. |
| `Aneiang.Yarp.Regression` | 22 passed, 3 existing failures concerning plugin DI/failed-health behavior, draining in-flight requests, and importing legacy plugin state. |
| Browser JavaScript syntax | `node --check` passed on the three changed scripts. |

The SSO fixture uses the ASP.NET Core OIDC handler and a controlled token endpoint. It verifies code flow with S256 and the matching verifier, invalid state and nonce, session cookie flags, valid and denied user sessions, System-only and expired permission denial, IAM outage, legacy credentials, AJAX status, CSRF, logout, REST and gRPC service-principal authentication, SignalR negotiation, and rejection of business forwarding when a bundle is unavailable. It uses loopback, generated signing material and fixture entitlements. Full browser interaction against real Keycloak and live IAM, end-to-end SignalR WebSocket authorization and split-listener deployment remain open.

## Operational boundaries

- Deploy the Dashboard on a separate management origin where possible. In AllInOne, backend responses share the browser origin with the Dashboard. The proxy strips Dashboard cookies and the antiforgery header before forwarding, and the origin still needs to be trusted.
- Session logout deletes the local browser cookie and initiates Keycloak logout. A copied ticket is bounded by its fixed lifetime. Existing SignalR connections are not immediately disconnected by a logout in a separate browser request.
- Provision and verify the IAM application, grants and Keycloak clients before cutover. Legacy automatic registration clients need compatible tokens. This repository change did not provision either external system.
