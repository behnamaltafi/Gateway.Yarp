# OpenAPI aggregation, Swagger UI and Scalar

`Aneiang.Yarp.OpenApi` integrates MMLib.OpenApiForYarp **1.1.0**, its SwaggerUI adapter **1.1.0**, and its Scalar adapter **1.1.0** with Aneiang's existing YARP builder. It targets `net10.0`. NuGet selects MMLib's .NET 8 assets on the framework; the shared YARP dependency remains **2.3.0**. No .NET 10 retargeting, additional routing provider, second proxy mapping, database, port, or synchronization service is introduced.

## Registration

Reference `src/Aneiang.Yarp.OpenApi/Aneiang.Yarp.OpenApi.csproj` (or the corresponding package when published). Keep your existing storage, dashboard and deployment registrations:

```csharp
using Aneiang.Yarp.Extensions;
using Aneiang.Yarp.OpenApi;
using Aneiang.Yarp.Dashboard.Extensions;
using Aneiang.Yarp.Storage.Sqlite;

builder.Services.AddAneiangYarp(
    proxy => proxy.AddAneiangOpenApi(), enableRegistration: false);
builder.Services.AddAneiangStorage();
builder.Services.AddAneiangYarpDashboard();
builder.Services.AddAneiangYarpDeployment();
builder.Services.AddAneiangOpenApiDashboard();

var app = builder.Build();
app.UseRouting();
// Call UseAuthentication here if your host uses ASP.NET Core authentication.
app.UseAneiangOpenApi();
app.UseAneiangYarpDashboard(); // owns the single MapReverseProxy call
app.MapControllers();
app.Run();
```

Both registration and middleware mounting are idempotent. Do not additionally call MMLib's UI/document mapping methods or `MapReverseProxy` when using these extensions.

For a host without the dashboard, configure `AuthorizationPolicy` with your existing ASP.NET Core authorization policy, or provide `AuthorizeRequest`. Map the proxy through the host's existing pipeline. Authentication must run before documentation middleware. Named policy authorization uses the current request principal; this integration does not create an authentication scheme or an OAuth flow.

## Configuration

```json
{
  "Gateway": {
    "OpenApi": {
      "Enabled": true,
      "SwaggerEnabled": true,
      "ScalarEnabled": true,
      "JsonEnabled": true,
      "SwaggerPath": "/swagger",
      "ScalarPath": "/scalar",
      "CatalogPath": "/openapi/catalog",
      "MaxClusters": 128,
      "MaxDocumentBytes": 4194304
    }
  },
  "YarpOpenApi": {
    "DocumentRoutePattern": "/openapi/{cluster}.json",
    "MergeDocuments": true,
    "CacheDuration": "00:00:30",
    "FetchTimeout": "00:00:10",
    "Clusters": {
      "orders": {
        "Title": "Orders",
        "OpenApiPath": "/swagger/v1/swagger.json",
        "AddOnlyPublishedPaths": true,
        "IncludePaths": ["^/api/"],
        "ExcludePaths": ["^/api/internal(?:/|$)"]
      }
    },
    "MergedDocument": {
      "DocumentName": "all",
      "RoutePattern": "/openapi/all.json",
      "Title": "Gateway APIs",
      "Version": "1.0.0",
      "RenameDuplicateSchemas": true
    }
  }
}
```

Cluster IDs must match existing YARP clusters. A cluster is opted in by an entry in `YarpOpenApi:Clusters` or by `OpenApi.Enabled=true` metadata. Other clusters are hidden. Metadata's explicit false overrides a configuration entry. Routes are read from the current Aneiang snapshot; do not duplicate route definitions in `YarpOpenApi`.

`JsonEnabled=false` disables JSON retrieval, including for the UIs. Disable a UI independently if only one interface is wanted. Enable merging to publish `/openapi/all.json`; keep this route/document name reserved rather than naming a cluster `all`. Cache TTL must be positive and at most one hour; downstream fetch timeout must be positive and at most one minute.

Default endpoints:

| Endpoint | Purpose |
| --- | --- |
| `/swagger` | Swagger UI and its embedded assets |
| `/scalar` | Scalar and its embedded assets |
| `/openapi/{cluster}.json` | Transformed, opted-in cluster document |
| `/openapi/all.json` | Optional merged document |
| `/openapi/catalog` | Live, authorized document catalog |
| `/{dashboard-prefix}/documentation` | Documentation links and enabled services |

Swagger's document configuration is served through `/swagger/index.js`; the HTML loads that script. Scalar normalizes document source URLs and resolves them against the gateway application base path using its bundled helper. Neither interface needs a public CDN.

## Runtime cluster settings and persistence

Use the existing dashboard's **Cluster → edit → Metadata** workflow. All supported MMLib cluster options can be supplied as one JSON string:

```json
"Metadata": {
  "OpenApi.Enabled": "true",
  "OpenApi.Settings": "{\"Title\":\"Orders API\",\"OpenApiPath\":\"/openapi/v1.json\",\"AddOnlyPublishedPaths\":true,\"ExcludePaths\":[\"/internal\"]}"
}
```

When present, `OpenApi.Settings` replaces that cluster's file-based options; omitted properties take upstream defaults. This uses MMLib's `YarpOpenApiClusterOptions` model instead of another settings model. Native cluster parsing, dashboard mapping/editing, `ConfigJson` persistence, configuration export, SQLite repositories and snapshot rollback retain these values. No schema migration is needed. Malformed metadata fails documentation requests safely rather than exposing default documents.

The catalog reads the current `IProxyConfigProvider` snapshot. Cluster addition, removal, destination changes, metadata changes and route changes are reflected on the next request. Reload the Swagger or Scalar page to refresh its selector; an already-open page does not receive push updates. Scalar evaluates its adapter callback for each request. Swagger's small request branch rebuilds its adapter options while reusing upstream embedded assets.

MMLib caches transformed documents by cluster ID. The integration removes the affected snapshot's old/current cluster cache entries before the next document request. Builds are serialized, with a one-second admission wait returning 429 when busy, so an older in-flight build cannot refill a newly invalidated cache. Requests already underway can finish using their captured configuration; the next request invalidates again if publication occurred during the build. This intentionally relies on the **version-pinned 1.1.0 cache key**, covered by destination, route, delete and disable integration checks. Recheck that contract before upgrading MMLib.

Global visibility and endpoint paths are startup settings. Change these with a restart. Runtime cluster metadata and route/destination publication do not require a restart.

## Paths, schemas and authentication

MMLib owns fetching, parsing, path rewriting, include/exclude filtering, component merging and duplicate schema renaming. `PathPattern`, `PathPrefix`, `PathRemovePrefix`, `PathSet` and passthrough are covered by integration tests. For example, a route `/demo/{**rest}` with `PathPattern=/api/local-service/{**rest}` publishes `/api/local-service/Ping` as `/demo/Ping`.

**Upstream limitation:** when several routes expose the same downstream operation, MMLib 1.1.0 selects one canonical gateway path (most specific downstream prefix; first route on ties). It does not publish every alias. All route definitions remain available to normal proxy forwarding. Do not interpret a missing alias as an inaccessible API. The integration additionally filters HTTP methods against the selected published route, removes backend server overrides at document/path/operation levels, and propagates document-level security requirements to operations so merging preserves them.

OpenAPI `servers` point at the gateway application base path. Per-cluster security definitions, parameters, request bodies and response schemas are preserved. Conflicting schemas can be renamed with `RenameDuplicateSchemas`. A conflicting path follows MMLib's first-document rule; conflicting same-named security schemes also follow the upstream merge rule. Give independently configured schemes distinct names.

HTTP integration checks verify security requirements and real authorized/unauthorized requests through the proxy. Automated browser interaction with Swagger's **Authorize / Try it out** and Scalar's authentication controls is not claimed. Services must still declare valid security schemes and enforce their own authorization. Documentation authorization does not authenticate business API calls.

## Documentation access and deployment roles

Documentation is globally **disabled by default**. Enabled documentation requires an authorization callback or policy. Without either, startup fails. `AllowAnonymousInDevelopment=true` is honored only when the host environment is Development; Production ignores it. A missing/unknown policy denies access.

`AddAneiangOpenApiDashboard` reuses the existing dashboard authorization service, including its header/JWT/cookie handling. `AuthMode.None` alone is rejected for protected documentation. Swagger, Scalar, their local assets, the catalog and raw JSON use the same access check. Unauthorized calls return 401 (403 for an authenticated principal denied by a policy); they do not return an unprotected login wrapper. Use the existing dashboard login first for cookie-based browser access. API-key deployments must provide their configured header when loading assets and documents, for example through an authenticated ingress. Credentials are never put in links.

| Deployment mode | Default documentation behavior with dashboard adapter |
| --- | --- |
| AllInOne | Existing listener(s), protected by dashboard authentication |
| Split | Dashboard or All listener only; Proxy/Health/Admin/unknown listeners return 404 |
| ProxyOnly | Documentation inaccessible through the dashboard adapter |
| DashboardOnly | Documentation inaccessible; no local API forwarding role |

Split mode's documentation listener does not forward business APIs. Interactive calls using relative gateway servers can therefore be unavailable on that listener. Use a deliberate host-specific setup for documentation on a forwarding listener with an explicit authentication policy; the default does not expose internal documentation on a public proxy port. No documentation-only port is added.

Document fetching uses an explicit allow-list of opted-in static destination/document URLs and refuses redirects. Embedded destination credentials, queries/fragments and nonlocal `OpenApiPath` values are rejected. This limits both accidental credential logging and cross-destination fetches. **Service-discovery logical addresses are not currently supported for documentation fetching**; configure a static documentation destination or extend the resolver integration separately. Existing proxy service-discovery plugins are unaffected.

Resource limits bound cluster count and response size; MMLib applies fetch timeouts and cache TTL. Disabled documents are denied before cache lookup and contribute no paths, schemas or security definitions to merged output. Opted-out destinations are not contacted by the fetch allow-list. Unavailable documents return 404; malformed documents or transform failures return a contained 502. Merging skips upstream fetch failures when MMLib returns no document; a fatal parsing/transformation failure can return 502 for that merged request. Gateway forwarding and health endpoints remain active.

Keep `AddOnlyPublishedPaths=true` and use explicit exclusions for internal operations on catch-all routes. These controls govern documentation; they do not replace backend/API authorization. Avoid proxying downstream documentation or management endpoints through broad business routes if those endpoints need separate access restrictions.

## Run the sample

The sample opts in the existing SampleLocalService cluster and demonstrates both UIs and the merged document. Run the service with auto-registration disabled; the gateway already has a static demonstration route:

```powershell
dotnet run --project samples/SampleLocalService --no-launch-profile -- --Gateway:Registration:Enabled=false
dotnet run --project samples/SampleGateway
```

Log in using the sample's existing dashboard authentication, then open `/swagger`, `/scalar`, `/openapi/sample-local-service.json` or `/openapi/all.json` on the gateway. The sample forwards `/demo/Ping`, `/demo/Echo?message=hello` and `POST /demo/EchoPost` to the existing controller. Its minimal checked-in OpenAPI fixture is for demonstration; keep it synchronized if changing those actions.

For a real .NET 8/9 service already using Swashbuckle, exposing an upstream document looks like:

```csharp
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(); // Swashbuckle.AspNetCore in the service
var app = builder.Build();
app.UseSwagger(); // /swagger/v1/swagger.json on the internal service listener
app.MapControllers();
app.Run();
```

Configure that cluster's `OpenApiPath` accordingly. Restrict the service listener to the gateway/network as appropriate; aggregation does not require exposing a downstream Swagger UI.

## Validation and troubleshooting

The new executable integration suite follows the repository's console-runner convention. It starts local Kestrel downstream APIs on ephemeral loopback ports; it requires no external services:

```powershell
dotnet restore Aneiang.Yarp.sln
dotnet build Aneiang.Yarp.sln
dotnet run --project tests/Aneiang.Yarp.OpenApi.Integration -f net10.0
dotnet run --project tests/Aneiang.Yarp.Regression
dotnet list src/Aneiang.Yarp.OpenApi package --vulnerable --include-transitive
```

- **401/403:** log into the dashboard or check the host's policy/header/cookie setup; `None` is intentionally insufficient.
- **404:** check global enablement, listener role, JSON visibility, exact cluster ID, opt-in metadata, downstream destination and document path.
- **502:** validate downstream JSON and regex filters; malformed metadata or unsupported address settings fail closed. Detailed document content and credentials are not returned to clients.
- **429:** another document build exceeded the admission window. Retry after it finishes; tune timeout/TTL and reduce merged catalog size if needed.
- **Old selector:** reload the UI page. Changes to global paths/visibility require restart.
- **Missing alias:** see the canonical route limitation above.
- **No forwarded request from Split UI:** use the Proxy listener for business APIs; documentation defaults to the management listener.
- **Locked build outputs on Windows:** stop the running application yourself, or use `dotnet build --artifacts-path <separate-directory>` to validate without touching its loaded assemblies.
