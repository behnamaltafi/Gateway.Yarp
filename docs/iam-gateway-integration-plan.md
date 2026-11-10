# IAM Gateway V1 Core integration plan

## G0 baseline (2026-11-10)

- Repository: `Gateway.Yarp`, HEAD `f5d8e1bd869f9390e6377f4e4ab1879f44aaa13e`.
- Starting branch: `master`; no `develop` branch exists locally or on `origin`. Work therefore starts from the reviewed production HEAD on `feature/iam-local-pdp`.
- Pre-existing working-tree item: `docs/Codex-Gateway-Yarp-IAM-V1-Core-Standalone-Prompt-fa.md` is untracked and is not modified by this work.
- SDK/runtime: .NET SDK `10.0.301`, ASP.NET Core runtime `10.0.9`; projects target `net10.0`.
- YARP: `2.3.0`. OpenAPI: `MMLib.OpenApiForYarp`, SwaggerUI and Scalar `1.1.0`.
- `dotnet restore Aneiang.Yarp.sln`: PASS after network access; NU1903 reports the pre-existing `SQLitePCLRaw.lib.e_sqlite3 2.1.10` high-severity advisory. Initial sandboxed restore failed without diagnostics because package sources were unreachable.
- `dotnet build Aneiang.Yarp.sln --no-restore`: PASS, 0 errors / 9 warnings (the advisory, vulnerability-feed reachability, and pre-existing CA2024).
- `dotnet run --project tests/Aneiang.Yarp.OpenApi.Integration -f net10.0 --no-build`: PASS, 41/41.
- `dotnet run --project tests/Aneiang.Yarp.Regression -f net10.0 --no-build`: FAIL, 22 pass / 3 pre-existing failures in plugin runtime drain/health and plugin-state persistence.

## Existing entry points and lifecycle

`AddAneiangYarp` calls `AddReverseProxy`, registers the sole `AneiangProxyConfigProvider` as `IProxyConfigProvider`, dynamic config managers, snapshot compiler/publisher, controllers and gRPC. Static `ReverseProxy` configuration is parsed into the initial immutable snapshot. `AddAneiangYarpDashboard` supplies persistence and plugin runtime services.

The sample host calls `UseRouting`, CORS, `UseAneiangOpenApi`, and `UseAneiangYarpDashboard`. The dashboard extension owns the single production `MapReverseProxy` call. It can auto-call `UseAuthorization`; an IAM host must instead explicitly order `UseAuthentication`, `UseAuthorization`, then `UseAneiangYarpDashboard` with `AutoUseAuthorization=false`. The IAM registration validates that ordering contract in documentation and tests.

The mandatory enforcement seam is the first middleware inside the existing `MapReverseProxy` branch. At that point endpoint routing has selected the route and YARP exposes `IReverseProxyFeature.Route.Config`; enforcement uses that exact route, its method constraint and a canonical security fingerprint. It runs before built-in transforms and every dynamically enabled plugin, and is registered by core service presence rather than through `IGatewayPlugin`, so Plugin Center cannot disable it.

## Route mutation inventory and coverage

| Mutation path | Existing flow | IAM coverage |
| --- | --- | --- |
| `ReverseProxy` appsettings | `AneiangProxyConfigProvider` constructor | Runtime matched-route guard; bundle/manifest compatibility |
| REST registration/update/delete | `GatewayConfigController` → `DynamicYarpConfigService` / managers / publisher | Runtime guard independently blocks unpublished or changed fingerprints |
| Dashboard CRUD, AI functions, import/export | dashboard controllers/services → same dynamic service | Same mandatory runtime guard |
| Dashboard rollback | `ConfigPersistenceService.RollbackAsync` → dynamic snapshot | Same guard; old policy cannot authorize a changed fingerprint |
| gRPC/client auto-registration | registry service / `GatewayAutoRegistrationClient` → registration API | Same guard; management-plane auth remains separate |
| SQLite restore/startup | hosted `DynamicYarpConfigService` loads repositories | Guard remains closed until a valid published bundle exists |
| Service discovery refresh | `ServiceDiscoveryRefreshService` publishes destination snapshot | Route fingerprint intentionally excludes volatile destination health/discovery addresses; route security semantics remain bound |
| Plugin binding changes | snapshot compiler/publisher and runtime domain | Guard executes before plugin pipeline and is not a plugin |
| YARP change token/hot reload | sole provider atomically swaps snapshot | Every newly matched route is checked against current immutable IAM snapshot |

## Reuse, gaps and PoCs

Reused: sole YARP provider, immutable config snapshots/change tokens, dynamic route management and SQLite persistence, dashboard single proxy mapping, plugin execution pipeline, deployment roles, existing OpenAPI/Swagger/Scalar aggregation, health/metrics infrastructure and existing test harness conventions.

Gaps to fill: standard JWT bearer adapter, published-bundle fetch/validation and readiness, exact route fingerprint binding, mandatory PEP, trusted principal entitlement client, bounded absolute L1 cache/single-flight, pure local PDP, spoofable-header removal, and IAM-specific integration/security tests.

PoCs/tests required: prove `IReverseProxyFeature` exposes the selected route before forwarding; null/`anonymous` YARP authorization cannot bypass IAM; same path GET/DELETE maps independently; route/fingerprint mutation denies; invalid/expired bundle denies; JWT outcomes are 401/403; IAM miss/down is 503; valid cache hit performs no outbound fetch; 20 parallel misses collapse to one; Swagger/Scalar regression remains independent.

## Risks and boundaries

- The repository has no current Keycloak environment or IAM repository. Contract-level Kestrel/JWT tests will use only test keys and an in-process IAM HTTP fixture; live Keycloak/IAM E2E remains BLOCKED until endpoints and credentials are supplied.
- Bundle canonicalization must be shared with IAM through the documented schema/canonical JSON rules. A schema/hash mismatch fails closed.
- L1 entitlement staleness is bounded by the smaller of configured 120 seconds and snapshot/grant expiry; suspension can remain effective only after that bound.
- Management endpoints, dashboard, gRPC, health and documentation are not business proxy routes. They retain their existing separate authentication/deployment boundary and must not be exposed with `GatewayApiAuthMode.None` or permissive production CORS.
- CI/CD, release/version files, IAM authoring, users/roles/permissions storage, Keycloak administration, Redis L2, event invalidation and multi-node synchronization are out of scope.
