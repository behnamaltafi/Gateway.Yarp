# IAM-enabled Gateway security and operation

Register existing YARP first, then IAM:

```csharp
builder.Services.AddAneiangYarp(proxy => proxy.AddAneiangOpenApi(), enableRegistration: false);
builder.Services.AddAneiangIamGateway(builder.Configuration);
```

The host pipeline must be explicit:

```csharp
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseAneiangOpenApi();
app.UseAneiangYarpDashboard(
    new DashboardApplicationBuilderExtensions.DashboardUseOptions
    {
        AutoUseAuthorization = false,
        AutoUseCors = false
    });
```

Configure an explicit restricted CORS policy if browser clients need it. `UseAneiangYarpDashboard` remains the owner of the single `MapReverseProxy`. When `AddAneiangIamGateway` is present, it inserts the mandatory guard first in that proxy branch, before transforms and Plugin Center middleware. The guard cannot be disabled as a plugin.

The guard reads the selected `IReverseProxyFeature.Route.Config`, exact HTTP method and canonical fingerprint. Missing/expired bundle returns 503; unpublished operation or route mismatch returns 403; missing/invalid authentication returns 401; identity/policy denial returns 403. It never calls the downstream on denial. Public responses include only status and correlation ID.

JWT bearer validation uses Authority/discovery/JWKS or a fixed trusted Issuer, signed token, allowed algorithms, lifetime/nbf and clock skew. Operation audience and optional scopes are evaluated after route selection. `typ=ID`/`ID_TOKEN` is rejected. `iss+sub` is resolved by IAM; `client_id`, `azp`, IP and caller headers never establish Service identity. InternalOnly additionally requires an IAM-resolved Service and the agreed trusted-channel claim/boundary.

Inbound identity and forwarding headers (`X-User-Id`, principal/role/permission/SystemId/OperationKey, Forwarded variants and the legacy `X-IAM-Resource-Proof`) are removed before proxying. The Gateway evaluates active Global grants for permission policies. Each service owns resource decisions. Configure ASP.NET Core Forwarded Headers middleware only with explicit known proxies/networks at the ingress boundary.

The entitlement cache is a dedicated size-limited `MemoryCache`, uses collision-resistant hashed keys, absolute expiration only, per-key single-flight and bounded concurrent fetches. Every request still executes JWT authentication. No IAM, Redis or Keycloak HTTP occurs on a valid cache hit. Fetch errors are not cached and become 503 on misses.

The bundle readiness health check is tagged `ready`. The Dashboard readiness endpoint also checks the bundle when IAM is registered. Last-known-good is usable until the authenticated lease expires.

Management-plane endpoints are separate from business PEP. Keep route registration disabled on public hosts, protect Dashboard/config API/gRPC with existing strong authentication and network isolation, and never use `GatewayApiAuthMode.None` in production. Swagger/Scalar/OpenAPI retain their existing dashboard/policy protection and opt-in/exclusion rules; documentation visibility never grants business forwarding.

The built-in response cache is bypassed on IAM hosts, and retry of non-idempotent operations is disabled there. Keep sensitive body and header capture disabled for protected routes. Never log Authorization, cookies, JWTs, internal IAM credentials or grant payloads.

See `samples/SampleGateway/appsettings.Iam.example.json` for non-secret settings. Supply `InternalApiToken` using environment variables or a secret manager.
