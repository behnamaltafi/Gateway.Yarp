# Gateway Access ↔ Route ANY mode (draft)

The IAM and Gateway companion branches are:
- IAM: `behnamaltafi/IAM@feature/iam-access-route-any`
- Gateway: `behnamaltafi/Gateway.Yarp@feature/gateway-access-route-any`

This mode replaces the *proxy policy decision path* of the previous PublishedPolicyBundle-based integration, while preserving Keycloak JWT validation and the old internal entitlement client for Dashboard SSO. Do not remove the legacy entitlement API from IAM yet.

## Configuration

Use `samples/SampleGateway/appsettings.Access.example.json`, inject real Keycloak directory/admin/service credentials via environment variables or a secret store.

- `Gateway:Iam:Enabled=true` remains **mandatory** for validated JWT, managed Dashboard SSO, and protected internal gateway-to-IAM service token.
- `Gateway:Access:Enabled=true` selects the new middleware for YARP proxy routing; do not enable before IAM has imported the **actual incoming Gateway path** for every protected operation.
- `Gateway:Access:RoutesEndpoint` = `https://iam.internal/internal/v1/access-control/routes`
- `Gateway:Access:ResolveEndpoint` = `https://iam.internal/internal/v1/access-control/resolve`
- `Gateway:Iam:Audience` must appear in access JWT `aud`, in addition to issuer/signature/lifetime validation.
- `Gateway:Iam:EntitlementEndpoint` remains configured because Gateway Dashboard SSO still uses it.
- Setting `Gateway:Access:Enabled` will skip the legacy PolicyBundleRefreshService and legacy policy readiness healthcheck for the proxy. AccessRouteRefreshService + AccessReadyHealthCheck take over.
- HTTPS for all IAM endpoints. HTTP only for local development loopback explicitly enabled in the host.

## Decision process

1. YARP resolves the actual matching `RouteId`. The Access middleware strips incoming identity/proof headers. Route rules from IAM are matched to that YARP `RouteId`, **HTTP Method**, and **actual upstream request path** using ASP.NET route template matching. Catchall proxy routes do not grant blanket access.
2. If there is no unexpired route snapshot or no unique exact rule, deny (503 if no valid snapshot, 403 if unmapped/ambiguous).
3. Authenticate a **Bearer access token** using configured Keycloak authority, issuer, signing algorithms and lifetime. Validate the configured audience and extract `sub` (not username), `iss`, `azp/client_id`, `realm_access.roles`, `resource_access.*.roles`.
4. Resolve the subject's effective `AccessCodes` from IAM using an **internal client-credentials** token. IAM knows UserAccess + RoleAccess; the browser does not provide role IDs or grant modifications.
5. Verify matching application, subject, issuer, revision and expiry; cache the result for no longer than 30 seconds. Refresh route snapshot every 15 seconds, expiry 60 seconds. Missing IAM at expiration fails closed.
6. **ANY semantics:** at least one Access code from the matched route must be in the effective Access set. Empty Access list always means DENY. Parent Group does not imply child grants.
7. Only then proxy to the destination. Destination enforces row ownership/tenancy.

The route JSON is the same `schemaVersion = 1` as IAM `docs/iam-simple-access-any.md`. This is a new Access-specific contract; not the previous PublishedPolicyBundle schema.

## Mandatory production checks

- Source project must compile against .NET 10, private NuGet dependencies must restore; execute existing `tests/Aneiang.Yarp.Iam.Integration` and IAM tests.
- Verify Keycloak JWT role serialization and exact issuer/audience/key rotation.
- Verify route ID, case, parameter matching, multiple Access-to-route assignments, method mismatch, ambiguous templates and default denial.
- Test SQL migration up/down, import path prefix, read/write permissions and admin self-escalation.
- Test no direct backend entrypoints bypass Gateway.
- Run IAM and Gateway together with real Keycloak and SQL Server; then run OAuth User Authorization Code + PKCE and Service Account Client Credentials.
- Verify empty/expired grants, stale revision, IAM outage and disabled accounts; ensure no cached grant lasts beyond expiry.
- Test OAuth Token Exchange separately. Legacy Keycloak `act` tokens are rejected by the inherited JWT validator; do not claim full OBO support.
- The role reference in IAM stores a Keycloak UUID, but Keycloak access tokens commonly include only role names. A deleted role recreated with the same name can inherit a stale IAM RoleAccess mapping unless administrators reconcile it (or Keycloak emits stable role IDs). Mark this as a production-cutover risk.

## Non-goals

No new Permission, PolicyEngine, ApprovalWorkflow, operation-specific publication or SignalR. The new Access mode operates independently of the legacy operation catalog approval/binding/publication, which remains available for existing deployments until reviewed migration.
