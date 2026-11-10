# IAM V1 Core transport contract

This is the Gateway-side contract. The IAM repository remains the source of truth and must publish the same versioned JSON schema and canonical hashes. JSON property matching is case-insensitive in the .NET client; producers should emit the property names shown by the C# records in `Aneiang.Yarp.Iam`.

## Published policy bundle

`GET {PolicyBundleEndpoint}` is a direct internal Gateway → IAM call. It must require a service credential or mTLS at the infrastructure boundary and must not traverse this Gateway's business proxy. The optional `InternalApiToken` is sent as a bearer credential; production should inject it from a secret provider, never configuration committed to source.

Required root fields are `schemaVersion` (`1.0`), positive `revision`, lowercase hexadecimal SHA-256 `hash`, `routeManifestHash`, `publishedAt`, future `validatedUntil`, and `policies`. A bundle is immutable. The Gateway accepts only a strictly newer revision and retains last-known-good only while `validatedUntil` remains in the future.

Each policy contains: `operationKey`, exact case-sensitive `routeId`, uppercase-insensitive `httpMethod`, lowercase route `routeFingerprint`, `applicationId`, `backendServiceCode`, `requiredAudience`, `authMode`, `allowedPrincipalKinds`, optional `requiredOAuthScopes`, `requiredPermissions`, optional `requiredBusinessScopes`, `requirementMode`, `enforcementMode`, and positive `policyRevision`.

`routeFingerprint` is SHA-256 over canonical UTF-8 JSON of security-relevant YARP route fields: RouteId, ClusterId, Match path/hosts/methods/headers/query constraints and ordered transforms. Destinations are excluded because service discovery changes destination instances without changing authorization semantics. Any match or transform change requires republishing the manifest.

`routeManifestHash` is SHA-256 over the JSON array sorted by RouteId then method, with entries `{ operationKey, routeId, method, routeFingerprint }`. `hash` is SHA-256 over canonical bundle content excluding `hash`, with policies sorted by RouteId, method and OperationKey. IAM and Gateway compatibility tests must compare known vectors before production integration.

Invalid schema, hash, manifest hash, timestamps, duplicate route+method, empty Permission requirements, Unconfigured mode, malformed/oversized JSON or a stale revision is rejected and never becomes current.

## Entitlement snapshot

`GET {EntitlementEndpoint}?issuer=...&subject=...&applicationId=...` is the authenticated internal lookup on cache miss. Required fields are `schemaVersion` (`1.0`), canonical `principalId`, exact `issuer`, exact `subject`, exact `applicationId`, positive `revision`, `issuedAt`, future `expiresAt`, `isActive`, `principalKind` (`User` or `Service`) and `grants`.

Each grant contains `permission`, business `scope`, optional `expiresAt`, and `source` (`Direct` or `Role`). The Gateway does not reconstruct roles. It evaluates the already-effective grants locally and checks each grant expiry. If `requiredBusinessScopes` is present, a permission is effective only when its grant has an exact required scope. Scope values are opaque business scopes; `System10` is never treated as `Global` or `System20`. Resource ownership and final SystemId enforcement remain downstream responsibilities for `GatewayAndResource`.

Bindings (`iss+sub+applicationId`) must exactly match the validated JWT-derived request. Mismatch, inactive identity, malformed data, over 10,000 grants or expired snapshot is not cached. Positive absolute lifetime is `min(EntitlementMaxAge=120s, snapshot.expiresAt)`; inactive negative lifetime is `min(NegativeCacheMaxAge=15s, snapshot.expiresAt)`.

Delegated/exchanged-token actor semantics are not defined in schema 1.0. IAM must publish an agreed extension before those identities can gain additional authorization; the Gateway must not infer delegation from headers or `azp` alone.
