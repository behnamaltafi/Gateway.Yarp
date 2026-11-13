# IAM V1 Core transport contract

The Gateway validates JWTs and applies published API policies. IAM publishes policies and resolves the effective grants for a principal and application. The destination service owns resource access, ownership, data isolation and business rules.

## Published policy bundle

`GET {PolicyBundleEndpoint}` goes directly to IAM over HTTPS with a service credential. The schema 1 envelope has `schemaVersion` (integer), `revision`, `contentHash`, `validatedUntil` and `policyContentBase64`. The hash is lowercase hexadecimal SHA-256 of the exact decoded content bytes. Decoded content contains `schemaVersion`, `revision`, `publishedAt`, `routeManifestHash`, `routeManifestBase64` and `policies`. The manifest hash covers the exact decoded schema 1 manifest bytes.

Each policy carries `applicationId`, `applicationCode`, `backendServiceCode`, `operationKey`, `gatewayRouteId`, `httpMethod`, `gatewayRouteFingerprint`, `authMode`, `requiredAudience`, `allowedPrincipalKinds`, `requiredOAuthScopes`, `requiredPermissions`, `requirementMode` and explicit string `enforcementMode`. GatewayOnly is the only accepted enforcement mode. Legacy resource flags are rejected as unknown policy members, including when false. IAM must explicitly publish compatible bytes at a fresh revision for cutover.

The manifest exporter uses the active YARP provider snapshot. The fingerprint hashes the route ID, cluster ID, order, match conditions and ordered transforms. Requests require an exact published route/method and a matching live fingerprint. Destination instances can change through service discovery. The control plane must protect cluster and destination administration.

The bundle store rejects revision rollback and same-revision content changes. IAM can renew the lease on identical content. The last validated bundle remains usable only before lease expiry. Missing or expired bundles cause readiness and proxy authorization to fail closed.

## Entitlement snapshot

`POST {EntitlementEndpoint}` sends schema 1, `applicationId` and `validatedIdentity` with `issuer`, `subject` and `clientId`. The reply includes integer `schemaVersion`, `principalId`, `applicationId`, `issuer`, `subject`, `principalKind`, `clientId`, `revision`, `issuedAt`, `expiresAt`, `isActive` and `grants`. Each effective grant carries `permissionCode`, `scopeKind`, `scopeId`, `expiresAt` and `source`.

Direct and role-derived Global grants qualify for GatewayOnly permission checks while active. System grants retain their System ID in the snapshot and cannot authorize API-wide permission. The Gateway strips incoming client identity and legacy proof headers. Each service uses its own trusted data for resource decisions.

The dedicated L1 bounds positive entries at 120 seconds and negative entries at 15 seconds, with the snapshot expiration as an additional bound. The PDP checks grant expiration on each decision. A miss that cannot resolve through IAM fails closed.
