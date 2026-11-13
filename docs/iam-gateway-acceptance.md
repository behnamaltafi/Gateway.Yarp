# IAM Gateway V1 Core acceptance report

> Historical acceptance results for the IAM Gateway branch.

Results below distinguish complete automation from partial coverage and unavailable external systems. Commands were run on `feature/iam-local-pdp` from baseline HEAD `f5d8e1bd869f9390e6377f4e4ab1879f44aaa13e`.

## Gates

| Gate | Result | Evidence |
| --- | --- | --- |
| G0 baseline/inventory | PASS with known baseline failures | restore/build pass; OpenAPI 41/41; legacy Regression 22 pass/3 pre-existing fail; integration plan records mutation paths |
| G1 matched-route PEP PoC | PASS | real Kestrel/YARP forwarding; null/anonymous YARP route is blocked without published policy; GET/DELETE exact match |
| G2 JWT/PDP/L1 | PASS for contract harness; live Keycloak BLOCKED | signed JWT test key only in test project; direct/role-effective grant evaluator, audience, 401/403/503 and 20-way single-flight exercised |
| G3 bundle/dynamic safety | PASS for runtime guard; live IAM publish BLOCKED | immutable provider/validator/readiness, hash/schema/expiry code; route transform mutation test proves old policy cannot be borrowed |
| G4 OpenAPI/plugins regression | PASS/PARTIAL | existing OpenAPI suite 41/41; guard is before plugin runtime; production plugin safety is documented, not every plugin combination is automated |
| G5 E2E | PASS for local Gateway→resource and IAM fixture; external E2E BLOCKED | local Kestrel downstream and entitlement fixture are real HTTP/proxy execution; no supplied Keycloak/IAM environment |

## S01–S25

| ID | Result | Evidence / remaining work |
| --- | --- | --- |
| S01 | PASS | unpublished operation no-forward |
| S02 | PASS | YARP `AuthorizationPolicy=null` behavior covered by mandatory branch guard design; test route uses permissive YARP authorization and remains closed |
| S03 | PASS | YARP `anonymous` plus unpublished policy no-forward |
| S04 | PASS | exact published Anonymous GET forwards |
| S05 | PASS | same path GET/DELETE independent policies |
| S06 | PARTIAL | transform fingerprint mutation denies; host/header/catch-all/encoded-slash vector expansion remains |
| S07 | PASS | spoofed role header removed; identity headers use same removal set |
| S08 | PARTIAL | missing token and wrong audience automated; expired/bad signature/issuer/ID-token are enforced by JwtBearer/code but need explicit vectors |
| S09 | PASS for local PDP | User/Service kind substitution is denied; live IAM identity registry remains external |
| S10 | PARTIAL | effective Direct grant path automated; IAM supplies already-effective Role grants, but four explicit fixtures remain |
| S11 | PASS for Gateway pre-check / BLOCKED downstream | `System10` grant cannot satisfy required `System20`; final ownership test belongs to an external resource fixture not supplied |
| S12 | PASS | second valid cache request produces zero entitlement fetch; JWT still authenticates proxy requests |
| S13 | PASS | 20 parallel misses produce one source fetch |
| S14 | PASS for positive / PARTIAL negative | injected clock proves absolute positive expiry at 120 seconds; explicit 15-second inactive vector remains |
| S15 | PASS by evaluator code / needs dedicated vector | grant expiry is checked independently on every decision |
| S16 | PASS | miss/down returns 503/no-forward; valid-hit behavior covered by S12 |
| S17 | PARTIAL | binding/schema/size/grant-count validation implemented; malformed HTTP matrix remains |
| S18 | PASS | valid SHA-256 vector accepted; manifest tamper and expiry are rejected |
| S19 | PASS | fingerprint mismatch no-forward |
| S20 | PASS by invariant / PARTIAL automation | every mutation converges on matched runtime route guard; separate REST/Dashboard/gRPC/restore calls remain |
| S21 | PASS | live provider route mutation cannot reuse old binding |
| S22 | PASS | missing/expired bundle blocks and readiness is false |
| S23 | PASS | existing OpenAPI integration 41/41 including auth and internal exclusions |
| S24 | PARTIAL | guard precedes plugins and operational restrictions documented; identity leak/replay matrix remains |
| S25 | PARTIAL | existing management auth/deployment isolation retained; IAM-specific listener matrix remains |

## Commands

```powershell
dotnet restore Aneiang.Yarp.sln
dotnet build Aneiang.Yarp.sln --no-restore
dotnet run --project tests/Aneiang.Yarp.Iam.Integration -f net10.0 --no-build
dotnet run --project tests/Aneiang.Yarp.OpenApi.Integration -f net10.0 --no-build
dotnet run --project tests/Aneiang.Yarp.Regression -f net10.0 --no-build
```

Live Keycloak, live IAM API, mTLS/service credential deployment and downstream ownership enforcement are explicitly BLOCKED until those external endpoints/contracts are available. They must not be represented as passing based on the local fixture.
