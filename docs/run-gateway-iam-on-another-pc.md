# Run Gateway, IAM and Keycloak on another Windows PC

## Prerequisites

Use Windows, PowerShell 7.4+, the .NET 10 SDK, Docker Desktop with Linux containers, and a local SQL Server instance with Windows authentication. The Windows account running the initializer needs permission to create and migrate an isolated development database. Restore IAM with the NuGet feeds configured for that repository.

Clone the two feature branches next to each other:

```powershell
git clone -b feature/iam-v1-core https://github.com/behnamaltafi/IAM.git IAM
git clone -b feature/iam-local-pdp https://github.com/behnamaltafi/Gateway.Yarp.git Gateway
cd Gateway
```

## First run

Start Docker Desktop. Set the SQL instance name to the installed local instance. For a default SQL Server instance, use `localhost`. For a named instance, use a value such as `'.\MSSQLSERVER2'`.

```powershell
pwsh -NoProfile -File .\scripts\Initialize-LocalHttp.ps1 -IamPath ..\IAM -SqlServer '.\MSSQLSERVER2'
```

The initializer builds the projects, starts the Keycloak container on loopback, migrates `IAM_AuthorizationLab_gateway_http`, bootstraps an IAM administrator and grants the Dashboard test account Global `gateway.admin`. It stores generated client secrets and settings under the private, ignored `.gapcode/sso-http` directory on the new machine. These are Development test accounts:

| Panel | User | Initial password |
| --- | --- | --- |
| Gateway Dashboard | `gateway-local-admin` | `Bb@123123` |
| IAM Admin | `iam-test-admin` | `Bb@123123` |

The password is the local test default. Rotate it in the local realm when needed and update the corresponding private settings field if running the automated login check.

## Run and verify

For Visual Studio, open `Aneiang.Yarp.sln`, select `SampleGateway` as the startup project, choose **SampleGateway Local HTTP**, then press F5. The profile launches or reuses the dependencies. To run outside Visual Studio:

```powershell
pwsh -NoProfile -File .\Start-LocalGateway.ps1 -Http -VerifyLogin
```

| Component | URL |
| --- | --- |
| Gateway Dashboard | `http://localhost:17465/aneiang` |
| IAM Admin | `http://localhost:17464/` |
| IAM health | `http://localhost:17463/health/live` |
| Keycloak | `http://localhost:18445` |

Use one Gateway launcher per port. If a background Gateway process is already running, stop that local process before starting F5. Process IDs and logs are under `.gapcode/sso-http`. The launcher uses the IAM authorization controllers in a local host, and compiles the IAM Admin UI from the sibling checkout. For a business proxy smoke test, publish an operation policy against an exported route manifest. Dashboard SSO and its management grant can be verified independently.
