# MASTER PROMPT — توسعه Gateway.Yarp برای اتصال به IAM V1 Core

> Historical design. The current schema and enforcement boundary are documented in [IAM V1 Core transport contract](iam-policy-contract.md).

> **سند اجرایی مستقل برای Codex — فقط Repository مربوط به Gateway.**
>
> Repository هدف: `https://github.com/behnamaltafi/Gateway.Yarp.git`
>
> مرجع بررسی اولیه: شاخه `master`، Commit `f5d8e1bd869f9390e6377f4e4ab1879f44aaa13e` (۱۰ نوامبر ۲۰۲۶). هنگام اجرا **کپی محلی موجود و HEAD واقعی** را بررسی کن؛ ممکن است کد تغییر کرده باشد. نام‌ها/مسیرهای زیر برای راهنمایی مبتنی بر شواهد هستند، نه جایگزین بررسی سورس.
>
> این دستور فقط توسعه **Data Plane/PEP** و اتصال Gateway به IAM خارجی را پوشش می‌دهد؛ Backend اصلی IAM و پنل Blazor در Repository دیگر توسعه داده می‌شوند. در تعارض با نسخه قدیمی IAM که Ocelot می‌خواست، **YARP و همین Repository انتخاب قطعی جدید است**.

## 0. مأموریت، اولویت‌ها و حدود کار

تو در نقش Principal .NET / Gateway / Application Security Engineer عمل می‌کنی. **Gateway.Yarp فعلی را گسترش بده، نه اینکه Gateway جدید بنویسی.** هدف V1 Core:

1. `YARP + ASP.NET Core` به‌عنوان Proxy و PEP؛ `Keycloak` صرفاً IdP خارجی، خارج از Gateway.
2. دریافت Access Token واقعی، اعتبارسنجی محلی و استاندارد JWT، یافتن **Matched YARP Route**، بارگذاری **Published IAM Policy** و ارزیابی Permission با **Local PDP**.
3. `User` و `Service` هر دو دارای Role و Direct Permission در IAM؛ Gateway **Source of Truth** برای آنها نیست و هیچ IAM DB را مستقیم نمی‌خواند.
4. اختصاص L1 `IMemoryCache` محدود با Absolute TTL پیش‌فرض **120 ثانیه**، negative cache حداکثر **15 ثانیه**، single-flight. در **L1 hit معتبر برای Permission Decision هیچ درخواست HTTP به IAM/Redis/Keycloak** نباشد؛ JWT محلی هر بار validate شود.
5. `Route` یا `Operation` ناشناخته، بدون Published Policy، mismatch پیکربندی، Policy Bundle نامعتبر/منقضی → **Fail-Closed، هرگز Forward نشود**.
6. استفاده از Dynamic Routing/Config Provider، Dashboard، OpenAPI/Swagger/Scalar، Metrics و سایر قابلیت‌های موجود، با حداقل تغییر و **بدون بازنویسی**.
7. فقط V1 Core را بساز. Redis entitlement L2، Event Invalidation/Outbox، distributed synchronization، multi-Gateway coordination، workflow approval چندمرحله‌ای، ABAC/ReBAC، Dashboard IAM جدید و توسعه CI/CD **خارج از این کارند**.

### اصول غیرقابل تغییر

- Keycloak Admin Console، Realm، Client، Authentication Flowها، MFA، OTP، Device Flow، Token Exchange و مانند آنها را **پیاده‌سازی/پروکسی/مدیریت نکن**. Gateway یک Access Token معتبر را صرفاً به خاطر Flow صدورش رد نکند؛ اما token نوع اشتباه، audience اشتباه، delegation ناامن، هویت ناشناخته یا permission ناکافی همچنان رد شوند.
- مدل Business Permission مستقل از OAuth Scope، Route URL، Menu و Keycloak Role است.
- تفکیک `GatewayOnly` و `GatewayAndResource` حفظ شود؛ بررسی مالکیت رکورد و `SystemId` نهایی **وظیفه Microservice مقصد** است. Gateway از URL/Body مالکیت را حدس نزند.
- **هر مسیری که از Gateway عبور می‌کند** (از جمله Routeهای ایجادشده از Dashboard، API و Service Registration) باید از IAM enforcement عبور کند. حتی `AuthorizationPolicy=anonymous` در YARP مجوز Bypass نیست؛ `Anonymous` تنها پس از انتشار صریح IAM معتبر است.
- کد فعلی Repository، تاریخچه، فایل‌های Versioning، CI/CD، Git و Pluginها را بی‌دلیل پاک/بازنویسی نکن؛ قابلیت‌های موجود باید همچنان کار کنند.
- نام‌ها/Namespaceهای `Aneiang.Yarp.*` را برای این کار یک‌باره Rename نکن؛ نام‌گذاری مؤلفه تازه را با Convention مخزن سازگار کن.

## 1. Gate G0 — بررسی read-only کد موجود و نقطه‌های اتصال

ابتدا **قبل از هر ویرایش** سورس واقعی را بخوان، Git status/branch/commit و نسخه پکیج‌ها را ثبت کن، `restore/build` و تست‌های فعلی را اجرا کن. تغییرات کاربر را overwrite نکن. حداقل این فایل‌ها/مسیرها را بررسی کن:

```text
src/Aneiang.Yarp/Aneiang.Yarp.csproj
src/Aneiang.Yarp/Extensions/AneiangYarpServiceCollectionExtensions.cs
src/Aneiang.Yarp/Services/AneiangProxyConfigProvider.cs
src/Aneiang.Yarp/Services/DynamicYarpConfigService.cs
src/Aneiang.Yarp/Services/DynamicConfigPublisher.cs
src/Aneiang.Yarp/Services/GatewaySnapshotCompiler.cs
src/Aneiang.Yarp/Services/GatewaySnapshotPublisher.cs   # نام/محل واقعی را جستجو کن
src/Aneiang.Yarp/Services/RouteConfigManager.cs
src/Aneiang.Yarp/Controllers/GatewayConfigController.cs
src/Aneiang.Yarp.Dashboard/Extensions/DashboardApplicationBuilderExtensions.cs
src/Aneiang.Yarp.Dashboard/Modules/GatewayConfig/Controllers/RouteConfigController.cs
src/Aneiang.Yarp.Dashboard/Infrastructure/Auth/*
src/Aneiang.Yarp.Plugin.Abstractions/IGatewayPlugin.cs
src/Aneiang.Yarp.OpenApi/*
docs/openapi.md
samples/SampleGateway/*
tests/*
```

**اطلاعات احراز‌شده هنگام تهیه دستور:** نسخه اصلی YARP در `Aneiang.Yarp.csproj` برابر `2.3.0` و TFM پروژه‌های بررسی‌شده `net10.0` است؛ `Aneiang.Yarp.OpenApi` از `MMLib.OpenApiForYarp`/`SwaggerUI`/`Scalar` نسخه `1.1.0` بهره می‌برد. `AneiangProxyConfigProvider` یک `IProxyConfigProvider` با snapshot و change token است؛ `GatewaySnapshotCompiler` برای pipeline افزونه‌ها و `DashboardApplicationBuilderExtensions.UseAneiangYarpDashboard` برای ثبت `MapReverseProxy` استفاده می‌شوند. **اینها را در HEAD فعلی دوباره تأیید کن.**

### خروجی Gate G0

فایل کوتاه `docs/iam-gateway-integration-plan.md` بساز که در آن موارد زیر مشخص باشند:

- ورودی واقعی `AddAneiangYarp`, `UseAneiangYarpDashboard`, `MapReverseProxy` و `UseAuthentication/UseAuthorization`.
- مسیرهای فعال‌سازی/ویرایش Route از `appsettings`، Dashboard، REST، gRPC/client auto-registration، persistent restore، config rollback و plugin center؛ هرکدام را به enforcement پوشش بده.
- مکان مناسب mandatory security gate، pipeline ordering، نحوه دسترسی **ایمن** به Matched Route/Route Config و روش جلوگیری از bypass.
- قابلیت‌های موجود که reuse می‌شوند، Gapها، riskهای واقعی، نسخه‌ها و تست‌های PoC لازم.

برای غلبه بر کمبود اطلاعات یا API ناسازگار Reflection/Hack و پیاده‌سازی جعلی ننویس؛ PoC بساز، نتیجه را ثبت کن.

## 2. مالکیت مسئولیت‌ها و جلوگیری از پیاده‌سازی تکراری

| مسئولیت | صاحب آن در V1 Core | Gateway دقیقاً چه می‌کند؟ |
|---|---|---|
| Authentication, SSO, MFA, Token Issuance | Keycloak خارجی | فقط Access Token معتبر را validate می‌کند |
| Principal registry / Role / Permission / Grant / Scope | IAM Authorization API + SQL | روی cache miss Snapshot معتبر دریافت می‌کند، local evaluate می‌کند |
| BackendService Registry و OpenAPI **Import برای Permission Catalog** | IAM Control Plane | نتیجه Published Policy/RouteManifest را مصرف می‌کند؛ کاتالوگ دیگری نمی‌سازد |
| YARP Route/Cluster و تنظیمات اجرایی Proxy | Gateway.Yarp موجود | مدیریت فنی از قابلیت موجود و اعمال Validation/Gating IAM |
| Swagger و Scalar و OpenAPI **نمایش مستندات** | `Aneiang.Yarp.OpenApi` موجود | reuse؛ نه Import تجاری IAM و نه مرجع Permission |
| Policy authoring + Validate/Publish + Audit تجاری | IAM Control Plane | دریافت و فعال‌سازی نسخه معتبر؛ بدون Policy Editor دوم |
| Reverse Proxy + Authz enforcement | Gateway.Yarp | mandatory PEP + Local PDP، deny/no forward |
| Resource ownership/SystemId | Microservice مقصد | pre-check، سپس downstream final check |
| مدیریت کاربران/Roleها/Grantها در UI | Blazor IAM خارج از این Repo | هیچ UI جدید در Gateway نساز |

**دو مفهوم OpenAPI را یکی نکن:** نمایش Swagger/Scalar تجمیعی موجود، جایگزین `BackendService → OpenAPI Import → stable OperationKey → IAM Policy Publish` نیست. تو صرفاً Documentation موجود را نگه می‌داری و Mapping منتشرشده از IAM را اجرا می‌کنی.

## 3. طراحی Mandatory IAM PEP داخل YARP

### 3.1 PoC پایپ‌لاین، قبل از پیاده‌سازی کامل

- از `RouteConfig.AuthorizationPolicy`، `RouteConfig.Metadata`، ASP.NET Core Authentication/Authorization و extension point **واقعی همان نسخه مخزن** استفاده کن؛ ادعای APIهای Ocelot (`PreAuthorizationMiddleware` و `DownstreamRoute`) را کاملاً حذف کن.
- به‌طور مشخص **فقط یک `MapReverseProxy`** در Host باقی بماند؛ `UseAneiangYarpDashboard` در مخزن فعلی آن را register می‌کند. اگر لازم بود از پارامتر `configureProxyPipeline` یا extension رسمی مناسب همان Host استفاده کن.
- بهترین نقطه را با Integration Test ثابت کن: route و HTTP method از **endpoint یا `IReverseProxyFeature` واقعیِ matched**، نه حدس بر اساس `Request.Path`، Header، Path lowercasing یا الگوی string.
- PEP باید **پیش از Forward و قبل از هر plugin با side effect حساس** اجرا شود. پیاده‌سازی به‌شکل **Mandatory Guard** در Host/proxy pipeline یا hook امن متناظر باشد. آن را در `IGatewayPlugin` قابل Disable از Plugin Center قرار نده. اگر Plugin Interface را برای بسته‌بندی استفاده می‌کنی، enforcement مستقل و غیرقابل‌دورزدن بماند.
- `UseAuthentication()` باید پیش از `UseAuthorization()` و پیش از اجرای Policyهای proxy باشد. کد موجود `DashboardUseOptions.AutoUseAuthorization` و `AutoUseCors` دارد؛ اگر pipeline را صریح می‌چینی، آنها را برای جلوگیری از تداخل/اجراهای ناخواسته درست تنظیم کن و **CORS باز پیش‌فرض** را برای listenerهای حساس به سیاست محدود و قابل‌توجیه تغییر بده.
- در IAM-enabled deployment، هیچ fallback به allow وجود نداشته باشد؛ حتی اگر `RouteConfig.AuthorizationPolicy` خالی، `anonymous` یا توسط Dashboard اشتباه ویرایش شده باشد. YARP برای Route بدون AuthorizationPolicy الزاماً Authorization اجرا نمی‌کند؛ به این تنظیم به‌عنوان تنها حفاظ تکیه نکن.
- Endpointهای غیرproxy مانند Dashboard، Gateway Admin API، registration/gRPC، health و Swagger/Scalar **مرز امنیتی و سیاست جداگانه** دارند. Generic allowlist مانند `StartsWith("/api/")` برای عبور از IAM ممنوع است.

### 3.2 جدول سیاست‌های لازم

برای Operation منتشرشده، موارد زیر را طبق **قرارداد نسخه‌دار IAM** بخوان و validate کن:

```text
OperationKey (stable)
RouteId + matched HTTP method + canonical routing fingerprint / manifest binding
ApplicationId / BackendServiceCode / RequiredAudience
AuthMode = Anonymous | Authenticated | Permission | InternalOnly | Unconfigured
AllowedPrincipalKinds = User, Service
RequiredOAuthScopes (اختیاری؛ سقف Token، نه Business Permission)
RequiredPermissions + RequirementMode = Any | All
EnforcementMode = GatewayOnly | GatewayAndResource
PolicyRevision / SchemaVersion / Hash / ValidatedUntil
```

- `Unconfigured`, invalid kind/audience, unknown operation, disabled service, empty Permission policy → Deny.
- `Anonymous` تنها در Published Bundle و با eligibility قواعد امنیتی مجاز است؛ Route منتشرنشده هرگز به خاطر مقدار YARP `anonymous` عمومی نشود.
- `Authenticated`: token معتبر و Principal شناخته‌شده/active؛ بدون Business Permission ولی با audience/kind/scope محدودکننده در صورت تنظیم.
- `Permission`: Direct/Role effective grants از Snapshot؛ Policy All/Any؛ `Scope=System` به معنای `Global` نیست.
- `InternalOnly`: فقط identity واقعی Service + audience معتبر + کنترل کانال/شبکه مورد اعتماد؛ صرف IP خصوصی یا `client_id` کافی نیست.
- `GatewayAndResource`: Gateway فقط pre-check می‌دهد؛ مقصد باید `SystemId` و ownership را با داده معتبر خودش enforce کند.

### 3.3 هویت و توکن

- `AddJwtBearer`/Microsoft IdentityModel استاندارد با `Authority`, trusted issuer, signature/JWKS, allowed algorithms, lifetime/clock skew, `nbf`, audience و audience **مخصوص Operation**؛ ID Token را Bearer Access Token قبول نکن.
- `iss+sub` و در مورد Service، هویت client/service-account در **IAM registry معتبر** resolve شود. `azp` یا `client_id` به‌تنهایی Service بودن را اثبات نمی‌کند؛ User نمی‌تواند با جعل Header مجوز Service را قرض بگیرد.
- Route Policy به Grant Type خاص hardcode نشود. Keycloak Flowهای مختلف، محدود به قابلیت Token صادره، نباید موجب تغییر PolicyEngine شوند؛ Delegated/Exchanged Token باید علاوه بر اعتبارسنجی، محدودیت Actor/Subject مربوط را داشته باشد. اگر قرارداد Delegation کامل در Core وجود ندارد، **بدون Allow اضافی** وضعیت را Reject/Blocked و در ADR توضیح بده.
- Keycloak در این Repository نصب/Proxy/Admin نمی‌شود؛ دسترسی به discovery/JWKS استاندارد فقط برای Validation و cache signing keys است. اعتبارسنجی JWT محلی در هر درخواست ادامه دارد؛ Cache Hit entitlement به معنای Skip JWT validation نیست.
- Headerهای ورودی مانند `X-User-Id`, `X-Principal-Id`, `X-Role`, `X-Permission`, `X-SystemId`, `X-Operation-Key`, `X-Forwarded-*` نامعتبرند؛ spoofing را با sanitization و trusted-proxy configuration مدیریت کن. در صورت Forward کردن token واقعی به downstream، Audience و trust boundary مقصد معتبر باشد.

### 3.4 نتیجه و HTTP Status

```text
Missing/invalid/expired JWT برای route محافظت‌شده: 401
Valid identity ولی permission/kind/scope/policy Deny: 403
Unknown/Unpublished route or operation: 404 یا 403 (never forward)
IAM snapshot miss + internal IAM down / policy unavailable: 503 (never allow)
Valid L1 cache hit + IAM API down: local decision فقط تا ExpiresAt
Expired bundle یا mismatched route-policy: blocked + readiness degraded
```

اطلاعات حساس Permission/Grant/Token را در HTTP response عمومی نده؛ reason code داخلی، CorrelationId و metrics ثبت شود.

## 4. Entitlement Cache و Local PDP (V1 Core)

- `IMemoryCache` **dedicated + SizeLimit + max entries** و `absolute expiration`، `EntitlementMaxAge=120s` قابل تنظیم، negative deny cache <=15s، بدون sliding.
- Snapshot پیشنهادی و Transport Contract با IAM: `SchemaVersion, PrincipalId, Issuer/Subject binding, ApplicationId, Revision, IssuedAt, ExpiresAt, IsActive, Grants[]`. Contract واقعی را با IAM agent هماهنگ کن؛ API/JSON ساختگیِ ناسازگار بساز و بعد به آن تکیه نکن.
- Cache key از claimهای **validated** و شناسه canonical Principal/Application و context معتبر؛ عدم collision و raw unbounded keys؛ `ExpiresAt` هر Grant جدا از عمر Snapshot بررسی شود.
- `single-flight` per-key، bounded concurrency/queue، cancellation/timeout و idempotent retries محدود روی miss؛ فقط با **internal authenticated IAM endpoint** ارتباط بگیر. از Circuit Breaker موجود در مسیر مناسب reuse کن اگر با امنیت و بودجه Retry سازگار است؛ authz request را وارد pluginهای عمومی request-retry نکن بدون تحلیل.
- پاسخ `schemaVersion/hash` ناسازگار، Principal mismatch، timestamp نامعتبر، oversized payload، revision invalid یا malformed JSON وارد cache نشود؛ هیچ HTTP 500/timeout/parse error به Allow تبدیل نشود.
- در L1 hit معتبر تصمیم Permission صرفاً local باشد: outbound HTTP به IAM/Keycloak/Redis **صفر**. در missing/expired snapshot، اگر IAM unreachable بود 503؛ هرگز stale-while-revalidate مثبت پس از TTL.
- `Redis rate-limit` موجود همان **Redis Entitlement Cache** نیست. **Redis L2، Pub/Sub، Outbox و Event Invalidation** را به Core اضافه نکن.
- وضعیت suspended کاربر در IAM تا TTL می‌تواند stale بماند؛ غیرفعالی در Keycloak برای token از قبل صادرشده تا پایان lifetime/refresh policy ممکن است متفاوت باشد. این Trade-off در مستندات شفاف بماند.

## 5. Route–Policy Publication و جلوگیری از Bypass مسیرهای Dynamic

**این بخش حیاتی‌ترین تفاوت نسبت به Ocelot و مهم‌ترین ریسک مخزن فعلی است.** مخزن مسیرهای متفاوت برای دستکاری Route دارد؛ PEP باید مستقل از همه آنها عمل کند.

### 5.1 قرارداد انتشار با IAM

- **Authoring، validation کسب‌وکاری، ثبت Audit و Publish** در IAM API انجام می‌شود. Gateway فقط **Published RouteManifest+PolicyBundle** نسخه‌دار را از endpoint داخلی معتبر دریافت می‌کند.
- فیلدهای الزامی Bundle: `SchemaVersion`, `Revision`, `Hash`, `RouteManifestHash`, `PublishedAt`, `ValidatedUntil`, و policy mapping دقیق؛ محتوای bundle immutable باشد. برای SHA-256 و canonical serialization، قرارداد واحد قابل تست بین دو Repo تعریف کن؛ نتیجه Hash با payload واقعی سنجیده شود.
- با Client Authentication داخلی (مثلاً service identity دارای audience مناسب یا mTLS) Bundle را Pull کن. مسیر فراخوانی آن نباید از همان Proxy/PEP عبور کند که برای آماده شدنش به آن نیاز دارد؛ **Gateway → IAM internal API مستقیم و حفاظت‌شده**.
- Bundle در Startup قبل از Ready validate شود و snapshot محلی immutable داشته باشد؛ روی Refresh موفق، **سازگاری config واقعی فعال YARP با policy** چک شود. Last Known Good فقط تا `ValidatedUntil` و با integrity check مجاز است.
- اگر IAM و Gateway به دو Repository جدا تقسیم می‌شوند، DTOهای قراردادی را از طریق OpenAPI schema/نسخه‌بندی یا یک shared package کم‌حجم و تست‌شده هماهنگ کن؛ پروژه‌های EF/Domain/Application IAM را داخل Gateway Reference نکن.

### 5.2 دفاع در همه مسیرهای تغییر Route

مسیرهای زیر را با test جداگانه پوشش بده و هیچ‌کدام حق بازکردن Route بی‌Policy را نداشته باشند:

1. Static routeهای `ReverseProxy` در appsettings.
2. REST Route Registration/Update مثل `GatewayConfigController`.
3. Dashboard native Route CRUD و import/export/restore/rollback.
4. gRPC/Client SDK auto-registration و service-discovery refresh، هرجا می‌توانند route/destination فعال را تغییر دهند.
5. persisted SQLite state و راه‌اندازی دوباره Gateway.
6. config change token/hot-reload و plugin binding changes.

**حداقل راهکار V1 Core:** Guard runtime قبل از Forward که به `RouteId + HTTP method + matched route fingerprint` و Policy Bundle معتبر bind شده است؛ تغییر Route جدید/ناهمخوان فوراً Deny می‌شود، حتی اگر Pipeline مدیریت YARP آن را در حافظه منتشر کرده باشد. در کنار آن، **Publish Validation Gate** روی config snapshot در مسیر فعال‌سازی، برای کاهش خطاها اضافه کن. Gate نباید تنها حفاظ باشد، چون ممکن است مسیرهای دیگری برای تغییر Runtime وجود داشته باشد.

- مسیرهایی که به Snapshot جاری Backend وصل می‌شوند نباید به‌صرف انتشار یک YARP config جدید permission تازه بگیرند. اگر Route یا Transforms semantics تغییر کردند، fingerprint و manifest سازگار لازم است.
- `GET` و `DELETE` روی یک Path، Host، method constraints، path transform، catch-all/encoded slash و overlapping route precedence را تست کن. `OperationId` مستندات Swagger یا URL تنها کلید Permission نیست.
- برای Startup/restore و on-the-fly route update، **Fail Closed** را بر availability ترجیح بده؛ عدم cross-node atomicity برای Core مشکلی ندارد (فقط یک Gateway instance).
- `AneiangProxyConfigProvider` را نگه دار؛ **IProxyConfigProvider دوم، shadow routing state و MapReverseProxy دوم نساز**. اگر extension کوچک لازم است، در همان snapshot/compiler/provider موجود با حداقل دستکاری و تست regression انجام بده.
- Gateway Dashboard همچنان می‌تواند تنظیمات فنی را مدیریت کند، اما **Dashboard نمی‌تواند منبع Publish Business Authorization باشد**. جلوگیری از به‌روزرسانی ناخواسته سیاست و کنترل دسترسی به UI/API مدیریتی لازم است.

### 5.3 دامنه Management Plane

- در Host با IAM فعال، `enableRegistration:false` پیش‌فرض امن برای public-facing host باشد؛ اگر ثبت سرویس الزامی شد، تنها listener/internal endpoint با authentication قوی و allowlist شبکه.
- Dashboard admin، API مدیریت config، gRPC registration، storage/config rollback و Swagger/Scalar باید جداگانه authenticated/network-isolated باشند. تنظیم `GatewayApiAuthMode.None` یا تنظیم permissive CORS برای Production قابل قبول نیست؛ **صرف داشتن JWT برای Business API از Management Plane حفاظت نمی‌کند**.
- auth داخلی Dashboard موجود را بی‌دلیل rewrite نکن؛ اگر integration با Keycloak برای Dashboard اجباری نیست، از تنظیم محافظت‌شده/شبکه خصوصی آن استفاده کن. **پنل Blazor IAM در Repository دیگری است** و هیچ Blazor جدیدی به Gateway اضافه نکن.
- داشبورد فعلی Gateway ممکن است WebSocket/SignalR برای Traffic داشته باشد؛ ممنوعیت SignalR قبلی **مخصوص پنل Blazor IAM** بود. این دستور به تو اجازه حذف/بازنویسی بی‌درخواست Realtime Dashboard موجود را نمی‌دهد.

## 6. استفاده مجدد از OpenAPI / Swagger / Scalar و Pluginها

### 6.1 OpenAPI

- ماژول موجود `Aneiang.Yarp.OpenApi` با MMLib 1.1.0 را reuse کن: `/swagger`, `/scalar`, `/openapi/{cluster}.json`, `/openapi/all.json` و Dashboard documentation links.
- `AddAneiangOpenApi`, `UseAneiangOpenApi`, `AddAneiangOpenApiDashboard` با lifecycle و `MapReverseProxy` فعلی یکپارچه‌اند؛ بدون نیاز ماژول جدید یا fetch/aggregation دیگری نساز.
- مستندات باید فقط به clusters opt-in و در دسترس مدیر مجاز باشند؛ `AddOnlyPublishedPaths`, `IncludePaths`, `ExcludePaths` و تنظیم دسترسی اسناد را رعایت کن. **نمایش یک endpoint در Swagger یا نبود آن، دلیل مجاز/غیرمجاز بودن Forward نیست**؛ Mandatory PEP همیشه قضاوت می‌کند.
- `/swagger` و `/scalar` اگر روشن می‌شوند روی Listener/Policy مجاز و با Auth جدا باشند؛ endpointهای `/internal` را به شکل غیرمجاز در مستندات عمومی expose نکن.

### 6.2 سایر قابلیت‌های موجود

- از RateLimit، Health، Metrics، WAF، CircuitBreaker و Logging موجود **فقط در صورت نیاز Core و بعد از تست سازگاری** استفاده کن؛ هیچ dashboard observability دوم نساز.
- **Response Cache** روی APIهای حاوی داده شخصی/مجوزدار ممکن است نشت بین کاربران ایجاد کند؛ برای protected routes پیش‌فرض خاموش باشد مگر test isolation و cache-key بر مبنای امنیت اثبات شود. Entitlement cache مستقل است.
- `request-retry` برای عملیات state-changing، به‌ویژه POST/DELETE، بدون قرارداد idempotency ممنوع؛ قابلیت پیش‌فرض existing را طوری نگه دار که Core محافظت شود.
- Proxy Logging باید Authorization header، Cookie، JWT، Secret، body حساس و PII را redacted کند؛ قابلیت ضبط کامل request در Production بدون سیاست محافظت فعال نشود.

## 7. اجرای مرحله‌ای Codex — تنها V1 Core

### G0 — Baseline & inventory

- Clone/checkout local موجود، Git status، Build/Test پایه، Architecture map، فهرست route mutation paths، تعیین integration seam. بدون تغییر بیرون Repository.
- خروجی: `docs/iam-gateway-integration-plan.md` و جدول Smoke Test مخزن.

### G1 — PoC ایمنی Routing/PEP

- یک Protected Route و یک Anonymous Published Route ساختگیِ تستی؛ PEP بر Matched YARP Route پیش از Forward؛ سناریوی `AuthorizationPolicy=null/anonymous` از طریق YARP در حضور IAM بدون bypass.
- مسیر ثبت route از REST/Dashboard (یا معادل تست داخلی) نتواند Policy را دور بزند. `UseAuthentication/UseAuthorization` ordering درست. بدون side effect به Proxy.
- اگر hook واقعی نیاز به تغییر دارد، کوچک‌ترین extension قابل‌تست را انتخاب کن، با ADR برای دلیل.

### G2 — JWT + Local PDP + L1 Cache

- Keycloak JWT bearer validation، trusted User/Service resolver، HTTP authenticated entitlement fetch، policy evaluator محلی، TTL 120/15، single-flight و 401/403/503.
- برای تست بدون Secret واقعی Fake JWT signer فقط در Test Project؛ **Production هیچ fake auth ندارد**. E2E با Keycloak خارجی اگر در دسترس است؛ در غیر این صورت Blocked ثبت شود نه Pass.

### G3 — Published Bundle & Dynamic Config Safety

- secure policy bundle pull/validate؛ snapshot local immutable؛ route manifest compatibility؛ startup readiness؛ safe refresh؛ route update/restore/registration tests؛ known-good با expiry محدود.
- Controllerهای مدیریت Gateway یا publisher جاری را بی‌دلیل بازنویسی نکن؛ enforcement باید همه مسیرهای تغییر را مستقل پوشش دهد.

### G4 — Existing Plugins/OpenAPI & security regression

- استفاده از Swagger/Scalar موجود، docs access و exclusions، security listener setup، response-cache/retry/logging safety، test regression روی dynamic routing و OpenAPI aggregation.
- اگر `Aneiang.Yarp.OpenApi` از قبل درست کار می‌کند، فقط Regression/Security Test مرتبط با IAM اضافه کن.

### G5 — End-to-End Acceptance و تحویل

- integration test واقعی Gateway→Sample Resource API و Gateway→IAM internal Snapshot API (stub فقط در Test Harness)؛ test با Keycloak در دسترس و Resource `SystemId` در سرویس نمونه (سورس نمونه در Repo جدا می‌تواند با قرارداد fixture باشد).
- build/test/failure report، منابع، نحوه راه‌اندازی امن، limitations و contract compatibility با IAM Core را بنویس.

**هیچ فاز V1.1/V2 را پیش از Pass بودن Core شروع نکن.** اگر تستی نیاز به IAM خارجی دارد و حاضر نیست، با Test Harness قراردادی Gateway را تکمیل کن ولی E2E واقعی را **Blocked** گزارش بده.

## 8. ماتریس تست اجباری Gateway

| شماره | سناریو | انتظار |
|---|---|---|
| S01 | Unknown Route / Unpublished Operation | No Forward؛ 403/404 |
| S02 | YARP route با `AuthorizationPolicy=null` | No bypass |
| S03 | YARP route با `AuthorizationPolicy=anonymous` اما IAM unpublished | No Forward |
| S04 | Explicit Published IAM Anonymous | فقط همان operation forward |
| S05 | Same path با GET و DELETE | policyهای مستقل |
| S06 | Host/path/method/transform/catch-all mismatch | Deny، بدون permission borrowing |
| S07 | Header spoof (`X-Principal`, `X-Role`, `X-OperationKey`, Forwarded) | رد اعتماد جعلی |
| S08 | JWT missing/expired/bad signature/wrong issuer/audience/ID token | 401 |
| S09 | User ↔ Service identity substitution | Deny؛ بدون Grant قرضی |
| S10 | User Direct Grant/Role Grant/Service Direct/Role Grant | نتیجه مطابق Snapshot معتبر |
| S11 | Scope `System10` در Gateway pre-check و Resource `System20` | Deny در مقصد |
| S12 | Valid L1 hit | 0 IAM/Keycloak/Redis HTTP، JWT validation همچنان فعال |
| S13 | Parallel miss حداقل 20 درخواست | single-flight/bounded fetch |
| S14 | Positive TTL <=120 و negative <=15، clock-injected | expiry بدون sliding |
| S15 | Grant ExpiresAt قبل از Snapshot | expired grant Deny |
| S16 | IAM API down با valid cache / cache miss | local until expiry / 503 |
| S17 | Malformed/oversized/mismatched entitlement | Deny/Unavailable، عدم Cache Poison |
| S18 | Bundle bad hash/schema/expired | blocked، readiness degraded |
| S19 | RouteManifest mismatch با YARP snapshot | no Forward |
| S20 | REST/Dashboard/gRPC registration و persisted restore | هر مسیر بدون Published Policy blocked |
| S21 | Runtime route mutation / config reload | Policy binding قدیمی برای Route جدید reuse نشود |
| S22 | Startup بدون Bundle معتبر | readiness false، protected routes blocked |
| S23 | Swagger/Scalar access + internal path exclusions | docs protected، business policy مستقل |
| S24 | Response cache/retry/logging protected route | بدون نشت هویت و Replay ناامن |
| S25 | Health/Admin/Gateway management endpoints | جدا و محافظت‌شده؛ نه Business bypass |

تست‌های موجود `tests/Aneiang.Yarp.Regression`، `tests/Aneiang.Yarp.OpenApi.Integration` و نمونه `SampleGateway` را **حفظ** کن؛ معادل‌های مناسب جدید را بر اساس Convention همان Repo اضافه کن. هر تست را با `PASS/FAIL/BLOCKED` و command واقعی ثبت کن؛ صرف نوشتن تست یا document کافی نیست.

## 9. Git Flow، نسخه‌گذاری و قیود تغییر

- `master` فعلی را به‌عنوان شاخه Production ببین؛ پیش از تغییر، وضعیت `develop` و فایل‌های Git/Versioning/Conventional Commit را بررسی کن. برای کار جدید branch از نوع `feature/iam-local-pdp` یا نام مشابه طبق Git Flow از `develop` بساز؛ اگر develop وجود ندارد، بدون تخریب/Force و مطابق محدودیت دسترسی عمل کن.
- Commitها Conventional باشند، نمونه: `feat(gateway): enforce published IAM route policies`, `test(gateway): reject unconfigured dynamic routes`, `docs(gateway): document IAM integration`.
- **فایل‌های versioning و CI/CD و release scripts فعلی را تغییر نده**؛ هیچ pipeline، package publish، tag، push، force-push، merge به `master`، release یا deployment واقعی بدون دستور صریح کاربر انجام نده.
- Config/Sample Secrets واقعی commit نشوند؛ از env / user secrets / Secret Manager استفاده کن. تغییر مخرب SQLite/DB، حذف فایل یا گسترده‌سازی غیرمرتبط ممنوع.

## 10. خروجی‌های اجباری

حداقل این فایل‌های مرتبط را در Repo بساز/ویرایش کن (نام/محل دقیق مطابق Convention مخزن):

```text
docs/iam-gateway-integration-plan.md
docs/iam-policy-contract.md
docs/iam-gateway-security.md
docs/iam-gateway-acceptance.md
# source: mandatory IAM PEP + pure local evaluator + JWT adapter +
#         entitlement L1 cache + trusted IAM HTTP client + bundle validator/provider
# tests: routing/security/cache/bundle/integration (existing test conventions)
# samples: IAM-enabled config only, without secrets
```

در گزارش انتهایی: `HEAD/branch`, فایل‌های تغییرکرده، مسیر hook و دلیل انتخاب، re-used components، قراردادهای موردنیاز IAM، commandهای build/test، Pass/Fail/Blocked، مسیرهای باقی‌مانده برای bypass که بررسی کردی، Known Risks و **مرزبندی دقیق کارهایی که IAM team باید در Repo خودش انجام دهد** را ارائه بده.

### Definition of Done — فقط Gateway V1 Core

1. Gate G0 و baseline build/test ثبت شده باشد؛ Existing YARP routing, dashboard, swagger/scalar, plugin extension و config persistence با تست regression حفظ شده باشند.
2. Mandatory PEP واقعی قبل از Forward، از matched route/method و **published policy exact** استفاده کند؛ هیچ مسیر ویرایش/ثبت Route نتواند bypass ایجاد کند.
3. JWT استاندارد، IAM principal binding، Direct/Role Grants، User/Service، business scope، allowed kinds و audience correctly evaluate شوند؛ flow-specific restriction بی‌دلیل ایجاد نشده باشد.
4. L1 entitlement cache bounded + absolute TTL 120/15 + single-flight + **zero network on valid hit** و fail-closed در miss/down/expired اثبات شده باشد.
5. Published Bundle + RouteManifest immutable/hash/version/expiry معتبر؛ startup/readiness و route mutation امن؛ no unknown route forward.
6. Management Plane protected؛ Swagger/Scalar موجود reuse شده؛ response-cache/retry/logging خطرناک روی مسیرهای محافظت‌شده کنترل شده باشد.
7. تست‌های S01–S25 واقعی با نتیجه ثبت شوند؛ E2E بدون محیط واقعی صرفاً Blocked بماند، نه Pass.
8. هیچ Ocelot، IAM SQL/DbContext، Blazor جدید، Keycloak Admin API، Redis L2، Outbox، Approval workflow، Multi-Gateway coordination یا CI/CD جدید ساخته نشده باشد.

## 11. دستور کوتاه شروع — مستقیم به Codex بفرست

> فایل `Codex-Gateway-Yarp-IAM-V1-Core-Standalone-Prompt-fa.md` را کامل مطالعه کن و فقط روی Repository `Gateway.Yarp` موجود اجرا کن. ابتدا read-only inventory + baseline build/test و Gate G0 را انجام بده. YARP و Dashboard، Snapshot Provider، Pluginها و OpenAPI/Swagger/Scalar موجود را reuse کن؛ Gateway جدید/Ocelot/MapReverseProxy دوم/Route Provider دوم نساز. **Mandatory IAM PEP غیرقابل Disable** را قبل از Forward با Matched YARP Route + Method پیاده کن؛ Route جدید حتی از Dashboard/Registration/Restore بدون Published Policy معتبر هرگز Forward نشود. JWT استاندارد Keycloak خارجی، User/Service principal mapping، Local PDP و L1 cache با Absolute TTL 120s/negative <=15s و بدون هیچ تماس HTTP در valid cache hit؛ Fail Closed؛ Bundle/RouteManifest immutable و hash/revision سازگار. IAM API جدا مسئول Role/Permission/Grant/Policy authoring است؛ Gateway صرفاً Snapshot می‌گیرد و locally evaluate می‌کند. فازهای G0 تا G5 و S01 تا S25 را با تست واقعی پیش ببر. فقط V1 Core، Git Flow و Conventional Commits؛ CI/CD/Versioning موجود تغییر نکنند؛ بدون Push/Merge/Tag/Release خودسرانه. وضعیت Pass/Fail/Blocked مستند شود.

## 12. منابع و نقاط مرجع

- Repository: https://github.com/behnamaltafi/Gateway.Yarp
- مستندات OpenAPI در Repo: https://github.com/behnamaltafi/Gateway.Yarp/blob/master/docs/openapi.md
- YARP Authorization: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/yarp/authn-authz
- YARP Middleware: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/yarp/middleware
- YARP Configuration: https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/yarp/config-files

**تفاوت تصمیم جدید با سند قدیمی IAM:** تمام عبارت‌های Ocelot، Ocelot PreAuthorization و مدیریت Route با Ocelot **برای Gateway منسوخ‌اند**؛ اما مدل Role/Permission/Scope، Cache/TTL، Policy Snapshot و Fail-Closed همچنان الزام هستند.
