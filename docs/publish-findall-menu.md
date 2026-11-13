# راهنمای اتصال FindAll به منوی فرانت

در این مثال، کاربر منوی «فهرست نمونه‌ها» را می‌بیند، فرانت صفحهٔ `/samples` را باز می‌کند و جدول از Gateway داده می‌گیرد. مسیر، متد و مدل ورودی را با Swagger سرویس خودت تطبیق بده. اکشن نمونهٔ موجود در `IAM.Api` از `POST /IAM/Sample/FindAll` و مدل `PagingFilter` استفاده می‌کند.

| مورد | مقدار نمونه |
| --- | --- |
| IAM Application | `samples-ui` |
| Backend و Gateway Cluster ID | `samples-api` |
| Gateway Route ID | `samples-find-all` |
| Stable Operation Key | `samples.find-all` |
| IAM Permission Code | `samples.read` |
| Business API | `POST /IAM/Sample/FindAll` |
| مسیر صفحهٔ فرانت | `/samples` |
| Audience توکن API | `samples-api` |

## ۱. پروژه‌ها را اجرا کن و قرارداد API را چک کن

1. Docker Desktop و SQL Server محلی را اجرا کن. اگر سیستم تازه است، اول [راهنمای راه‌اندازی](run-gateway-iam-on-another-pc.md) را اجرا کن.
2. از Visual Studio با پروفایل **SampleGateway Local HTTP** و F5 اجرا کن، یا با PowerShell دستور زیر را اجرا کن. هر دو مسیر روی یک پورت هستند، پس یکی را انتخاب کن.

   ```powershell
   pwsh -NoProfile -File .\Start-LocalGateway.ps1 -Http
   ```

3. Gateway روی `http://localhost:17465/aneiang` و IAM Admin روی `http://localhost:17464/` در دسترس‌اند. با `gateway-local-admin` به Gateway و با `iam-test-admin` به IAM Admin وارد شو.
4. پروژه‌ای که واقعاً `FindAll` را پیاده کرده روی پورت جداگانه اجرا کن. Swagger آن را باز کن و **متد، مسیر، بدنهٔ صفحه‌بندی و ساختار پاسخ** را بردار. یک بار همان درخواست را مستقیم به سرویس بزن تا مستقل از Gateway کار کند. اگر اکشن داخل `IAM.Api` است، میزبان سبک Authorization روی `17463` فقط Controllerهای IAM Core را اجرا می‌کند. برای اکشن نمونه باید میزبان کامل `IAM.Api` را با تنظیمات سرویس و دیتابیس توسعه روی پورت دیگری اجرا کنی.

## ۲. Route را در Gateway بساز

1. در **Clusters**، کلاستر `samples-api` را بساز و آدرس سرویس مرحلهٔ قبل را به‌عنوان Destination ثبت کن.
2. در **Routes**، Route با ID برابر `samples-find-all` بساز. کلاستر را انتخاب کن و در Match، مسیر دقیق `/IAM/Sample/FindAll` و فقط متد `POST` را قرار بده. مثال از همان مسیر در Gateway و سرویس استفاده می‌کند و Transform لازم ندارد.
3. بعد از ذخیره، درخواست بدون Policy منتشرشده باید بسته بماند. برای انتشار، مانیفست را از Gateway فعال بگیر. مسیرهای Catch-all و Transformهایی مثل `PathPattern` برای این قرارداد GatewayOnly قابل Bind نیستند.

## ۳. Application، Permission و کاربر را در IAM ثبت کن

1. در IAM Admin بخش **Directory** یک Application با کد `samples-ui` بساز و UUID آن را یادداشت کن. این UUID را در تمام مراحل بعدی استفاده کن.
2. در بخش **Permissions** یا Directory، در همان Application یک Permission با کد `samples.read` بساز و UUID آن را بردار.
3. کاربر واقعی فرانت را در Keycloak بساز یا حساب موجودش را انتخاب کن. در IAM یک User mapping با **issuer و subject** همان هویت ثبت کن. `sub` از توکن معتبر همان کاربر به دست می‌آید و با نام کاربری فرق دارد.
4. در **Grants**، مجوز `samples.read` را مستقیم یا از طریق Role همان Application به کاربر بده. Scope باید `Global` و Grant فعال و منقضی‌نشده باشد. برای آزمون منفی یکی از کاربران را بدون این Grant نگه دار. تخصیص‌ها باید روی Principal کاربر فرانت انجام شوند.

## ۴. OpenAPI را وارد کن و Operation را به Route وصل کن

1. در فایل تنظیمات فعال IAM، Origin و IP واقعی سرویس را در `BackendImport:AllowedOrigins` و `BackendImport:AllowedAddresses` قرار بده. برای سرویس HTTP محلی، میزبان IAM باید در Development باشد و `BackendImport:AllowDevelopmentHttpLoopback=true` تنظیم شود. اگر آدرس `localhost` است، IPهای loopback که DNS برمی‌گرداند را در allowlist حساب کن. پس از تغییر config میزبان IAM را دوباره اجرا کن.
2. در IAM Admin → **Operations**، Backend را با Application مرحلهٔ قبل، کد `samples-api`، آدرس سرویس، مسیر JSON واقعی Swagger و `Gateway Cluster ID=samples-api` ثبت کن. Discover را بزن، عملیات `POST` را پیدا کن و Candidate را با کلید ثابت `samples.find-all` تأیید کن.
3. اپراتور باید مانیفست **همان Gateway اجراشده** را از `GET /internal/v1/iam/route-manifest` بگیرد. این مسیر توکن Access Token جدا با Audience مانیفست، `sub` مجاز در `ManifestExportSubjects` و IP مجاز در `ManifestExportRemoteAddresses` می‌خواهد. پروفایل محلی فعلی این هویت صادرکنندهٔ مانیفست را به‌صورت پیش‌فرض آماده نمی‌کند. ابتدا یک Service Client مخصوص با Audience Mapper در Keycloak بساز و تنظیمات یادشده را روی Gateway فعال کن.

   ```powershell
   # $manifestToken را از جریان Client Credentials کلاینت مخصوص مانیفست بگیر.
   $manifestPath = Join-Path $PWD 'route-manifest.json'
   Invoke-WebRequest 'http://localhost:17465/internal/v1/iam/route-manifest' `
       -AllowUnencryptedAuthentication -Headers @{ Authorization = "Bearer $manifestToken" } `
       -OutFile $manifestPath
   $manifestHash = (Get-FileHash $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
   ```

4. فایل اصلی را بدون تغییر بایت‌ها در مسیر محافظت‌شده نگه دار. در پیکربندی فعال IAM، `TrustedRouteManifest:ExportPath` و `TrustedRouteManifest:Sha256` را تنظیم کن. پس از بررسی منشأ و محتوای خروجی، `TrustedRouteManifest:ProvenanceVerified` را فعال کن. همچنین `PolicyPublishing:GatewayOnlyOperationKeys:samples-api:0=samples.find-all` را تنظیم کن و IAM را دوباره اجرا کن.
5. در فرم **Bind** همان Operation، مقدار `samples-find-all`، فیلد `fingerprint` همان Route در مانیفست و SHA-256 فایل را وارد کن. اگر هم‌زمان کسی Operation را تغییر داد، صفحه را دوباره باز کن تا RowVersion جدید را بگیری.

## ۵. Policy را منتشر کن و API را مستقل از فرانت تست کن

در IAM Admin → **Policy** برای `samples.find-all` این مقادیر را ثبت کن:

| فیلد | مقدار نمونه |
| --- | --- |
| Auth Mode | `Permission` |
| Enforcement Mode | `GatewayOnly` |
| Allowed Principal Kinds | `User` |
| Required Audience | `samples-api` |
| Required Permissions | UUID مربوط به `samples.read` |
| Requirement Mode | `All` |
| Required OAuth Scopes | فقط Scopeهایی که واقعاً در Keycloak تنظیم و صادر شده‌اند |

**Validate** و سپس **Publish** را بزن. Revision و Hash را ثبت کن و اجازه بده Gateway Bundle را در چرخهٔ Refresh دریافت کند. در Keycloak، Client فرانت باید از Authorization Code + PKCE استفاده کند و توکن کاربر باید Audience `samples-api` داشته باشد. با همان توکن و بدنهٔ واقعی Swagger، درخواست `POST http://localhost:17465/IAM/Sample/FindAll` را آزمون کن. برای درخواست مجاز، ساختار پاسخ و داده‌های صفحه‌بندی باید با Swagger بخواند.

## ۶. منو و صفحه را در فرانت وصل کن

1. در IAM Admin → **Navigation** همان Application را انتخاب کن و یک گره `Menu` فعال بساز. نمونهٔ مقادیر:

   | فیلد | مقدار |
   | --- | --- |
   | Key | `samples.list` |
   | TitleFa | فهرست نمونه‌ها |
   | TitleEn | Samples |
   | Url | `/samples` |
   | PermissionId | UUID مربوط به `samples.read` |
   | SortOrder | `10` |

2. فرانت یا BFF، بعد از ورود کاربر، فهرست گره‌های قابل‌نمایش را از `GET /api/v1/me/navigation?applicationId=<samples-ui-uuid>` در IAM بگیرد. این مسیر باید **توکن خود کاربر با Audience قابل‌قبول برای Bearer میزبان IAM** را بگیرد. در محیط نمونه Audience این میزبان `iam-admin` است. اگر از BFF استفاده می‌کنی، فراخوانی IAM را سروری انجام بده. برای درخواست مستقیم مرورگر از Origin جدا، CORS را فقط برای Originهای لازم پیکربندی کن. پیکربندی جداگانهٔ Audience برای سرویس خواندن Navigation در محیط عملیاتی را بر اساس قرارداد همان میزبان انجام بده.

   اگر میزبان سبک IAM را قبلاً ساخته‌ای و `/api/v1/me/navigation` پاسخ 404 می‌دهد، میزبان محلی را متوقف کن و [Initializer را دوباره اجرا کن](run-gateway-iam-on-another-pc.md) تا نسخه‌ای که `MeController` را ثبت می‌کند ساخته شود. یک 404 از میزبان سبک برای خود `FindAll` هم یعنی باید درخواست را به میزبان واقعی سرویس مرحلهٔ ۱ بفرستی.
3. گره‌ها را بر اساس `parentId` گروه‌بندی و بر اساس `sortOrder` مرتب کن. برای `Menu` از `url` به‌عنوان مسیر Router استفاده کن. در صفحهٔ `/samples`، درخواست `POST /IAM/Sample/FindAll` را با توکن Access Token مربوط به Business API، پارامترهای صفحه‌بندی و مدل واقعی Swagger به Gateway بفرست. منو صرفاً نمایش UI است و Gateway مجوز API را مستقلاً بررسی می‌کند.
4. برای ساخت جدول، Loading، Empty، خطا و فیلترها را به قرارداد واقعی پاسخ وصل کن. اگر سرویس به‌جای GET، POST می‌خواهد، متد فرانت، Route و عملیات منتشرشده باید همگی POST بمانند.

## ۷. آزمون نهایی

| آزمون | انتظار |
| --- | --- |
| کاربر دارای `samples.read` با Grant معتبر Global | منو ظاهر می‌شود و درخواست مجاز موفق است |
| کاربر فعال بدون Grant یا فقط با Grant از نوع System | منو نمایش داده نمی‌شود و درخواست مستقیم به API رد می‌شود |
| توکن منقضی یا بدون توکن برای عملیات محافظت‌شده | Gateway درخواست را رد می‌کند |
| Bundle موجود با Route یا Fingerprint متفاوت | عملیاتی که Bind معتبر ندارد Forward نمی‌شود |
| Bundle منتشر نشده یا Lease منقضی | Gateway Fail-Closed می‌ماند |
| کلیک روی منو | Router به `/samples` می‌رود و جدول از Gateway داده می‌گیرد |

بعد از تغییر Grant، برای تست مجدد نتیجهٔ Cache معتبر Gateway را در نظر بگیر که حداکثر ۱۲۰ ثانیه است. بعد از تغییر Route، مانیفست را دوباره export کن و Policy سازگار منتشر کن. این راهنما گردش کار را مستند می‌کند. اجرای کامل روی Endpoint و فرانت واقعی باید با مسیرها، توکن‌ها و داده‌های همان پروژه انجام شود.
