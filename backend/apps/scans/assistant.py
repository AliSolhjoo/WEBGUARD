"""Deterministic, offline security guidance grounded in stored WEBGUARD findings.

This is intentionally not marketed as a generative AI model. It provides consistent,
explainable remediation guidance with no external API, data exfiltration, or model key.
"""

from datetime import datetime, timezone


GUIDANCE = {
    "WG-HTTP-001": {
        "priority": "P1",
        "impact": "Traffic may be exposed to interception or downgrade-related risks when a trusted HTTPS endpoint is unavailable.",
        "steps": [
            "Install or renew a certificate from a publicly trusted certificate authority.",
            "Configure the complete intermediate certificate chain on the web server or load balancer.",
            "Verify the certificate hostname and validity from an independent client.",
            "Retest HTTPS before enabling HSTS for the domain.",
        ],
        "validation": "A fresh TLS handshake succeeds and the certificate chain and hostname validate without warnings.",
    },
    "WG-HTTP-002": {
        "priority": "P2",
        "impact": "Visitors using plain HTTP may remain on an unencrypted endpoint rather than being redirected to the verified HTTPS origin.",
        "steps": [
            "Configure the web server or edge proxy to redirect HTTP requests to the same hostname over HTTPS.",
            "Use a permanent 301 or 308 redirect after confirming application compatibility.",
            "Preserve only the intended path and query parameters and avoid open redirects.",
            "Retest from an unauthenticated client over port 80.",
        ],
        "validation": "An HTTP request receives a same-host HTTPS redirect and the resulting HTTPS endpoint validates.",
    },
    "WG-HDR-001": {
        "priority": "P2",
        "impact": "Without a Content-Security-Policy, browsers have fewer restrictions on where scripts and other resources may load from.",
        "steps": [
            "Inventory legitimate script, style, image, font, and API origins used by the application.",
            "Start with Content-Security-Policy-Report-Only to measure compatibility.",
            "Define a restrictive default-src and explicit script-src, style-src, img-src, connect-src, and frame-ancestors directives.",
            "Remove unsafe-inline and unsafe-eval where feasible; use nonces or hashes for required inline scripts.",
        ],
        "validation": "The enforced CSP blocks an intentionally disallowed test resource without breaking legitimate application flows.",
    },
    "WG-HDR-002": {
        "priority": "P2",
        "impact": "Browsers are not instructed to consistently prefer HTTPS for future visits to the hostname.",
        "steps": [
            "Confirm HTTPS works on every relevant route and hostname before enabling HSTS.",
            "Set Strict-Transport-Security with a suitable max-age, commonly at least six months after validation.",
            "Add includeSubDomains only after all subdomains are confirmed HTTPS-ready.",
            "Consider preload only after reviewing the irreversible operational implications.",
        ],
        "validation": "A successful HTTPS response includes a valid Strict-Transport-Security header with a positive max-age.",
    },
    "WG-HDR-003": {
        "priority": "P3",
        "impact": "Some browsers may perform MIME sniffing when content types are ambiguous, increasing the chance of content being interpreted unexpectedly.",
        "steps": [
            "Set X-Content-Type-Options: nosniff on application responses.",
            "Ensure static assets have correct Content-Type values.",
            "Retest representative HTML, JavaScript, CSS, and download responses.",
        ],
        "validation": "The response contains exactly X-Content-Type-Options: nosniff.",
    },
    "WG-HDR-004": {
        "priority": "P3",
        "impact": "The browser may disclose more referrer information to destination sites than the application intends.",
        "steps": [
            "Set a privacy-conscious Referrer-Policy, such as strict-origin-when-cross-origin.",
            "Review application flows that intentionally rely on referrer details.",
            "Retest same-origin and cross-origin navigation behavior.",
        ],
        "validation": "The response includes the intended Referrer-Policy and cross-origin requests disclose no full path or query string.",
    },
    "WG-HDR-006": {
        "priority": "P2",
        "impact": "A page may be embedded in another site unless the browser receives a framing restriction, which can enable UI redress attacks.",
        "steps": [
            "Set CSP frame-ancestors to 'none' or an explicit allowlist appropriate for the product.",
            "For legacy compatibility, consider X-Frame-Options: DENY or SAMEORIGIN.",
            "Test legitimate embedding workflows before enforcing the policy.",
        ],
        "validation": "The response includes a restrictive frame-ancestors directive or a recognized X-Frame-Options value.",
    },
    "WG-TLS-001": {
        "priority": "P1",
        "impact": "An expired or soon-to-expire certificate can cause browser warnings, failed integrations, or service disruption.",
        "steps": [
            "Renew the certificate before its expiry date.",
            "Confirm the certificate covers the exact hostname and includes the full chain.",
            "Automate renewal and monitor expiry with a separate alerting mechanism.",
        ],
        "validation": "An external TLS client verifies the renewed certificate and reports an acceptable validity window.",
    },
    "WG-TLS-002": {
        "priority": "P1",
        "impact": "Obsolete TLS protocol versions may expose connections to known protocol weaknesses and compatibility risks.",
        "steps": [
            "Configure the server, reverse proxy, or load balancer to allow TLS 1.2 and TLS 1.3.",
            "Disable SSLv3, TLS 1.0, and TLS 1.1 where supported clients permit it.",
            "Review cipher suite policy using current platform guidance.",
        ],
        "validation": "Independent TLS inspection confirms the endpoint negotiates TLS 1.2 or TLS 1.3 and rejects obsolete versions.",
    },
    "WG-COOKIE-001": {
        "priority": "P2",
        "impact": "Cookies without appropriate flags may be exposed to client-side script access or sent in unintended request contexts.",
        "steps": [
            "Set Secure on cookies that must only travel over HTTPS.",
            "Set HttpOnly on session and other sensitive cookies unless script access is required.",
            "Choose SameSite=Lax or Strict where possible; SameSite=None must be paired with Secure.",
            "Review cookies on authenticated and state-changing routes, not only the public homepage.",
        ],
        "validation": "Set-Cookie responses for sensitive cookies contain the intended Secure, HttpOnly, and SameSite attributes.",
    },
    "WG-CONTENT-001": {
        "priority": "P2",
        "impact": "HTTP resources embedded in an HTTPS page can be modified in transit and may cause browser mixed-content blocking or warnings.",
        "steps": [
            "Replace insecure resource URLs with HTTPS URLs or same-origin relative paths.",
            "Update application templates, CMS content, and asset references.",
            "Use Content-Security-Policy upgrade-insecure-requests only as a migration aid after testing.",
            "Retest the rendered page and representative application routes.",
        ],
        "validation": "A fresh homepage sample contains no insecure HTTP resource references and browser mixed-content warnings are absent.",
    },
    "WG-DNS-001": {
        "priority": "P3",
        "impact": "The domain may lack a published sender policy that helps receiving mail systems identify authorized outbound mail sources.",
        "steps": [
            "Inventory all legitimate services that send mail for the domain.",
            "Publish one SPF TXT policy at the domain apex.",
            "Avoid multiple SPF records and review DNS lookup limits before adding includes.",
            "Use an intentional -all or ~all qualifier after validating all senders.",
        ],
        "validation": "A public DNS query returns one valid SPF record that matches the domain's actual sending services.",
    },
    "WG-DNS-002": {
        "priority": "P3",
        "impact": "Without DMARC, the domain has limited policy-based protection and reporting against email domain impersonation.",
        "steps": [
            "Publish a DMARC TXT record at _dmarc.<domain>.",
            "Begin with p=none and configure an aggregate report mailbox.",
            "Review SPF/DKIM alignment and report data before moving to quarantine or reject.",
        ],
        "validation": "A public DNS query returns a valid DMARC record and the policy reflects the organization's enforcement stage.",
    },
    "WG-HDR-005": {
        "priority": "P3",
        "impact": "Browser capabilities such as camera, microphone, or location may remain available to contexts that do not need them.",
        "steps": [
            "Inventory browser capabilities required by the application and any trusted embeds.",
            "Set a restrictive Permissions-Policy allowlist for each required capability.",
            "Retest legitimate application workflows in supported browsers.",
        ],
        "validation": "The response includes an intentional Permissions-Policy and disallowed capabilities are denied by the browser.",
    },
    "WG-HDR-007": {
        "priority": "P2",
        "impact": "unsafe-inline or unsafe-eval in CSP can weaken script execution restrictions.",
        "steps": [
            "Inventory inline scripts and eval-dependent behavior that the application actually requires.",
            "Use nonces or hashes for required inline scripts.",
            "Remove unsafe-inline and unsafe-eval from script-src and monitor CSP violations.",
        ],
        "validation": "The enforced CSP has no unsafe script directives while required application scripts continue to work.",
    },
    "WG-DNS-003": {
        "priority": "P2",
        "impact": "A permissive SPF all qualifier or duplicate SPF policies can weaken sender authorization checks.",
        "steps": [
            "Inventory and validate all legitimate outbound mail services.",
            "Publish a single SPF record at the domain apex.",
            "Use an intentional -all or ~all qualifier after validating every sender.",
        ],
        "validation": "Public DNS returns exactly one valid SPF record with the intended terminal qualifier.",
    },
    "WG-DNS-004": {
        "priority": "P2",
        "impact": "A DMARC p=none policy monitors alignment but does not ask receivers to quarantine or reject failing messages.",
        "steps": [
            "Review DMARC aggregate reports to identify legitimate senders.",
            "Fix SPF and DKIM alignment issues before enforcement.",
            "Move to quarantine or reject after confirming operational readiness.",
        ],
        "validation": "The DMARC policy reaches the intended enforcement level and legitimate mail continues to pass alignment checks.",
    },
    "WG-DNS-005": {
        "priority": "P3",
        "impact": "Without CAA records, DNS does not publish a policy restricting which certificate authorities may issue certificates for the domain.",
        "steps": [
            "Identify the certificate authorities used by the organization.",
            "Publish CAA records that match the intended issuance workflow.",
            "Test certificate issuance and renewal after the DNS change.",
        ],
        "validation": "Public DNS returns the intended CAA policy and authorized certificate issuance continues to work.",
    },
    "WG-CONTENT-002": {
        "priority": "P3",
        "impact": "Public technology version metadata or source-map references can provide unnecessary details about the application's stack.",
        "steps": [
            "Review public response headers and HTML for unnecessary product version disclosure.",
            "Publish source maps only when required and with access controls appropriate to the product.",
            "Remove unnecessary version headers, while keeping software patching as the primary security control.",
        ],
        "validation": "A fresh public response no longer exposes unnecessary version metadata or unintended source-map references.",
    },
}


GUIDANCE_FA = {
    "WG-HTTP-001": {
        "impact": "در دسترس نبودن HTTPS معتبر می‌تواند ارتباط کاربران را در معرض شنود یا تنزل پروتکل قرار دهد.",
        "steps": [
            "گواهی معتبر را از مرجع صدور مورد اعتماد نصب یا تمدید کنید.",
            "کامل بودن زنجیره گواهی و گواهی‌های میانی را روی وب‌سرور یا Load Balancer بررسی کنید.",
            "نام دامنه و بازه اعتبار گواهی را با یک کلاینت مستقل اعتبارسنجی کنید.",
            "پیش از فعال‌سازی HSTS، اتصال HTTPS را دوباره آزمایش کنید.",
        ],
        "validation": "Handshake جدید TLS موفق باشد و نام میزبان و زنجیره گواهی بدون هشدار تأیید شوند.",
    },
    "WG-HTTP-002": {
        "impact": "کاربران HTTP ممکن است به‌جای انتقال به HTTPS معتبر، روی نقطه پایانی رمزنگاری‌نشده باقی بمانند.",
        "steps": [
            "روی وب‌سرور یا پراکسی لبه، انتقال HTTP به HTTPS را برای همان میزبان تنظیم کنید.",
            "پس از بررسی سازگاری برنامه از Redirect دائمی 301 یا 308 استفاده کنید.",
            "فقط مسیر و پارامترهای موردنیاز را حفظ کنید و از Open Redirect جلوگیری کنید.",
            "رفتار را با یک درخواست بدون احراز هویت روی پورت 80 دوباره بررسی کنید.",
        ],
        "validation": "درخواست HTTP به HTTPS همان میزبان منتقل شود و مقصد HTTPS معتبر باشد.",
    },
    "WG-HDR-001": {
        "impact": "نبود CSP محدودیت مرورگر را برای منابعی که می‌توانند اسکریپت یا محتوای صفحه را بارگذاری کنند کاهش می‌دهد.",
        "steps": [
            "مبدأهای واقعی اسکریپت، Style، تصویر، فونت و API را فهرست کنید.",
            "ابتدا CSP را در حالت Report-Only فعال کنید تا ناسازگاری‌ها شناسایی شوند.",
            "دستورهای default-src، script-src، style-src، img-src، connect-src و frame-ancestors را متناسب با برنامه تعریف کنید.",
            "در صورت امکان unsafe-inline و unsafe-eval را حذف و از Nonce یا Hash استفاده کنید.",
        ],
        "validation": "CSP اعمال‌شده یک منبع آزمایشی غیرمجاز را مسدود کند و جریان‌های معتبر برنامه همچنان کار کنند.",
    },
    "WG-HDR-002": {
        "impact": "مرورگر برای مراجعه‌های بعدی به میزبان، الزام ماندن روی HTTPS را دریافت نمی‌کند.",
        "steps": [
            "پیش از فعال کردن HSTS، HTTPS را روی تمام مسیرها و زیردامنه‌های مرتبط تأیید کنید.",
            "پس از اطمینان از سازگاری، Strict-Transport-Security با max-age مناسب تنظیم کنید.",
            "includeSubDomains را فقط وقتی اضافه کنید که همه زیردامنه‌ها HTTPS آماده باشند.",
            "پیش از استفاده از preload پیامدهای عملیاتی آن را بررسی کنید.",
        ],
        "validation": "پاسخ HTTPS شامل HSTS معتبر با max-age مثبت باشد.",
    },
    "WG-HDR-003": {
        "impact": "در صورت مبهم بودن Content-Type، برخی مرورگرها ممکن است نوع محتوا را حدس بزنند و آن را ناخواسته تفسیر کنند.",
        "steps": [
            "هدر X-Content-Type-Options: nosniff را روی پاسخ‌های برنامه تنظیم کنید.",
            "برای فایل‌های ایستا Content-Type صحیح ارسال کنید.",
            "پاسخ‌های نمونه HTML، JavaScript، CSS و فایل‌های دانلودی را دوباره بررسی کنید.",
        ],
        "validation": "پاسخ دقیقاً شامل X-Content-Type-Options: nosniff باشد.",
    },
    "WG-HDR-004": {
        "impact": "ممکن است مرورگر جزئیات بیشتری از Referrer را به وب‌سایت مقصد ارسال کند.",
        "steps": [
            "سیاستی مانند strict-origin-when-cross-origin را تنظیم کنید.",
            "جریان‌هایی را که واقعاً به اطلاعات Referrer نیاز دارند بازبینی کنید.",
            "رفتار پیمایش هم‌مبدأ و میان‌مبدأ را دوباره آزمایش کنید.",
        ],
        "validation": "سیاست موردنظر در پاسخ وجود داشته باشد و در درخواست میان‌مبدأ مسیر و Query کامل افشا نشود.",
    },
    "WG-HDR-006": {
        "impact": "در صورت نبود محدودیت Frame، امکان قراردادن صفحه در سایت دیگر وجود دارد و خطر فریب رابط کاربری افزایش می‌یابد.",
        "steps": [
            "دستور CSP frame-ancestors را روی none یا فهرست مجاز محدود تنظیم کنید.",
            "برای سازگاری قدیمی، X-Frame-Options با مقدار DENY یا SAMEORIGIN را بررسی کنید.",
            "پیش از اعمال محدودیت، جریان‌های Embed مجاز را آزمایش کنید.",
        ],
        "validation": "پاسخ شامل frame-ancestors محدودکننده یا مقدار شناخته‌شده X-Frame-Options باشد.",
    },
    "WG-TLS-001": {
        "impact": "گواهی منقضی یا نزدیک به انقضا می‌تواند هشدار مرورگر، اختلال اتصال یا قطعی سرویس ایجاد کند.",
        "steps": [
            "گواهی را پیش از تاریخ انقضا تمدید کنید.",
            "پوشش نام میزبان و کامل بودن زنجیره گواهی را بررسی کنید.",
            "تمدید خودکار و هشدار مستقل انقضا راه‌اندازی کنید.",
        ],
        "validation": "کلاینت TLS مستقل گواهی جدید را با بازه اعتبار قابل قبول تأیید کند.",
    },
    "WG-TLS-002": {
        "impact": "نسخه‌های قدیمی TLS می‌توانند اتصال را در معرض ضعف‌های شناخته‌شده پروتکل قرار دهند.",
        "steps": [
            "روی سرور، پراکسی یا Load Balancer نسخه‌های TLS 1.2 و TLS 1.3 را مجاز کنید.",
            "در صورت سازگاری کلاینت‌ها SSLv3 و TLS 1.0 و TLS 1.1 را غیرفعال کنید.",
            "سیاست Cipher Suite را با راهنمای به‌روز پلتفرم تطبیق دهید.",
        ],
        "validation": "ابزار مستقل TLS مذاکره TLS 1.2 یا TLS 1.3 را تأیید و نسخه‌های منسوخ را رد کند.",
    },
    "WG-COOKIE-001": {
        "impact": "Cookieهای حساس بدون پرچم مناسب ممکن است در دسترس اسکریپت سمت کاربر قرار گیرند یا در زمینه ناخواسته ارسال شوند.",
        "steps": [
            "برای Cookieهایی که فقط باید روی HTTPS ارسال شوند Secure را فعال کنید.",
            "برای نشست و داده حساس HttpOnly را فعال کنید، مگر اینکه دسترسی اسکریپت الزام واقعی داشته باشد.",
            "در صورت امکان SameSite=Lax یا Strict انتخاب کنید؛ مقدار None باید همراه Secure باشد.",
            "Cookieهای مسیرهای احراز هویت و عملیات حساس را هم بررسی کنید، نه فقط صفحه اصلی را.",
        ],
        "validation": "پاسخ‌های Set-Cookie برای داده حساس، پرچم‌های Secure و HttpOnly و SameSite موردنیاز را داشته باشند.",
    },
    "WG-CONTENT-001": {
        "impact": "منابع HTTP در صفحه HTTPS می‌توانند در مسیر انتقال دست‌کاری شوند یا موجب هشدار و مسدودسازی Mixed Content شوند.",
        "steps": [
            "نشانی منابع ناامن را با HTTPS یا مسیر نسبی هم‌مبدأ جایگزین کنید.",
            "قالب‌های برنامه، محتوای CMS و نشانی فایل‌های ایستا را به‌روزرسانی کنید.",
            "پس از آزمایش، از upgrade-insecure-requests فقط به‌عنوان کمک مهاجرت استفاده کنید.",
            "صفحه رندرشده و مسیرهای نمونه را دوباره بررسی کنید.",
        ],
        "validation": "نمونه تازه صفحه هیچ منبع HTTP ناامنی نداشته باشد و هشدار Mixed Content در مرورگر مشاهده نشود.",
    },
    "WG-CONTENT-002": {
        "impact": "افشای نسخه فناوری یا ارجاع به Source Map عمومی می‌تواند اطلاعات کمکی درباره ساختار فناوری برنامه فراهم کند.",
        "steps": [
            "هدرها و فایل‌های عمومی را از نظر افشای غیرضروری نسخه بازبینی کنید.",
            "در محیط Production، Source Mapها را فقط در صورت نیاز و با کنترل دسترسی مناسب منتشر کنید.",
            "اطلاعات نسخه را از Headerهای غیرضروری حذف کنید؛ این کار جایگزین به‌روزرسانی امنیتی نیست.",
        ],
        "validation": "پاسخ عمومی پس از انتشار مجدد، فراداده غیرضروری و Source Mapهای ناخواسته را افشا نکند.",
    },
    "WG-DNS-001": {
        "impact": "نبود سیاست SPF می‌تواند تشخیص سرورهای مجاز ارسال ایمیل از دامنه را برای دریافت‌کننده دشوار کند.",
        "steps": [
            "تمام سرویس‌های مجاز ارسال ایمیل با دامنه را شناسایی کنید.",
            "یک رکورد SPF در TXT دامنه اصلی منتشر کنید.",
            "از چند رکورد SPF هم‌زمان اجتناب و محدودیت DNS Lookup را بررسی کنید.",
            "پس از اعتبارسنجی فرستنده‌ها، Qualifier مناسب مانند -all یا ~all را انتخاب کنید.",
        ],
        "validation": "DNS عمومی یک رکورد SPF معتبر و منطبق با سرویس‌های واقعی ارسال ایمیل برگرداند.",
    },
    "WG-DNS-002": {
        "impact": "بدون DMARC، دامنه از سیاست و گزارش‌دهی لازم برای مقابله با جعل هویت ایمیلی کمتر بهره می‌برد.",
        "steps": [
            "رکورد TXT در _dmarc دامنه منتشر کنید.",
            "با p=none شروع و صندوق دریافت گزارش Aggregate را تنظیم کنید.",
            "هم‌ترازی SPF و DKIM و گزارش‌ها را بررسی کنید و سپس سیاست را به quarantine یا reject ارتقا دهید.",
        ],
        "validation": "DNS عمومی رکورد DMARC معتبر با سیاست متناسب با مرحله اجرایی سازمان برگرداند.",
    },
    "WG-HDR-005": {
        "impact": "قابلیت‌های مرورگر مانند دوربین، میکروفون یا موقعیت مکانی ممکن است بدون نیاز برنامه در دسترس باشند.",
        "steps": [
            "قابلیت‌های واقعاً موردنیاز برنامه و سرویس‌های ثالث را شناسایی کنید.",
            "Permissions-Policy را با allowlist حداقلی برای هر قابلیت تنظیم کنید.",
            "جریان‌های مجاز برنامه را در مرورگرهای پشتیبانی‌شده دوباره آزمایش کنید.",
        ],
        "validation": "پاسخ شامل Permissions-Policy متناسب با قابلیت‌های موردنیاز باشد و قابلیت‌های غیرمجاز رد شوند.",
    },
    "WG-HDR-007": {
        "impact": "دستورهای unsafe-inline یا unsafe-eval در CSP می‌توانند محدودیت اجرای اسکریپت را تضعیف کنند.",
        "steps": [
            "وابستگی‌های واقعی اسکریپت‌های درون‌خطی و eval را شناسایی کنید.",
            "برای اسکریپت‌های درون‌خطی از Nonce یا Hash استفاده کنید.",
            "unsafe-inline و unsafe-eval را از script-src حذف کنید و خطاهای CSP را بررسی کنید.",
        ],
        "validation": "CSP بدون دستورهای ناامن اعمال شود و اسکریپت‌های موردنیاز برنامه همچنان به‌درستی کار کنند.",
    },
    "WG-DNS-003": {
        "impact": "سیاست SPF بیش از حد permissive یا چند رکورد SPF می‌تواند اعتبارسنجی فرستنده ایمیل را تضعیف کند.",
        "steps": [
            "تمام فرستنده‌های مجاز ایمیل را فهرست و تأیید کنید.",
            "فقط یک رکورد SPF در دامنه منتشر کنید.",
            "پس از بررسی همه فرستنده‌ها، از Qualifier آگاهانه مانند -all یا ~all استفاده کنید.",
        ],
        "validation": "فقط یک رکورد SPF معتبر با سیاست پایانی موردنظر در DNS مشاهده شود.",
    },
    "WG-DNS-004": {
        "impact": "سیاست DMARC با p=none پیام‌های مشکوک را قرنطینه یا رد نمی‌کند و فقط برای پایش مناسب است.",
        "steps": [
            "گزارش‌های DMARC را برای شناسایی فرستنده‌های معتبر تحلیل کنید.",
            "هم‌ترازی SPF و DKIM را بررسی و اشکالات ارسال را اصلاح کنید.",
            "در صورت آمادگی عملیاتی، سیاست را به quarantine یا reject ارتقا دهید.",
        ],
        "validation": "رکورد DMARC یک سیاست اعمالی مورد تأیید سازمان داشته باشد و ارسال‌کنندگان معتبر با موفقیت عبور کنند.",
    },
    "WG-DNS-005": {
        "impact": "نبود CAA به مراجع صدور گواهی محدودیت DNS مشخصی درباره صدور گواهی برای دامنه ارائه نمی‌دهد.",
        "steps": [
            "مراجع صدور گواهی مورد استفاده سازمان را شناسایی کنید.",
            "رکورد CAA را مطابق راهنمای DNS و نیاز صدور گواهی منتشر کنید.",
            "فرایند تمدید و صدور گواهی را پس از اعمال تغییر آزمایش کنید.",
        ],
        "validation": "DNS عمومی رکورد CAA موردنظر را برگرداند و صدور گواهی مجاز همچنان کار کند.",
    },
}

FA_TRANSLATIONS = {
    "summary": "راهنمای اصلاح بر اساس یافته ثبت‌شده در WEBGUARD تولید شده است. ابتدا شواهد را با تنظیمات واقعی سرویس تطبیق دهید.",
    "disclaimer": "این راهنما مبتنی بر قواعد و شواهد ذخیره‌شده است؛ تحلیل مدل زبانی یا اثبات بهره‌پذیری نیست. تغییرات را ابتدا در محیط آزمایشی بررسی کنید.",
}


def analyze_finding(finding, language="en"):
    check = finding.check_result
    guidance = GUIDANCE.get(check.check_id)
    if guidance is None:
        guidance = {
            "priority": "P3" if check.severity in {"low", "informational"} else "P2",
            "impact": "The assessment recorded a configuration observation that should be reviewed in the context of the application architecture.",
            "steps": [
                "Review the technical evidence and confirm that the observation applies to this hostname and response.",
                "Compare the observed configuration with the organization's security baseline.",
                "Apply the least disruptive corrective configuration and document any accepted risk.",
            ],
            "validation": "Run a new WEBGUARD assessment and independently verify the relevant configuration.",
        }
    is_fa = language == "fa"
    if is_fa and check.check_id in GUIDANCE_FA:
        guidance = {**guidance, **GUIDANCE_FA[check.check_id]}
    elif is_fa:
        guidance = {
            **guidance,
            "impact": "این یافته یک مشاهده پیکربندی است و باید با معماری و نیاز واقعی برنامه تطبیق داده شود.",
            "steps": [
                "شواهد فنی را بررسی و ارتباط آن را با دامنه و پاسخ فعلی تأیید کنید.",
                "پیکربندی مشاهده‌شده را با خط‌مشی امنیتی سازمان مقایسه کنید.",
                "کم‌تغییرترین راهکار اصلاح را اعمال و هر ریسک پذیرفته‌شده را مستند کنید.",
            ],
            "validation": "یک ارزیابی تازه WEBGUARD اجرا و تنظیم مربوطه را به‌صورت مستقل اعتبارسنجی کنید.",
        }
    # Technical identifiers remain unchanged so the advice can be mapped to server settings and standards.
    return {
        "engine": "WEBGUARD Deterministic Security Advisor",
        "mode": "offline-rule-based",
        "language": "fa" if is_fa else "en",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_id": finding.pk,
        "check_id": check.check_id,
        "asset_domain": check.scan.asset.domain,
        "title": check.name,
        "severity": check.severity,
        "priority": guidance["priority"],
        "status": finding.status,
        "summary": FA_TRANSLATIONS["summary"] if is_fa else "A remediation plan was generated from the saved WEBGUARD evidence. Validate the observation against the live application before changing production configuration.",
        "business_impact": guidance["impact"],
        "remediation_steps": guidance["steps"],
        "validation_criteria": guidance["validation"],
        "evidence": check.evidence,
        "limitations": FA_TRANSLATIONS["disclaimer"] if is_fa else "This is deterministic, rule-based guidance grounded in the stored check result. It is not an LLM analysis or proof of exploitability. Validate changes in a test environment first.",
    }
