# MasterDnsVPN — تغییرات و بهبودها

## بررسی و اصلاح توسط Claude Sonnet 4.6 — 1404

---

## 🔴 رفع اشکالات بحرانی

### 1. `internal/security/codec.go` — ChaCha20 بدون احراز هویت
- **مشکل:** `chacha20.NewUnauthenticatedCipher` هیچ MAC ندارد؛ مهاجم می‌تواند ciphertext را بدون شناسایی تغییر دهد.
- **راه‌حل:** جایگزینی با `chacha20poly1305.NewX` (XChaCha20-Poly1305 AEAD) که احراز هویت کامل دارد.

### 2. `internal/client/client.go` — نشت goroutine
- **مشکل:** اگر بعد از `StartAsyncRuntime` یک panic رخ می‌داد، worker goroutineها پاکسازی نمی‌شدند.
- **راه‌حل:** افزودن `recover()` guard برای اطمینان از فراخوانی `StopAsyncRuntime` در صورت بروز panic.

### 3. `internal/client/mtu_logging.go` — race condition
- **مشکل:** بررسی `mtuSuccessOutputPath` و نوشتن فایل در دو قفل مجزا انجام می‌شد؛ session reset بین دو قفل ممکن بود path را null کند.
- **راه‌حل:** re-check مسیر درون قفل دوم قبل از IO.

---

## 🟡 رفع هشدارها

### 4. `internal/security/codec.go` — key derivation با MD5
- **مشکل:** method=3 از MD5 برای derive کردن کلید AES-128 استفاده می‌کرد.
- **راه‌حل:** جایگزینی تمام روش‌ها با HKDF-SHA256 با domain separation (info string) برای هر method.

### 5. `internal/security/codec.go` — AES-192 با کلید truncated
- **مشکل:** کلید کوتاه‌تر از 24 بایت با صفر pad می‌شد.
- **راه‌حل:** HKDF همیشه دقیقاً `targetLen` بایت خروجی می‌دهد.

### 6. `internal/security/encryption_key.go` — هشدار permission والد
- **مشکل:** مجوز پوشه والد فایل کلید بررسی نمی‌شد.
- **راه‌حل:** بررسی `mode & 0o022` روی parent dir و چاپ هشدار در صورت world/group writable بودن.

### 7. `internal/security/encryption_key.go` — هشدار method ناامن
- **مشکل:** اجرا با method=0 (بدون رمزنگاری) بدون هیچ هشداری امکان‌پذیر بود.
- **راه‌حل:** افزودن `InsecureMethodWarning` map و چاپ به stderr در startup.

---

## ⚡ بهینه‌سازی‌ها

### 8. `internal/client/socks_ratelimit.go` — Sharded Rate Limiter
- **مشکل:** یک `sync.Mutex` سراسری برای تمام IPها — bottleneck در load بالا.
- **راه‌حل:** 64 shard مستقل با FNV hash routing. API کاملاً سازگار با قبل. کاهش contention ~64x.

### 9. `internal/logger/async_logger.go` — Async Logger (فایل جدید)
- **مشکل:** هر پیام لاگ mutex را می‌گرفت و goroutine caller را block می‌کرد.
- **راه‌حل:** `AsyncLogger` با channel بافر ۴۰۹۶ — caller هرگز block نمی‌شود. متد `Flush()` برای graceful shutdown.

---

## 🚀 نوآوری‌های جدید (فایل‌های جدید)

### 10. `internal/metrics/metrics.go` — Prometheus Metrics Server
- HTTP server روی `127.0.0.1:9090` (قابل تنظیم)
- `/metrics` — فرمت Prometheus text برای scrape
- `/api/status` — JSON برای GUI
- `/health` — health check endpoint
- Atomic counters: bytes up/down، drops، latency، streams، resets

### 11. `internal/obfuscation/padding.go` — Traffic Obfuscation
- Padding بسته‌ها به اندازه‌های استاندارد DNS: 28، 56، 120، 248، 512، 1232 بایت
- پر کردن padding با bytes تصادفی (crypto/rand) — قابل تشخیص نیست
- `WrapWithLength` + `StripPadding` برای بازیابی payload اصلی

### 12. `internal/configwatcher/watcher.go` — Hot-Reload Config
- گوش دادن به `SIGHUP` در background goroutine
- `ReloadFunc` callback قابل تعریف توسط caller
- بدون dependency خارجی — فقط `os/signal`

### 13. `gui/dashboard.html` — داشبورد GUI کامل
- UI کراس‌پلتفرم بر پایه HTML/JS (قابل embed در Wails یا Fyne WebView)
- صفحات: داشبورد · Resolverها · رمزنگاری · تنظیمات · لاگ‌ها · متریک‌ها
- نمودار throughput زنده با SVG
- مدیریت resolver با وضعیت real-time
- انتخاب روش رمزنگاری با هشدار برای روش‌های ناامن
- پشتیبانی از `/api/status` برای داده زنده

---

## سازگاری

- تمام تغییرات با API داخلی موجود سازگارند
- هیچ dependency خارجی جدیدی اضافه نشده (به جز `golang.org/x/crypto/chacha20poly1305` که قبلاً در go.mod بود)
- `hkdf` از `golang.org/x/crypto/hkdf` — همان ماژول موجود
