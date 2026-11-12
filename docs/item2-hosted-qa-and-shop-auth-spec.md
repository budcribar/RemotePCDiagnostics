# Item 2 Implementation Spec: Hosted QR Verification (`GET /r/{id}`) + Multi-Tenant Shop Auth & Branding in `RemoteBlazorWebView`

> **Target Repository:** `https://github.com/budcribar/RemoteBlazorWebView`  
> **Target Branch:** `net10` (`git fetch origin && git checkout net10 && git pull --rebase origin net10`)  
> **Cross-Repo Boundary:** Do **NOT** edit files in `budcribar/RemotePCDiagnostics` while another agent is implementing Item 1 on `RemotePCDiagnostics` `main`. Everything in this spec lives in `budcribar/RemoteBlazorWebView`.

---

## 1. Goal & Scope

Add multi-tenant repair-shop / laptop-refurbisher SaaS capabilities directly into `RemoteWebViewService` (`budcribar/RemoteBlazorWebView` on `net10`) with **zero extra auth containers** and **zero breakage to the Native AOT `NoAuthorization` relay build**:

1. **Public Hosted Report & Buyer Hardware QA QR Verification (`GET /r/{id}` + `GET /cert/{id}`)** and authenticated report/certificate upload API (`POST /api/reports`, `GET /api/reports`, `DELETE /api/reports/{id}`).
2. **In-Process `ASP.NET Core Identity` Shop Auth (`ShopIdentityAuthorization : IRelayAuthorization` + `ShopUserService : IUserService`)** backed by **SQLite (`WAL` mode)** by default (configurable connection string, e.g. `Data Source=/data/shops.db` in containers or `%LOCALAPPDATA%/RemoteWebViewService/shops.db` locally).
3. **2-Step, 60-Second Shop Signup + Branding Settings UI & Public Branding Lookup (`GET /api/shops/{group}/branding`)** matching `RemotePCDiagnostics`'s `ShopBranding` JSON contract verbatim.
4. **Active `Group` Validation & Per-Tier Concurrent Remote Session Caps** in `RemoteWebViewService.CreateWebView` / `ClientIPCService` (**unlimited** hosted bench QA certificate uploads on paid shop plans, capped concurrent live remote sessions by tier).

---

## 2. Critical `RemoteBlazorWebView` Architectural Rules (Must Follow)

1. **Preserve Native AOT (`Configuration == 'NoAuthorization'`) in `RemoteWebViewService.Lib`:**
   - `src/RemoteWebViewService/RemoteWebViewService.csproj` compiles with `<PublishAot Condition="'$(Configuration)' == 'NoAuthorization'">True</PublishAot>` and `<PublishTrimmed>True</PublishTrimmed>`, and **does NOT suppress `IL2026` or `IL3050`** from repo code.
   - Follow the exact sidecar pattern of `src/RemoteWebViewService.AzureB2C/`:
     - Put EF Core / `Microsoft.AspNetCore.Identity.EntityFrameworkCore` / `Microsoft.Data.Sqlite` / Razor or server-rendered HTML signup & settings endpoints inside a **new project**: `src/RemoteWebViewService.ShopIdentity/RemoteWebViewService.ShopIdentity.csproj` (`net10.0`, namespace `PeakSWC.RemoteWebView`).
     - Reference `RemoteWebViewService.ShopIdentity.csproj` from `src/RemoteWebViewService/RemoteWebViewService.csproj` inside `<ItemGroup Condition="'$(Configuration)' != 'NoAuthorization'">` (just like `RemoteWebViewService.AzureB2C.csproj` on lines 71–73).
     - Add `src/RemoteWebViewService/Authorization/ShopIdentityRegistration.cs` with `[ModuleInitializer]` calling `RelayAuthorization.Register(ShopIdentityAuthorization.ProviderName, () => new ShopIdentityAuthorization());`, and exclude it when `'$(Configuration)' == 'NoAuthorization'` (matching `AzureB2CRegistration.cs` on line 75).
     - Add `RemoteWebViewService.ShopIdentity.csproj` to `RemoteBlazorWebView.sln` **and** add `COPY src/RemoteWebViewService.ShopIdentity/ src/RemoteWebViewService.ShopIdentity/` to `Dockerfile` (right next to `COPY src/RemoteWebViewService.AzureB2C/` on line 11 of `Dockerfile`)!
   - Any interfaces/hooks added to `src/RemoteWebViewService.Lib/` (e.g., `IShopSessionPolicy` with a default `AllowAllShopSessionPolicy` for `NoAuthorization` / `FakeAuthorization`, or `IRelayEndpointExtension` / `IRelayAuthorization.MapEndpoints(IEndpointRouteBuilder)`) MUST be 100% reflection-free and AOT-safe (`JsonSerializerContext` if serializing in `Lib`).
2. **Claim Lookup Compatibility (`ClaimsPrincipalExtensions.GetUserObjectId`):**
   - Look at `src/RemoteWebViewService.Lib/ClaimsPrincipalExtensions.cs`:
     - `GetUserObjectId()` currently checks `"oid"` and `"http://schemas.microsoft.com/identity/claims/objectidentifier"`.
     - Update `GetUserObjectId()` to also fall back to `principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? principal.FindFirst("sub")?.Value`, **and** have `ShopIdentity` emit an `"oid"` claim equal to `user.Id` (plus `"preferred_username"` = email/display name so `GetUserDisplayName()` works in session audit logs!).
3. **Configuration Without `ConfigurationBinder` in `Lib`:**
   - Read settings via `configuration["ShopIdentity:ConnectionString"]` etc. rather than reflection-based `ConfigurationBinder` inside `RemoteWebViewService.Lib`.

---

## 3. Data Model (`RemoteWebViewService.ShopIdentity`)

Use lightweight SQLite (`Microsoft.Data.Sqlite` + either `Microsoft.AspNetCore.Identity.EntityFrameworkCore` or clean `IPasswordHasher<ShopUser>` + cookie authentication + Dapper/ADO.NET SQLite WAL—note: `Microsoft.AspNetCore.Identity` `PasswordHasher<TUser>` + `AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(...)` + `AddJwtBearer` or API-key bearer auth with explicit `Microsoft.Data.Sqlite` tables in `PRAGMA journal_mode=WAL;` is ultra-fast, zero-migration-headache, and has tiny package footprint! Either `IdentityDbContext` with `EnsureCreatedAsync` or `PasswordHasher<ShopUser>` + `Microsoft.Data.Sqlite` WAL tables is great, as long as passwords use `PasswordHasher` PBKDF2/ASP.NET Identity v3 format and cookies use `Microsoft.AspNetCore.Authentication.Cookies` with CSRF antiforgery on form POSTs).

### Tables

1. **`ShopTenants`**
   - `Id` (`TEXT PRIMARY KEY`, GUID)
   - `GroupSlug` (`TEXT NOT NULL UNIQUE` — lowercase `^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$`, e.g. `acme-pc-repair`; reserved slugs blocked: `admin`, `api`, `app`, `mirror`, `voice`, `health`, `status`, `wait`, `stats`, `cert`, `r`, `login`, `signup`, `account`, `test`)
   - `PlanTier` (`TEXT NOT NULL` — `"community"`, `"solo"` = 1 concurrent remote session, `"shop"` / `"founding_shop"` = 5 concurrent remote sessions, `"msp"` = 25 concurrent remote sessions)
   - `SubscriptionStatus` (`TEXT NOT NULL` — `"trialing"`, `"active"`, `"past_due"`, `"canceled"`; newly registered shops start in `"trialing"` for 30 days with `TrialEndsUtc`, `PlanTier = "shop"` so Founding Shops can test immediately before Stripe webhook flips to `"active"`)
   - `MaxConcurrentSessions` (`INTEGER NOT NULL` — `1` for `solo`, `5` for `shop`/`founding_shop`, `25` for `msp`, `0` when expired/canceled)
   - `ApiKeyHash` (`TEXT NOT NULL` — SHA-256 hash of a shop upload API token `rpd_live_<random>`, rotatable in shop settings, used by desktop bench machines to `POST /api/reports` without browser cookies)
   - **Branding columns (matching `RemotePCDiagnostics.Core.Workflow.ShopBranding`):**
     - `ShopName` (`TEXT`, max 120)
     - `LogoDataUri` (`TEXT NULL`, validated `^data:image/(png|jpeg|jpg|webp|gif);base64,[A-Za-z0-9+/=\r\n]+$`, max 80,000 chars — **reject `image/svg+xml`, `http://`, `https://`, `javascript:`**)
     - `Phone` (`TEXT NULL`, max 60)
     - `Email` (`TEXT NULL`, max 120)
     - `Website` (`TEXT NULL`, max 200, normalized `http://` or `https://` only)
     - `Address` (`TEXT NULL`, max 200)
     - `TechnicianName` (`TEXT NULL`, max 80)
     - `WarrantyFooter` (`TEXT NULL`, max 500)
     - `VerificationBaseUrl` (`TEXT NULL`, max 200)
   - `StripeCustomerId` (`TEXT NULL`), `StripeSubscriptionId` (`TEXT NULL`)
   - `CreatedUtc` (`TEXT NOT NULL`), `TrialEndsUtc` (`TEXT NULL`)

2. **`ShopUsers`**
   - `Id` (`TEXT PRIMARY KEY`, GUID — emitted as `"oid"` and `ClaimTypes.NameIdentifier`)
   - `ShopTenantId` (`TEXT NOT NULL REFERENCES ShopTenants(Id)`)
   - `Email` (`TEXT NOT NULL UNIQUE`, case-insensitive)
   - `DisplayName` (`TEXT NOT NULL`)
   - `PasswordHash` (`TEXT NOT NULL` via `Microsoft.AspNetCore.Identity.PasswordHasher<ShopUser>`)
   - `Role` (`TEXT NOT NULL` — `"owner"` or `"tech"`)
   - `CreatedUtc` (`TEXT NOT NULL`)

3. **`HostedReports`**
   - `Id` (`TEXT PRIMARY KEY` — URL-safe ID: either the certificate's `QA-YYYYMMDD-XXXXXX` when unique per upload or a 10-char Base62/nanoid slug like `QA-20261112-A1B2C3`, plus lookup by `Slug`)
   - `ShopTenantId` (`TEXT NOT NULL REFERENCES ShopTenants(Id)`)
   - `Kind` (`TEXT NOT NULL` — `"qa_certificate"` or `"service_report"`)
   - `Title` (`TEXT NOT NULL`, max 200)
   - `MachineName` (`TEXT NULL`, max 120)
   - `ManufacturerModel` (`TEXT NULL`, max 160)
   - `SerialNumber` (`TEXT NULL`, max 120)
   - `Verdict` (`TEXT NULL`, e.g. `"CertifiedPass"`, `"PassedWithNotes"`, `"AttentionRequired"`, `"Done"`)
   - `VerificationHash` (`TEXT NULL` — 64-char hex SHA-256 digest from `HardwareQaSnapshot.VerificationHash`, or computed SHA-256 of `HtmlContent`)
   - `HtmlContent` (`TEXT NOT NULL` — capped at `512_000` bytes; served inside a strict Content-Security-Policy!)
   - `SummaryJson` (`TEXT NULL` — optional structured metadata JSON, max `64_000` bytes)
   - `CreatedUtc` (`TEXT NOT NULL`), `ExpiresUtc` (`TEXT NULL`)

---

## 4. Exact Wire Contracts (Must Match `RemotePCDiagnostics`)

### 4.1 `GET /api/shops/{group}/branding` (Public, CORS-enabled, Anonymous)
Used by `RemotePCDiagnostics` when a customer connects with `-g=<group>` (to display the shop's logo & phone trust banner and verify the group slug exists before starting a session):
- `404 Not Found` if `{group}` does not exist or tenant subscription is expired (`SubscriptionStatus` not `"trialing"` or `"active"`, or `TrialEndsUtc < UtcNow` when `"trialing"`).
- `200 OK` (`application/json`, camelCase matching `System.Text.Json` Web defaults / `ShopBranding` properties case-insensitively):
```json
{
  "group": "acme-pc-repair",
  "active": true,
  "shopName": "Acme PC Repair & Refurb",
  "logoDataUri": "data:image/webp;base64,...",
  "phone": "(555) 019-2834",
  "email": "service@acmepc.example",
  "website": "https://acmepc.example/",
  "address": "120 Main St",
  "technicianName": "Alex Rivera",
  "warrantyFooter": "Backed by our 90-Day Parts & Labor Warranty.",
  "verificationBaseUrl": "https://remoteblazorwebview.com/r"
}
```

### 4.2 `POST /api/reports` (Authenticated via Session Cookie OR `Authorization: Bearer rpd_live_...` Shop API Key)
Allows **unlimited simultaneous bench QA uploads** (no per-PC dongle limit!) for any active/trialing shop tenant:
- Request body (`application/json`, max 600 KB):
```json
{
  "id": "QA-20261112-A1B2C3",
  "kind": "qa_certificate",
  "title": "Dell Inc. Latitude 7420 (QA-20261112-A1B2C3)",
  "machineName": "REFURB-04",
  "manufacturerModel": "Dell Inc. Latitude 7420",
  "serialNumber": "8H9K2L3",
  "verdict": "CertifiedPass",
  "verificationHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "html": "<!DOCTYPE html><html lang=\"en\">...</html>"
}
```
- Behavior:
  - Validate shop tenant is active/trialing (`402 Payment Required` or `403 Forbidden` if expired).
  - If `id` is already taken by *another* tenant (or collision with a different `verificationHash`), append a short random suffix (`QA-20261112-A1B2C3-7K9M`) so one shop can never overwrite another shop's certificate! If the *same* tenant re-uploads the exact same `id` + `verificationHash`, return the existing record idempotently.
  - Return `201 Created`:
```json
{
  "id": "QA-20261112-A1B2C3",
  "url": "https://<host>/r/QA-20261112-A1B2C3",
  "shortHash": "9F86D081884C"
}
```

### 4.3 `GET /r/{id}` and `GET /cert/{id}` (Public Buyer QR Verification Endpoint — Anonymous)
Notice `HardwareQaCertificate.BuildQrPayload` in `RemotePCDiagnostics` generates:
`{VerificationBaseUrl}/{Uri.EscapeDataString(certId)}?h={shortHash}` (for example `https://remoteblazorwebview.com/r/QA-20261112-A1B2C3?h=9F86D081884C` or `/cert/QA-20261112-A1B2C3?h=9F86D081884C`).
- Support **both** `GET /r/{id}` and `GET /cert/{id}`!
- If query parameter `?h={shortHash}` is present, check whether `VerificationHash` starts with `h` (case-insensitive):
  - If `?raw=1` is requested (used inside a sandboxed `<iframe>`), return `HtmlContent` directly with strict security headers:
    - `Content-Security-Policy: default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src 'none'; frame-ancestors 'self'; form-action 'none'`
    - `X-Content-Type-Options: nosniff`
    - *(This guarantees uploaded HTML can NEVER execute JavaScript, steal cookies on the relay origin, or load external tracking pixels!)*
  - On normal `GET /r/{id}` (what an eBay/BackMarket laptop buyer sees when scanning the QR code on their phone):
    - Render a clean, mobile-responsive **Verified Hardware QA / Service Report Wrapper Page** showing:
      - Green **"Verified Authentic Certificate"** banner (or Red **"Hash Mismatch Warning"** if `?h=` does not match `VerificationHash`!) with Shop Name, Issue Date (`CreatedUtc`), Model, Masked/Full Serial Number, SHA-256 prefix, and a **"Print / Save PDF"** button
      - An embedded `<iframe sandbox="" src="/r/{id}?raw=1">` rendering the full 1-page certificate / service report safely with zero script execution!

### 4.4 2-Step Shop Signup, Login & Dashboard Pages (`/signup`, `/login`, `/logout`, `/shop`)
Server-rendered HTML pages (following `Pages/LockedPage.cs` / `RestartPage.cs` clean self-contained HTML style—no extra JS bundler needed!):
1. **`GET/POST /signup` (2-Step or Combined Single-Screen 60-Second Flow):**
   - Step 1: Email, Password (min 8 chars), Your Name, Shop Name $\rightarrow$ auto-suggests `GroupSlug` (`GET /api/shops/{slug}/available` live check). Creates `ShopTenant` (`trialing` for 30 days, `PlanTier = "shop"`, `MaxConcurrentSessions = 5`, generates initial API key) + `ShopUser` (`owner`), signs user in via cookie, redirects to `/shop/onboarding` (Step 2).
   - Step 2 (`/shop/onboarding`, skippable with "Skip for now" $\rightarrow$ `/shop`): Upload Shop Logo (client/server-validated `< 55 KB` PNG/JPEG/WebP/GIF $\rightarrow$ `data:image/...;base64,...`), Phone, Website, Address, Warranty Footer.
2. **`GET/POST /login` & `POST /logout`:**
   - Standard cookie authentication (`LoginPath = "/login"`, `AccessDeniedPath = "/login?denied=1"`, `HttpOnly = true`, `SameSite = Lax`, `SecurePolicy = SameAsRequest` in dev / `Always` in prod).
3. **`GET /shop` (Authenticated Shop Portal):**
   - Shows the shop's **Group Code** (e.g., `acme-pc-repair`), current Plan & Concurrent Session usage (`X of 5 active remote sessions`), **Bench Upload API Key** (reveal/rotate button + copyable `VerificationBaseUrl`), Branding editor, list of hosted reports/certificates with links & delete buttons, and optional Stripe Checkout / Billing Portal link placeholder (`ShopIdentity:StripePaymentLinkUrl` config hook when configured).

---

## 5. Session Concurrency Caps & Active `Group` Enforcement

Add an interface in `src/RemoteWebViewService.Lib/` (e.g., `src/RemoteWebViewService.Lib/Authorization/IShopSessionPolicy.cs`):
```csharp
public readonly record struct SessionGateDecision(bool Allowed, string? ErrorCode = null, string? Message = null);

public interface IShopSessionPolicy
{
    Task<SessionGateDecision> CheckCreateSessionAsync(string group, int activeInGroupCount, CancellationToken ct = default);
}
```
- Default registration in `Startup.cs` (`TryAddSingleton<IShopSessionPolicy, AllowAllShopSessionPolicy>()`) always returns `Allowed = true` so `NoAuthorization`, `FakeAuthorization`, and existing `RemoteWebView.Lifecycle.Tests` / `StaticContentCache.ServiceTests` pass unchanged!
- When `ShopIdentityAuthorization` is active:
  - Lookup `ShopTenant` by `group` (optionally allowing `"default"` / `"test"` only if `ShopIdentity:AllowUnregisteredGroups=true`, default `false`).
  - If `group` is unknown or tenant subscription is expired: return `Allowed = false, ErrorCode = "group_inactive"`.
  - Count active sessions in `serviceDictionary` currently belonging to `group` (`Task.IsCompletedSuccessfully && !state.Token.IsCancellationRequested`). If `activeInGroupCount >= tenant.MaxConcurrentSessions`: return `Allowed = false, ErrorCode = "session_limit_reached"`.
  - In `Services/RemoteWebViewService.cs` (`CreateWebView`), check `IShopSessionPolicy.CheckCreateSessionAsync` before registering the session; if denied, log warning and write `new WebMessageResponse { Response = $"createFailed:{decision.ErrorCode}" }` and return cleanly without throwing or leaking dictionary entries.
- In `ShopUserService : IUserService`:
  - `GetUserGroups(string oid)` returns `[tenant.GroupSlug]` **only** when the user exists and `tenant` has an active or valid-trial subscription (`[]` when expired/canceled—so `SessionAccessHandler` and `ClientIPCService.GetClients` automatically block expired accounts!).

---

## 6. Required Unit & Integration Tests (`RemoteBlazorWebView`)

Add a dedicated test suite (either in `test/RemoteWebView.Lifecycle.Tests/ShopIdentityTests.cs` or a new `test/RemoteWebViewService.ShopIdentity.Tests/` project added to `RemoteBlazorWebView.sln` and CI):
1. **Signup + Login + `SessionAccessHandler` Integration Test (on real `EmbeddedRemoteWebViewServer`):**
   - Register Shop A (`acme-repair`) and Shop B (`beta-tech`) against a temp SQLite DB.
   - Verify Shop A's signed-in cookie can open `/status/{sessionInAcme}` (`200 OK`) and gets `403 Forbidden` on `/status/{sessionInBeta}`, while unauthenticated owner key `/app/{id}?role=owner&key=...` still succeeds without login.
   - Verify expiring/canceling Shop A's subscription causes `IUserService.GetUserGroups` to return `[]` and `/mirror/{sessionInAcme}` to return `403 Forbidden`.
2. **Concurrent Session Cap Test:**
   - Set Shop A to `solo` (`MaxConcurrentSessions = 1`). Connect 1st session (`created:`), verify 2nd concurrent `CreateWebView` in `acme-repair` returns `createFailed:session_limit_reached`, and after 1st disconnects, next session succeeds.
3. **Public Branding & Hosted QR Certificate Verification + CSP XSS Test:**
   - `GET /api/shops/acme-repair/branding` returns `200` with sanitized logo/website; rejects `image/svg+xml` and `javascript:` URLs on save.
   - `POST /api/reports` with Bearer API key stores a `HardwareQaCertificate` HTML; `GET /r/{id}?h={matchingPrefix}` returns `200` showing Verified state; `GET /r/{id}?h=000000000000` shows mismatch warning; `GET /r/{id}?raw=1` sets `Content-Security-Policy: default-src 'none'` so `<script>alert(1)</script>` cannot execute; cross-tenant `POST /api/reports` with Shop A's existing `id` does NOT overwrite Shop A's certificate.
4. **Native AOT / Build Verification:**
   - Verify `dotnet test` passes on all test projects and `NoAuthorization` configuration continues to compile without `ShopIdentity` trim/AOT warnings.

---

## 7. Git & Check-In Checklist for Bot #2

1. Work in `/home/antigravity/budcribar/RemoteBlazorWebView` on branch `net10`:
   ```bash
   git fetch origin
   git checkout net10
   git pull --rebase origin net10
   ```
2. Implement `src/RemoteWebViewService.ShopIdentity/`, wire `ShopIdentityRegistration.cs` + `Dockerfile` + `RemoteBlazorWebView.sln` + `IShopSessionPolicy` + `ClaimsPrincipalExtensions.GetUserObjectId`.
3. Commit, `git pull --rebase origin net10`, push to `origin/net10`, and watch GitHub Actions (`gh run list -R budcribar/RemoteBlazorWebView --branch net10`) to confirm green CI.
