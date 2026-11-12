# Item 4B Specification: Shop Relay Production Hardening, Live Demo QR Certificate, Rate Limiting & Container Deploy

> Mirror summary of [`RemoteBlazorWebView/doc/ShopRelayProductionAndDemoSpec.md`](https://github.com/budcribar/RemoteBlazorWebView/blob/net10/doc/ShopRelayProductionAndDemoSpec.md) for cross-repo tracking in `RemotePCDiagnostics`.

**Target Repository:** `budcribar/RemoteBlazorWebView`  
**Target Branch:** `net10`  
**Baseline Commit:** `7fef1a0` (`Match shop billing and team invites to the written spec`)  
**Scope Constraint:** Work **strictly inside `RemoteBlazorWebView`**. Do **not** modify `budcribar/RemotePCDiagnostics`.

---

## Summary of Deliverables for Parallel Bot #2

1. **Public Conversion Page (`GET /welcome`) & Auto-Seeded Live Sample Certificate (`/r/DEMO-LATITUDE-7420`):**
   - Avoid route collisions with `Startup.cs` (`GET /` and `GET /health` stay untouched).
   - Auto-seed a reserved inactive demo tenant (`demo-shop`, `MaxConcurrentSessions = 0`) + print-ready sample certificate `DEMO-LATITUDE-7420` when `ShopIdentity:SeedDemoReport` is `true` (default) so refurbishers can scan and verify a live hosted certificate immediately.
   - Render `GET /welcome` with 3-step overview, transparent Solo/Founding Shop/MSP pricing, `/signup` & `/login` CTAs, and live `/r/DEMO-LATITUDE-7420` demo link.
2. **Built-In Endpoint Rate Limiting (`Microsoft.AspNetCore.RateLimiting`):**
   - Zero new NuGet packages; `NoAuthorization` Native AOT untouched.
   - `"shop-auth"` fixed-window policy on `POST /signup`, `POST /login`, and `POST /invite/{token}` + `"shop-reports"` policy on `POST /api/reports`, configurable via `ShopIdentity:RateLimit:*` and returning `429 Too Many Requests`.
3. **Deep SQLite WAL Health Probe & Expired-Row Cleanup:**
   - `GET /api/shop/health` verifying SQLite WAL journal mode + schema connectivity.
   - `ShopStore.PurgeExpired(DateTime nowUtc)` + `ShopMaintenanceService` hourly sweep removing expired `HostedReports` and expired unaccepted `ShopInvites`.
4. **Turnkey Container Deployment (`Dockerfile` `/data` volume + `deploy/`):**
   - Non-root `$APP_UID` write permissions for `/data` in `Dockerfile` + `deploy/docker-compose.shop.yml`, `deploy/.env.shop.example`, and `deploy/fly.toml.example`.
