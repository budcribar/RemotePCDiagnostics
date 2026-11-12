# Item 3B Specification: Stripe Billing (Checkout, Customer Portal & Signed Webhooks) + Multi-Tech Team Invites

> Mirror copy of [`RemoteBlazorWebView/doc/ShopBillingAndTeamInvitesSpec.md`](https://github.com/budcribar/RemoteBlazorWebView/blob/net10/doc/ShopBillingAndTeamInvitesSpec.md) for cross-repo tracking in `RemotePCDiagnostics`.

**Target Repository:** `budcribar/RemoteBlazorWebView`  
**Target Branch:** `net10`  
**Baseline Commit:** `16b9ce1` (`Add shop accounts and hosted QA certificates to the relay`)  
**Scope Constraint:** Work **strictly inside `RemoteBlazorWebView`** (`src/RemoteWebViewService.ShopIdentity/` and `test/RemoteWebView.ShopIdentity.Tests/`). Do **not** modify `budcribar/RemotePCDiagnostics`.

---

## Summary of Deliverables for Parallel Bot #2

1. **Zero-Dependency Stripe Billing (`ShopStripe.cs` + `ShopEndpoints.cs`):**
   - Pure `HttpClient` + `HMACSHA256` + `CryptographicOperations.FixedTimeEquals` inside `src/RemoteWebViewService.ShopIdentity/` (zero third-party `Stripe.net` NuGet dependency; Native AOT `NoAuthorization` untouched).
   - `POST /shop/billing/checkout` (`owner` + CSRF): creates Stripe Checkout Session (`mode=subscription`, `client_reference_id`, `metadata[tenant_id]`, `metadata[plan_tier]`) for `solo` (\$15/mo, 1 session / 1 seat), `founding_shop` (\$25/mo, 5 sessions / 3 seats), `shop` (\$39/mo, 5 sessions / 3 seats), or `msp` (\$99+/mo, 25 sessions / 10 seats).
   - `POST /shop/billing/portal` (`owner` + CSRF): opens Stripe Customer Billing Portal for invoices, card updates, and cancellations.
   - `POST /api/stripe/webhook` (anonymous, raw body, 5-minute replay tolerance, `ProcessedStripeEvents` idempotency table): handles `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`, and `invoice.payment_failed`, automatically updating `ShopTenants` (`StripeCustomerId`, `StripeSubscriptionId`, `PlanTier`, `SubscriptionStatus`, `MaxConcurrentSessions`).
2. **Multi-Tech Team Invites & Role Guards (`owner` vs `tech`):**
   - `ShopInvites` SQLite table (`TokenHash`, `ShopTenantId`, `Email`, `Role`, `ExpiresUtc`, `AcceptedUtc`).
   - `POST /shop/team/invite`, `POST /shop/team/invites/{id}/revoke`, `POST /shop/team/{userId}/remove` (`owner` + CSRF) enforcing per-tier seat limits (`solo` = 1, `founding_shop`/`shop` = 3, `msp` = 10).
   - `GET /invite/{token}` + `POST /invite/{token}` onboarding invited technicians (`Role = "tech"`) who immediately gain `/mirror/{id}` remote session access for `tenant.GroupSlug` and report upload access while owner-only actions (`/shop/apikey/rotate`, `/shop/branding`, billing, team management) return `403 Forbidden`.
   - Immediate revocation on `RemoveUser` via live `ShopStore.FindUserById(oid)` checks in `ShopUserService` and `ShopAuth`.
3. **Integration Test Suite (`ShopIdentityTests.cs`):**
   - HMAC signature verification, tamper & stale-timestamp rejection, duplicate `evt_...` idempotency, subscription cancellation session-gate lockout, mocked `HttpMessageHandler` Checkout/Portal redirects, and full owner -> tech invite -> role guard -> seat cap -> tech removal lifecycle.
