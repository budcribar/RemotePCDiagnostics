# Launch & Monetization Todo List ($0 Bootstrap Path)

Persistent tracker for shipping **Remote PC Diagnostics** to paying Repair Shops, Solo Techs, and Laptop Refurbishers with **$0 up-front spend** (see [marketing-plan.md](marketing-plan.md)).

## Completed Foundation
- [x] Define B2B SaaS pricing, Store commerce rules (`10.8.1` / `10.8.6`), and two-channel distribution strategy in [marketing-plan.md](marketing-plan.md)
- [x] Document multi-tenant `Group` onboarding & relay isolation architecture
- [x] Document MSIX vs. `Policy 10.2.9` Win32 Store rules, unsigned NuGet `.dll` handling, driver exclusions, MSP `winget` flow, and B2B sales playbook
- [x] Lock in **$0 Out-of-Pocket Bootstrap Budget** ($0 Store account + $0 MSIX Store signing + $0-fixed-fee Stripe Checkout; defer standalone `.exe` cert until community traction or Customer #1 revenue)
- [x] Document open-source **`ASP.NET Core Identity`** (`ShopIdentityAuthorization : IRelayAuthorization` + `IUserService`), 2-step `ShopBranding` onboarding, and **PC-Doctor (`pcdremote.com`) Competitor Battlecard**

---

## Step 1: $0 Microsoft Store Registration & Public OSS Release *(DONE — Store Pending Verification)*
- [x] Open **free Microsoft Store Developer account** at `https://storedeveloper.microsoft.com` ($0 — submitted, pending verification; **MSIX signing covers `Host.exe` + all unsigned NuGet `.dll`s for $0 with zero GitHub-star gate and zero SmartScreen warning**)
- [x] Enable GitHub 2FA, switch `budcribar/RemotePCDiagnostics` to **Public** under the MIT License, add [Privacy & security policy](../README.md#privacy--security-policy) (documenting read-only CIS `HardeningKitty` baseline scope and zero telemetry), and publish rolling GitHub Actions installers ([ci.yml](../.github/workflows/ci.yml))
- [x] Submit initial **SignPath Foundation** OSS inquiry *(declined for now solely pending organic GitHub stars / Reddit / YouTube mentions — **reapply after Step 5 community posts**, or fund $9.99/mo Azure Artifact Signing out of Customer #1's $25/mo subscription)*

## Step 2: Ship `ShopBranding` Before/After Reports & Dongle-Free Buyer QR Certificates *(DONE — `7d9804a` & `16b9ce1`)*
- [x] Extend [ClientReport.cs](../src/RemotePCDiagnostics.Core/Workflow/ClientReport.cs) to accept [ShopBranding.cs](../src/RemotePCDiagnostics.Core/Workflow/ShopBranding.cs) (inline `data:image/...` logo, shop name, phone/URL, warranty footer, technician notes—proving Before/After Windows speedups where PC-Doctor stops at *"Hardware Passed"*)
- [x] Build **1-Page Buyer Hardware QA QR Certificate** mode ([HardwareQaCertificate.cs](../src/RemotePCDiagnostics.Core/Workflow/HardwareQaCertificate.cs), [QrCodeSvg.cs](../src/RemotePCDiagnostics.Core/Workflow/QrCodeSvg.cs), and [BrandingCertificatePage.razor](../src/RemotePCDiagnostics.UI/Pages/BrandingCertificatePage.razor): Model/Serial + Battery % + SMART SSD + Thermal Stress + Dongle-Free WASAPI Audio Loopback + Webcam + GPU/NPU + scannable eBay/BackMarket QR badge with zero new NuGet DLLs)
- [x] Finish **Bench Refurbisher QA Suite** in `RemotePCDiagnostics` (`7d9804a`):
  - [x] Interactive **Keyboard NKRO + Display Dead-Pixel / Touch** check ([PhysicalBenchQa.cs](../src/RemotePCDiagnostics.Core/Workflow/PhysicalBenchQa.cs), [PhysicalBenchQaCard.razor](../src/RemotePCDiagnostics.UI/Shared/PhysicalBenchQaCard.razor)) rolled up onto [HardwareQaCertificate.cs](../src/RemotePCDiagnostics.Core/Workflow/HardwareQaCertificate.cs)
  - [x] **WHEA Hardware Error** roll-up across [BsodHistoryModule.cs](../src/RemotePCDiagnostics.Core/Areas/BsodHistoryModule.cs), [CrashesModule.cs](../src/RemotePCDiagnostics.Core/Areas/CrashesModule.cs), and [EventLogModule.cs](../src/Modules/EventLog/EventLogModule.cs)
  - [x] 1-click **"10-Minute Hardware Intake / QA Check"** offline-safe bench preset ([BenchQaRunner.cs](../src/RemotePCDiagnostics.Core/Workflow/BenchQaRunner.cs))
- [x] Ship **Hosted QR Verification (`GET /r/{id}`) + Multi-Tenant Shop Auth/Branding** in [RemoteBlazorWebView](https://github.com/budcribar/RemoteBlazorWebView) (`16b9ce1` on `net10`, [item2-hosted-qa-and-shop-auth-spec.md](item2-hosted-qa-and-shop-auth-spec.md)):
  - [x] `ShopIdentityAuthorization : IRelayAuthorization` + `ShopUserService : IUserService` backed by SQLite (`WAL` mode)
  - [x] 2-step `/signup`, `/login`, `/shop` portal + public `GET /api/shops/{group}/branding`
  - [x] `POST /api/reports` (`Bearer rpd_live_...` or cookie) + CSP-sandboxed `GET /r/{id}` & `GET /cert/{id}` QR verification pages
  - [x] `IShopSessionPolicy` enforcing active `Group` + per-tier concurrent remote session caps (`1` Solo, `5` Shop, `25` MSP)

## Step 3: Desktop Shop Relay Integration + Stripe Billing & Multi-Tech Team Invites *(ACTIVE — Parallel Split)*
- [ ] **NEXT #1 *(In Progress — Bot #1 in `RemotePCDiagnostics` `main`)*:** Connect Desktop Client to `16b9ce1` Shop Relay & Hosted QR Certificates:
  - [ ] Add `-g=<group>` (`REMOTEPC_GROUP`) to [SessionLaunchOptions.cs](../src/RemotePCDiagnostics.Core/Session/SessionLaunchOptions.cs), persisted across browser restarts (`RestartArguments`), reboot resume ([RebootResumeCoordinator.cs](../src/RemotePCDiagnostics.Core/Areas/RebootResumeCoordinator.cs)), and workflow restarts ([WindowsWorkflowSystem.cs](../src/RemotePCDiagnostics.Host/WindowsWorkflowSystem.cs)), setting `RemoteBlazorWebView.Group` before `HostPage` in [MainWindow.xaml.cs](../src/RemotePCDiagnostics.Host/MainWindow.xaml.cs)
  - [ ] Add **"Connect to Technician"** top-bar dialog ([MainLayout.razor](../src/RemotePCDiagnostics.UI/Shared/MainLayout.razor)) validating `GET /api/shops/{group}/branding`, showing live shop logo + phone trust banner, and surfacing clear messages when a group is inactive or at session limit
  - [ ] Add 1-click **"Publish Hosted QR Link"** (`POST /api/reports` with `Bearer rpd_live_...` stored in `UserPreferences`) on [BrandingCertificatePage.razor](../src/RemotePCDiagnostics.UI/Pages/BrandingCertificatePage.razor) and [WorkflowPage.razor](../src/RemotePCDiagnostics.UI/Pages/WorkflowPage.razor) so printed QR codes point straight to live `/r/{id}` verification URLs
- [ ] **NEXT #2 *(Ready for Parallel Bot #2 in `RemoteBlazorWebView` `net10` — Full Spec in [item3b-stripe-and-team-invites-spec.md](item3b-stripe-and-team-invites-spec.md) / `doc/ShopBillingAndTeamInvitesSpec.md`)*:** Wire **Stripe Checkout, Billing Portal, Signed Webhooks & Multi-Tech Team Invites**:
  - [ ] Pure-`HttpClient` `POST /shop/billing/checkout` + `POST /shop/billing/portal` ($0/mo fixed fee: $15/mo Solo, $25/mo Founding Shop, $39/mo Shop, $99+/mo MSP)
  - [ ] `HMACSHA256`-verified `POST /api/stripe/webhook` with 5-minute replay window + `ProcessedStripeEvents` idempotency updating `ShopTenants` (`PlanTier`, `SubscriptionStatus`, `MaxConcurrentSessions`)
  - [ ] `ShopInvites` table + `/shop/team/invite`, `/invite/{token}`, `/shop/team/{userId}/remove`, per-tier seat caps (`1` / `3` / `10`), and `owner` vs `tech` role enforcement

## Step 4: User/Admin Split & $0 Microsoft Store MSIX Submission *(Weeks 3–4)*
- [ ] Change [app.manifest](../src/RemotePCDiagnostics.Host/app.manifest) on `Host.exe` from `requireAdministrator` to `asInvoker` and gracefully badge admin-only modules/fixes when un-elevated
- [ ] Build `RemotePCDiagnostics.Admin` (`--mode=helper --parent-pid=<pid>`) with Named-Pipe gRPC, `PipeSecurity` ACLs, `GetNamedPipeClientProcessId` MSIX Package Identity / Authenticode check, Job Object exit tie-in, and local **"Enable Admin Repair Mode"** UAC flow
- [ ] Verify zero `.sys` driver files in publish output and upload **MSIX** (`runFullTrust` + `allowElevation`) to Partner Center so Microsoft signs all `.exe`s and unsigned NuGet `.dll`s for **$0** *(installable by both end customers in Microsoft Store and technicians via `winget install --source msstore`)*

## Step 5: Outbound Sales to First 25 Founding Shops *(Weeks 4–5)*
- [ ] Generate and host 1 live sample **Hardware QA Certificate** from a real laptop
- [ ] Record 60-second silent-friendly **Store → Group Code → Before/After Report** Loom/GIF demo
- [ ] Send 10 messages/day to eBay/Swappa/BackMarket laptop refurbishers (target: first 10 trials)
- [ ] Post MIT open-source bench tool showcase on Technibble, `r/computertechs`, and The Tech Tribe *(also builds the organic stars/discussions needed to reapply to SignPath Foundation for $0)*
- [ ] DM 15 PC repair / refurbishment YouTubers with free lifetime white-labeled Pro accounts

## Step 6: Unattended MSP Fleet Tier & Standalone Installer Signing *(Post-First Paying Customers)*
- [ ] Reapply to **SignPath Foundation** ($0) once community stars/mentions land — or turn on **$9.99/mo Azure Artifact Signing** funded by Customer #1 ($25/mo) to sign standalone [RemotePCDiagnostics.iss](../installer/RemotePCDiagnostics.iss) (`RemotePCDiagnostics-Setup.exe`)
- [ ] Build `RemotePCDiagnostics.Agent.exe` Windows Service (`--mode=service`, combining `AgentHub.Connect` from [agent.proto](../src/RemotePCDiagnostics.Agent/Protos/agent.proto) + Named-Pipe admin gRPC)
- [ ] Scope `AgentAdmin` by tenant `Group` and add 1-click RMM snippet generator on **Computers** page
- [ ] Publish `BudCribar.RemotePCDiagnostics.Agent` to `microsoft/winget-pkgs` with `namazso.PawnIO` in `PackageDependencies`
