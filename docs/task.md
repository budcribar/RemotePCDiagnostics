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
- [x] Extend [ClientReport.cs](../src/RemotePCDiagnostics.Core/Workflow/ClientReport.cs) to accept [ShopBranding.cs](../src/RemotePCDiagnostics.Core/Workflow/ShopBranding.cs)
- [x] Build **1-Page Buyer Hardware QA QR Certificate** mode ([HardwareQaCertificate.cs](../src/RemotePCDiagnostics.Core/Workflow/HardwareQaCertificate.cs), [QrCodeSvg.cs](../src/RemotePCDiagnostics.Core/Workflow/QrCodeSvg.cs), and [BrandingCertificatePage.razor](../src/RemotePCDiagnostics.UI/Pages/BrandingCertificatePage.razor))
- [x] Finish **Bench Refurbisher QA Suite** in `RemotePCDiagnostics` (`7d9804a`): WHEA hardware error roll-up, interactive Keyboard NKRO + Display Dead-Pixel/Touch check, and 1-click 10-Minute Hardware Intake / QA Check
- [x] Ship **Hosted QR Verification (`GET /r/{id}`) + Multi-Tenant Shop Auth/Branding** in [RemoteBlazorWebView](https://github.com/budcribar/RemoteBlazorWebView) (`16b9ce1` on `net10`, [item2-hosted-qa-and-shop-auth-spec.md](item2-hosted-qa-and-shop-auth-spec.md))

## Step 3: Desktop Shop Relay Integration + Stripe Billing & Multi-Tech Team Invites *(DONE — `ef59232` & `7fef1a0`)*
- [x] Connect Desktop Client to Shop Relay & Hosted QR Certificates (`ef59232` on `RemotePCDiagnostics` `main`):
  - [x] `-g=<group>` (`REMOTEPC_GROUP`) across [SessionLaunchOptions.cs](../src/RemotePCDiagnostics.Core/Session/SessionLaunchOptions.cs), [RebootResumeCoordinator.cs](../src/RemotePCDiagnostics.Core/Areas/RebootResumeCoordinator.cs), [WindowsWorkflowSystem.cs](../src/RemotePCDiagnostics.Host/WindowsWorkflowSystem.cs), and [MainWindow.xaml.cs](../src/RemotePCDiagnostics.Host/MainWindow.xaml.cs)
  - [x] **"Connect to Technician"** top-bar dialog + live shop logo/phone trust banner ([MainLayout.razor](../src/RemotePCDiagnostics.UI/Shared/MainLayout.razor))
  - [x] 1-click **"Publish Hosted QR Link"** (`POST /api/reports` with `Bearer rpd_live_...`) on [BrandingCertificatePage.razor](../src/RemotePCDiagnostics.UI/Pages/BrandingCertificatePage.razor) and [WorkflowPage.razor](../src/RemotePCDiagnostics.UI/Pages/WorkflowPage.razor)
- [x] Wire **Stripe Checkout, Billing Portal, Signed Webhooks & Multi-Tech Team Invites** (`7fef1a0` on `RemoteBlazorWebView` `net10`, [item3b-stripe-and-team-invites-spec.md](item3b-stripe-and-team-invites-spec.md))

## Step 4: Microsoft Store `asInvoker` + MSIX Packaging & Relay Launch Hardening *(ACTIVE — Parallel Split)*
- [x] **NEXT #1 *(DONE — `RemotePCDiagnostics` `main`)*:** Switch to `asInvoker`, Add Elevated Admin Repair Mode & Build `.msix` Store Package:
  - [x] Switch [app.manifest](../src/RemotePCDiagnostics.Host/app.manifest) on `Host.exe` from `requireAdministrator` to `asInvoker` + add runtime elevation detection (`IElevationContext` / `ElevationService`) and clear admin badges in UI when running un-elevated
  - [x] Add **"Enable Admin Repair Mode"** UAC flow + Named-Pipe elevated helper (`RemotePCDiagnostics.Admin`, `--mode=helper --parent-pid=<pid>` with `PipeSecurity` ACLs, client process verification, and Win32 Job Object exit tie-in)
  - [x] Add [AppxManifest.template.xml](../msix/AppxManifest.template.xml) (`runFullTrust` + `allowElevation`), Store visual assets, zero-`.sys`-driver CI assertion ([Build-Msix.ps1](../msix/Build-Msix.ps1)), and automated `MakeAppx.exe` `.msix` build in [ci.yml](../.github/workflows/ci.yml) ready for $0 Partner Center upload
- [ ] **NEXT #2 *(Ready for Parallel Bot #2 in `RemoteBlazorWebView` `net10` — Full Spec in [item4b-relay-production-and-demo-spec.md](item4b-relay-production-and-demo-spec.md) / `doc/ShopRelayProductionAndDemoSpec.md`)*:** Production Relay Landing Page, Live Sample QR Certificate, Rate Limiting & Container Deploy:
  - [ ] Public `GET /welcome` landing/pricing page + auto-seeded live sample certificate at `GET /r/DEMO-LATITUDE-7420`
  - [ ] Built-in `Microsoft.AspNetCore.RateLimiting` (`429` protection on `/signup`, `/login`, `/invite/{token}`, and `/api/reports`)
  - [ ] `GET /api/shop/health` SQLite WAL readiness probe + `ShopMaintenanceService` expired-report/invite sweep + turnkey `deploy/docker-compose.shop.yml` & `deploy/fly.toml.example`

## Step 5: Outbound Sales to First 25 Founding Shops *(Weeks 4–5)*
- [ ] Deploy live relay container & verify live sample **Hardware QA Certificate** (`/r/DEMO-LATITUDE-7420`)
- [ ] Record 60-second silent-friendly **Store → Group Code → Before/After Report** Loom/GIF demo
- [ ] Send 10 messages/day to eBay/Swappa/BackMarket laptop refurbishers (target: first 10 trials)
- [ ] Post MIT open-source bench tool showcase on Technibble, `r/computertechs`, and The Tech Tribe *(also builds the organic stars/discussions needed to reapply to SignPath Foundation for $0)*
- [ ] DM 15 PC repair / refurbishment YouTubers with free lifetime white-labeled Pro accounts

## Step 6: Unattended MSP Fleet Tier & Standalone Installer Signing *(Post-First Paying Customers)*
- [ ] Reapply to **SignPath Foundation** ($0) once community stars/mentions land — or turn on **$9.99/mo Azure Artifact Signing** funded by Customer #1 ($25/mo) to sign standalone [RemotePCDiagnostics.iss](../installer/RemotePCDiagnostics.iss) (`RemotePCDiagnostics-Setup.exe`)
- [ ] Build `RemotePCDiagnostics.Agent.exe` Windows Service (`--mode=service`, combining `AgentHub.Connect` from [agent.proto](../src/RemotePCDiagnostics.Agent/Protos/agent.proto) + Named-Pipe admin gRPC)
- [ ] Scope `AgentAdmin` by tenant `Group` and add 1-click RMM snippet generator on **Computers** page
- [ ] Publish `BudCribar.RemotePCDiagnostics.Agent` to `microsoft/winget-pkgs` with `namazso.PawnIO` in `PackageDependencies`
