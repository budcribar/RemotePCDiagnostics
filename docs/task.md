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

## Step 2: Ship `ShopBranding` Before/After Reports & Dongle-Free Buyer QR Certificates *(ACTIVE — Week 1, $0)*
- [x] Extend [ClientReport.cs](../src/RemotePCDiagnostics.Core/Workflow/ClientReport.cs) to accept [ShopBranding.cs](../src/RemotePCDiagnostics.Core/Workflow/ShopBranding.cs) (inline `data:image/...` logo, shop name, phone/URL, warranty footer, technician notes—proving Before/After Windows speedups where PC-Doctor stops at *"Hardware Passed"*)
- [x] Build **1-Page Buyer Hardware QA QR Certificate** mode ([HardwareQaCertificate.cs](../src/RemotePCDiagnostics.Core/Workflow/HardwareQaCertificate.cs), [QrCodeSvg.cs](../src/RemotePCDiagnostics.Core/Workflow/QrCodeSvg.cs), and [BrandingCertificatePage.razor](../src/RemotePCDiagnostics.UI/Pages/BrandingCertificatePage.razor): Model/Serial + Battery % + SMART SSD + Thermal Stress + Dongle-Free WASAPI Audio Loopback + Webcam + GPU/NPU + scannable eBay/BackMarket QR badge with zero new NuGet DLLs)
- [ ] **NEXT #1 *(In Progress — Bot #1)*:** Finish **Bench Refurbisher QA Suite** in `RemotePCDiagnostics`:
  - [ ] Add quick **Keyboard Rollover + Display Dead-Pixel / Touch** check in [RemotePCDiagnostics.UI](../src/RemotePCDiagnostics.UI/RemotePCDiagnostics.UI.csproj) and roll up onto [HardwareQaCertificate.cs](../src/RemotePCDiagnostics.Core/Workflow/HardwareQaCertificate.cs)
  - [ ] Audit/enhance [BsodHistoryModule.cs](../src/RemotePCDiagnostics.Core/Areas/BsodHistoryModule.cs) & [CrashDumpDebugger.cs](../src/RemotePCDiagnostics.Core/Areas/CrashDumpDebugger.cs) for **WHEA Hardware Error** roll-up on QA certificates
  - [ ] Add 1-click **"10-Minute Hardware Intake / QA Check"** bench preset alongside [WorkflowService.cs](../src/RemotePCDiagnostics.Core/Workflow/WorkflowService.cs)
- [ ] **NEXT #2 *(Ready for Parallel Bot #2 — Full Spec in [item2-hosted-qa-and-shop-auth-spec.md](item2-hosted-qa-and-shop-auth-spec.md))*:** Add **Hosted QR Verification (`GET /r/{id}`) + Multi-Tenant Shop Auth/Branding** in [RemoteBlazorWebView](https://github.com/budcribar/RemoteBlazorWebView) (`net10` branch, sidecar project `src/RemoteWebViewService.ShopIdentity` preserving Native AOT `NoAuthorization`):
  - [ ] `ShopIdentityAuthorization : IRelayAuthorization` + `ShopUserService : IUserService` backed by SQLite (`WAL` mode) + update `ClaimsPrincipalExtensions.GetUserObjectId`
  - [ ] 2-step 60-second shop signup/login/portal (`/signup`, `/login`, `/shop`) + public `GET /api/shops/{group}/branding` matching [ShopBranding.cs](../src/RemotePCDiagnostics.Core/Workflow/ShopBranding.cs)
  - [ ] `POST /api/reports` (cookie or `Bearer rpd_live_...` shop API key, unlimited bench QA uploads) + public `GET /r/{id}` & `GET /cert/{id}` QR verification wrapper with `CSP: default-src 'none'` sandboxed raw view and `?h=` SHA-256 prefix check
  - [ ] `IShopSessionPolicy` in `RemoteWebViewService.CreateWebView` enforcing active `Group` + per-tier concurrent remote session caps (`1` Solo, `5` Shop, `25` MSP) + integration tests on `EmbeddedRemoteWebViewServer`

## Step 3: `ASP.NET Core Identity` Shop Auth, 2-Step Branding Signup, Concurrency Caps & Stripe *(Week 2 — $0)*
- [ ] Implement `ShopIdentityAuthorization : IRelayAuthorization` + `ShopUserService : IUserService` in `RemoteWebViewService.Lib` with SQLite (WAL) / PostgreSQL + Passkeys & Google/Microsoft OAuth
- [ ] Build **2-step, 60-second shop signup wizard** (Step 1: account + Shop Name / `Group` slug; Step 2, skippable: resize Shop Logo `< 40 KB` WebP `data:` URI + Phone, Website, Warranty Footer) and `GET /api/shops/{group}/branding`
- [ ] Enforce **active `Group` validation & per-tier concurrent remote session caps** in `ClientIPCService.cs` (`1` session on $15/mo Solo, `5` sessions on $25/$39/mo Shop, `15–50` on $99–$199/mo MSP + unlimited local bench QA uploads)
- [ ] Wire **Stripe Checkout / Billing Portal** ($0/mo fixed fee: $15/mo Solo 1-Session, $25/mo Founding Shop, $39/mo Solo Shop, $99–$199/mo MSP)
- [ ] Add `-g=<group>` to [SessionLaunchOptions.cs](../src/RemotePCDiagnostics.Core/Session/SessionLaunchOptions.cs) (including `RestartArguments` and `PendingRebootState`) + **"Connect to Technician"** dialog with live shop logo banner in [MainLayout.razor](../src/RemotePCDiagnostics.UI/Shared/MainLayout.razor) & [MainWindow.xaml.cs](../src/RemotePCDiagnostics.Host/MainWindow.xaml.cs)

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
