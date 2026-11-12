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
- [x] Enable GitHub 2FA, switch `budcribar/RemotePCDiagnostics` to **Public** under the MIT License, add [Privacy & security policy](../README.md#privacy--security-policy), and publish rolling GitHub Actions installers ([ci.yml](../.github/workflows/ci.yml))
- [x] Submit initial **SignPath Foundation** OSS inquiry *(declined pending organic GitHub stars / Reddit / YouTube mentions — **reapply after Step 5 community posts**, or fund $9.99/mo Azure Artifact Signing out of Customer #1's $25/mo subscription)*

## Step 2: Ship `ShopBranding` Before/After Reports & Dongle-Free Buyer QR Certificates *(DONE — `7d9804a` & `16b9ce1`)*
- [x] Extend [ClientReport.cs](../src/RemotePCDiagnostics.Core/Workflow/ClientReport.cs) to accept [ShopBranding.cs](../src/RemotePCDiagnostics.Core/Workflow/ShopBranding.cs)
- [x] Build **1-Page Buyer Hardware QA QR Certificate** mode ([HardwareQaCertificate.cs](../src/RemotePCDiagnostics.Core/Workflow/HardwareQaCertificate.cs), [QrCodeSvg.cs](../src/RemotePCDiagnostics.Core/Workflow/QrCodeSvg.cs), and [BrandingCertificatePage.razor](../src/RemotePCDiagnostics.UI/Pages/BrandingCertificatePage.razor))
- [x] Finish **Bench Refurbisher QA Suite** in `RemotePCDiagnostics` (`7d9804a`): WHEA hardware error roll-up, interactive Keyboard NKRO + Display Dead-Pixel/Touch check, and 1-click 10-Minute Hardware Intake / QA Check
- [x] Ship **Hosted QR Verification (`GET /r/{id}`) + Multi-Tenant Shop Auth/Branding** in [RemoteBlazorWebView](https://github.com/budcribar/RemoteBlazorWebView) (`16b9ce1` on `net10`)

## Step 3: Desktop Shop Relay Integration + Stripe Billing & Multi-Tech Team Invites *(DONE — `ef59232` & `7fef1a0`)*
- [x] Connect Desktop Client to Shop Relay & Hosted QR Certificates (`ef59232` on `RemotePCDiagnostics` `main`)
- [x] Wire **Stripe Checkout, Billing Portal, Signed Webhooks & Multi-Tech Team Invites** (`7fef1a0` on `RemoteBlazorWebView` `net10`)

## Step 4: Microsoft Store `asInvoker` + MSIX Packaging & Relay Launch Hardening *(DONE — `3b37765` & `924d5cf`)*
- [x] Switch [app.manifest](../src/RemotePCDiagnostics.Host/app.manifest) to `asInvoker`, build `RemotePCDiagnostics.Admin` Named-Pipe helper + **"Enable Admin Repair Mode"**, and publish Store-ready `.msix` (`runFullTrust` + `allowElevation`, zero `.sys` drivers) on rolling GitHub Releases (`3b37765`)
- [x] Ship public `GET /welcome` page, auto-seeded `/r/DEMO-LATITUDE-7420`, `429` rate limiting, `/api/shop/health`, `ShopMaintenanceService`, and `deploy/docker-compose.shop.yml` + `deploy/fly.toml.example` (`924d5cf` on `RemoteBlazorWebView` `net10`)

## Step 5 & 6: Partner Center Store Kit, Outbound Sales Pack & Unattended MSP Fleet Tier *(ACTIVE — Parallel Split)*
- [ ] **NEXT #1 *(In Progress — Bot #1 in `RemotePCDiagnostics` `main`)*:** Partner Center Submission Pack, Automated Store Screenshots, Outbound Sales Kit & Client Fleet Agent (`-g=<group>` + Windows Service + `winget` Manifest):
  - [ ] Generate crisp `1920x1080` Partner Center Store PNG screenshots automatically in CI + write `msix/PartnerCenter-Submission-Guide.md` (exact listing text, privacy answers, and `Policy 10.2.9` reviewer notes)
  - [ ] Write `docs/outbound-sales-kit.md` (copy-paste eBay/Swappa/BackMarket refurbisher DMs, Technibble & `r/computertechs` MIT showcase posts, and YouTuber lifetime Pro outreach)
  - [ ] Complete `RemotePCDiagnostics.Agent` (`src/RemotePCDiagnostics.Agent/RemotePCDiagnostics.Agent.csproj` Windows Service + `LaunchCommand.group` -> `-g=<group>` in `LaunchRules.AppCommandLine` + `winget/` manifest templates)
- [ ] **NEXT #2 *(Ready for Parallel Bot #2 in `RemoteBlazorWebView` `net10` — Full Spec in [item5-store-sales-and-msp-fleet-spec.md](item5-store-sales-and-msp-fleet-spec.md) / `doc/ShopMspFleetAndAgentScopingSpec.md`)*:** Multi-Tenant MSP Fleet Scoping & `/shop` Fleet Computers Portal:
  - [ ] Add `group` field to `agent.proto` (`LaunchCommand` & `AgentInfo`) and `IAgentTenantPolicy` in `RemoteWebViewService.Lib`
  - [ ] Scope `AgentRegistry`, `AgentHubService`, and `AgentAdminService` by tenant `GroupSlug` via `ShopAgentTenantPolicy` (requiring active `"msp"` tier for `rpd_live_...` fleet enrollment)
  - [ ] Add **Fleet Computers** table, `POST /shop/computers/{machineId}/start`, and 1-click **RMM PowerShell Install Snippet** on `/shop`

## Post-Launch Operational Milestones *(Owner Actions)*
- [ ] Deploy live relay (`deploy/fly.toml.example` or `deploy/docker-compose.shop.yml`) & set `ShopIdentity:Stripe:*` keys
- [ ] Upload `RemotePCDiagnostics-1.2.0-win-x64.msix` + CI Store screenshots to Partner Center once Microsoft Store developer verification completes ($0 signing)
- [ ] Send daily refurbisher outreach & community posts from `docs/outbound-sales-kit.md`, then reapply to **SignPath Foundation** ($0) once community stars/mentions land (or fund $9.99/mo Azure Artifact Signing from Customer #1)
