# Marketing, Monetization & Store Distribution Plan

How **Remote PC Diagnostics** makes money, reaches paying users, and ships through the Microsoft Store and direct channels without compromising security or running afoul of Windows and Store policies.

Related docs: [architecture.md](architecture.md) (as-built projects and privilege model), [module-plugins.md](module-plugins.md) (signed/unsigned plugin boundaries and host queries), and [roadmap.md](roadmap.md) (planned `RemotePCDiagnostics.Agent` service and workflow items).

---

## 1. Executive Summary & Core Thesis

Remote PC Diagnostics looks like a PC utility on the surface, but its real differentiator is a **complete remote technician and hardware QA workflow**:

- Same Blazor UI locally on the bench or shared remotely via [RemoteBlazorWebView](https://github.com/budcribar/RemoteBlazorWebView)
- Built-in WebRTC voice (`--voice`), explicit local user consent, and tamper-evident Windows Event Log session/action auditing
- Guided multi-stage service workflows (measure $\rightarrow$ remediate $\rightarrow$ reboot & resume $\rightarrow$ re-measure $\rightarrow$ before/after client report)
- Hardware verification modules rarely found in one lightweight tool (thermal-guarded stress tests, SMART drive health, battery wear, speaker-to-mic loopback, webcam frame analysis, NPU compute check)
- Planned lightweight persistent/per-session enrollment agent (`RemotePCDiagnostics.Agent`)

### Strategic Rule: Free Client Distribution, Paid Professional Workflow

Charging individual consumers \$9.99 up front for a diagnostic download puts the product into a race-to-the-bottom category against free staples (HWiNFO, OCCT, Microsoft PC Manager) and sleazy "PC cleaner" scareware—and conflicts with the repository's [MIT License](../LICENSE).

Instead:

1. **Distribute the desktop client for free in the Microsoft Store (and `winget`)** as a zero-SmartScreen, high-trust acquisition and customer-onboarding channel.
2. **Monetize the hosted infrastructure and commercial deliverables** (the hosted `RemoteWebViewService` relay, TURN voice servers, enrolled `AgentHub` computer fleet, white-labeled client service reports, and serial-numbered hardware QA certificates).
3. **Turn MIT open source into a sales asset:** IT admins, repair shops, and security-conscious users can inspect every privileged command that runs on an endpoint, while recurring revenue lives in the hosted multi-tenant SaaS layer that costs far more time to self-host than a monthly subscription.

---

## 2. Target Customer Segments

### Segment A — Independent PC Repair Shops, Solo IT Consultants & Small MSPs *(Primary Recurring Revenue)*

- **Pain today:** Paying \$60–\$150/month per technician for generic remote-desktop tools, talking anxious clients past Windows Defender SmartScreen warnings on `.exe` downloads, manually running `dism`, `sfc`, SMART checks, and HWiNFO, then typing up an invoice summary by hand to justify a \$99–\$149 tune-up fee.
- **Why they buy:**
  - **Zero-SmartScreen, no-URL client onboarding:** *"Open the Microsoft Store, install Remote PC Diagnostics, click **Connect to Technician**, and enter **`acme-repair`**"*—the customer's PC immediately appears on the technician's Admin website without reading long session URLs over the phone, while one shared relay isolates multiple shops by group.
  - **Tangible proof of work:** Automated **white-labeled Before/After Client Service Reports** (with the shop's logo, RAM/storage freed, integrity repairs, and benchmark deltas) justify the shop's service charge to the end customer.
  - **Enrolled fleet (`Computers` dashboard):** Persistent `RemotePCDiagnostics.Agent` installs keep retainer clients one click away in the same technician group without heavyweight RMM bloat.

### Segment B — Laptop Refurbishers & Used-PC Resellers *(High-Margin Vertical Wedge)*

- **Pain today:** Enterprise refurbishment suites (Blancco, PC-Doctor Service Center, Eurosoft) cost thousands of dollars annually and require sales calls, so smaller eBay, BackMarket, and local refurbishers test audio, webcams, batteries, drives, and thermals manually without buyer-verifiable proof.
- **Why they buy:**
  - Remote PC Diagnostics already covers the full bench QA checklist in one UI: model/serial inventory, battery health, SSD SMART & retrim status, CPU/GPU/RAM/Disk stress tests with thermal cutoffs, WASAPI speaker-to-microphone loopback, WinRT webcam frame/brightness checks, and NPU checks.
  - Adding a **Hosted Hardware Health Certificate** (tamper-evident PDF + hosted verification URL/QR code keyed to machine serial + timestamp) gives resellers something they can embed directly in eBay/storefront listings to command higher resale prices and fewer returns.

### Segment C — DIY Enthusiasts & "Family IT Support" Prosumers *(Organic Funnel & Impulse Tier)*

- **Pain today:** Consumer tune-up tools rely on dark patterns and fake "critical error" counts; helping a parent or friend troubleshoot a slow PC over the phone is frustrating.
- **Why they use & share it:**
  - 100% honest, ad-free local checks and stress tests build 5-star Microsoft Store ratings and organic search ranking.
  - A low-cost annual or one-time personal pass unlocks a personal group code, unlimited voice-enabled remote sessions, and reboot-and-resume workflows for helping family computers.

---

## 3. Pricing, Packaging & Store Commerce

### Tier Structure

| Tier | Price | Target User | Included |
| :--- | :--- | :--- | :--- |
| **Community (Free)** | **\$0** | Consumers, DIY bench users, evaluation | All local checks, sensors, stress/audio/webcam/NPU tests, and local fixes. Ad-hoc supervised remote sessions via direct link capped at 15 minutes (no TURN voice, standard report footer). |
| **Personal / Family Tech** | **\$19 / year** *(or \$15 30-day pass)* | Prosumers helping family & friends | Personal support group code on the Admin portal, unlimited supervised remote sessions with WebRTC voice (`--voice`), remote reboot-and-resume workflow, up to 5 enrolled family PCs. |
| **Solo Tech & Refurbisher** | **\$39 / month** *(or \$390 / year)* | Solo repair techs, mobile IT, laptop refurbishers | Dedicated shop group code (`acme-repair`), unlimited remote sessions + voice, **white-labeled Before/After Service Reports**, **Hosted Hardware QA Certificates** (QR/URL per serial), up to 50 enrolled `Agent` endpoints. |
| **Shop / Small MSP** | **\$99–\$199 / month** | Multi-tech repair shops, internal IT desks, MSPs | 3–10 technician seats in one or more groups, relay SSO/group authentication, 250–1,000 enrolled `Agent` endpoints, centralized session/remediation audit log retention, custom shop JSON checks & signed plugin deployment, unbranded reports. |

### Keeping ~97% of Revenue on PC (Store Policies `10.8.1` & `10.8.6`)

Under **Microsoft Store Policies `10.8.1` and `10.8.6`**, non-game PC applications distributed through the Microsoft Store are **explicitly permitted to use a secure third-party purchase API** (Stripe, Paddle, or Lemon Squeezy) for subscriptions and digital services rather than Microsoft's in-app billing:

- **0% Microsoft Store commission** (only standard ~2.9% + \$0.30 payment processor fees).
- **Single unified entitlement system** across Microsoft Store installs, `winget`, and direct Inno Setup / Agent deployments.
- **Compliance checklist for `10.8.2` / `10.8.6`:** Identify the payment provider at checkout, authenticate the user, allow turning off or re-authenticating purchases, allow browser handoff for account registration/checkout *after* installation completes, and declare third-party purchase API usage in Partner Center submission notes.

---

## 4. Commercial Readiness, Product Gaps & Sales Playbook

### 4.1 Realistic Odds, Unit Economics & \$0 Bootstrap Budget

- **Consumer B2C utility sales (<10% odds):** Consumers expect hardware diagnostics to be free (`HWiNFO`, `OCCT`, `CrystalDiskInfo`, `Microsoft PC Manager`), while paid consumer tune-up utilities are crowded out by high-ad-spend scareware.
- **Vertical B2B Micro-SaaS for Repair Shops, Solo Techs & Laptop Refurbishers (~50–65% odds of \$2k–\$10k/mo MRR in 6–12 months):**
  - **1-Job ROI:** A solo technician charging \$129 for a remote tune-up—or an eBay/BackMarket refurbisher earning +\$35 per laptop from a verified Hardware QA QR certificate—recovers a **\$39–\$99/month** subscription on a single job.
  - **90%+ Gross Margin:** Unlike full-desktop 60 fps video streaming tools, `RemoteBlazorWebView` relays lightweight UI diffs while heavy CPU/GPU/NPU benchmarks run on the endpoint. Fifty to a hundred small shops (\$3k–\$7k/mo MRR) run comfortably on modest cloud infrastructure.
  - **Positioning Discipline:** Do **not** pitch this as *"a cheaper TeamViewer"* (`RemoteBlazorWebView` mirrors the diagnostic app's UI, not the whole Windows desktop). Pitch it as **"Zero-SmartScreen Store Onboarding + Automated Bench/Remote Diagnostics + Client Proof-of-Work Reports."**

#### \$0 Out-of-Pocket Bootstrap Budget (Until Customer #1 Pays You)

You do **not** need to spend \$9.99/month on code signing before making money:

| Item | Up-Front Cost | How It Works |
| :--- | :--- | :--- |
| **Microsoft Store Developer Account** | **\$0** | Both Individual and Company developer registrations are permanently free at `storedeveloper.microsoft.com` (Microsoft eliminated the \$19 and \$99 onboarding fees in Sept 2025 / May 2026). |
| **Microsoft Store Code Signing (incl. unsigned NuGet DLLs)** | **\$0** | Upload as an **MSIX package**—Microsoft automatically signs your `.exe`s **and** every unsigned NuGet `.dll` (`LibreHardwareMonitorLib.dll`, `Vortice.*.dll`, `NAudio.Wasapi.dll`) for free with Microsoft's Store certificate. *(Pre-signing inner `.dll`s is only required for unpacked `Policy 10.2.9` `.exe` installers).* |
| **GitHub / USB Bench / `winget` Installer Signing** | **\$0** | **SignPath Foundation** (`signpath.org`) signs your `.exe`s and Inno Setup installer for free; SignPath's terms explicitly allow bundling unsigned upstream OSS NuGet `.dll`s inside a signed installer, and Windows SmartScreen only checks the outer installer/`.exe` signatures. |
| **Billing & Checkout** | **\$0 / mo** | **Stripe Checkout** has \$0 monthly fixed fees (only ~2.9% + \$0.30 when a shop pays). |
| **Optional Post-Revenue Upgrade (`Policy 10.2.9` Win32)** | **\$9.99 / mo *(later)*** | Turn on month-to-month **Azure Artifact Signing** (formerly Trusted Signing) *only after* your first \$25/mo Founding Shop customer is already covering it 2.5x over, if you ever want your own publisher name on UAC or an unpacked `Policy 10.2.9` Store installer. |

---

### 4.2 Six Must-Have Additions to Close Paying Customers

Roughly 85% of the core diagnostic engine is already built; closing B2B subscriptions requires adding the **commercial wrapper**:

1. **Open-Source Shop Auth (`ASP.NET Core Identity`), Branding Onboarding & Stripe Billing *(The Cash Register)*:**
   - Replace/supplement Azure AD B2C (retired by Microsoft for new tenants in May 2025) with in-process **`ASP.NET Core Identity` (.NET 10, MIT license)** backed by SQLite (WAL mode) or PostgreSQL—zero extra auth containers or hosting cost, with built-in Passkeys/2FA and free *"Sign in with Google / Microsoft"* OAuth.
   - Use a **2-step, 60-second signup flow** (Step 1: account + Shop Name $\rightarrow$ live `Group` slug check like `acme-pc-repair`; Step 2, skippable/editable in Settings: upload Shop Logo resized to `< 40 KB` WebP `data:` URI + Phone, Website, Address, and Warranty Footer) wired to **Stripe Checkout** (`trialing`/`active` gates `IUserService.GetUserGroups`).
2. **Upgrade `ClientReport.cs` into White-Labeled Hosted Reports & Hardware QA Certificates *(The #1 Sales Hook)*:**
   - **White-Labeled Service Report + Share Link:** Extend `src/RemotePCDiagnostics.Core/Workflow/ClientReport.cs` to accept `ShopBranding` (embedding the shop's inline `data:image/webp;base64,...` logo, contact header, warranty footer, and technician notes so offline HTML/PDFs never break), plus a 1-click **"Publish Report Link"** (`reports.<domain>/r/<short-id>`).
   - **Hardware QA Certificate Mode (for Refurbishers):** A 1-page pass/fail sheet combining **Model/Serial (`osquery`) + Battery Wear % + SMART SSD Health/Power-On Hours + Thermal Stress Pass + Speaker/Mic Loopback Pass + Webcam Pass + GPU/NPU Pass**, with a printable QR sticker/link. Enterprise refurbishment suites (Blancco, PC-Doctor) charge thousands per year for this exact deliverable.
3. **Store `Group` Onboarding & User/Admin Privilege Split:**
   - Add `-g=<group>` to `SessionLaunchOptions` + the **"Connect to Technician"** top-bar dialog in `MainLayout.razor`, switch `src/RemotePCDiagnostics.Host/app.manifest` to `asInvoker`, and ship `RemotePCDiagnostics.Admin` (`--mode=helper`) inside a **\$0 Microsoft-signed MSIX** (`runFullTrust` + `allowElevation`)—upgrading to a self-signed `Policy 10.2.9` Win32 installer later only if needed once revenue-positive.
4. **Finish the `RemotePCDiagnostics.Agent.exe` Service Binary *(Unlocks the \$99–\$199/mo MSP Tier)*:**
   - Build the Windows Service executable (`docs/roadmap.md#1-agent-program`) hosting both `AgentHub.Connect` and `--mode=service` Named-Pipe admin gRPC, and publish it to `winget` (`BudCribar.RemotePCDiagnostics.Agent`).
5. **Two High-Demand Bench Modules Used Daily by Techs & Refurbishers:**
   - **BSOD / Crash & WHEA Analyzer:** Parse `%SystemRoot%\Minidump` headers + `Kernel-Power` (Event 41) + `WHEA-Logger` hardware error logs into plain English (e.g., *"3 blue screens in 14 days caused by `nvlddmkm.sys`"*).
   - **Keyboard Rollover + Display Dead-Pixel / Touch Test:** A 60-second interactive key-matrix check and full-screen solid-color cycle in `RemotePCDiagnostics.UI` to complete 100% of a laptop refurbisher's physical checklist.
6. **One-Click "10-Minute Hardware Intake / QA Check" Preset:**
   - Alongside `WorkflowService`'s existing measure $\rightarrow$ fix $\rightarrow$ reboot $\rightarrow$ re-measure tune-up flow, add a hands-free bench preset (Inventory $\rightarrow$ SMART $\rightarrow$ Battery $\rightarrow$ 3-min Thermal Stress $\rightarrow$ Audio Loopback $\rightarrow$ Webcam $\rightarrow$ BSOD check $\rightarrow$ QA Certificate) so refurbishers can test 10 laptops on a bench simultaneously with minimal clicks.

---

### 4.3 Phased Go-To-Market (GTM) Rollout

#### Phase 1: \$0 Foundation, Free Signing & Store Distribution (Weeks 1–4)

1. **\$0 Store & Open-Source Signing:** Register a free Microsoft Store Developer account (`storedeveloper.microsoft.com`), package the Store build as **MSIX** (free Microsoft signing for all `.exe` and NuGet `.dll` files), and apply to **SignPath Foundation** (`signpath.org/apply.html`) for free signing of standalone GitHub Release / `winget` installers. *(Defer \$9.99/mo Azure Artifact Signing until post-revenue).*
2. **Microsoft Store Listing (ASO):**
   - Target high-intent, non-spammy search terms (up to 7 search phrases per Policy `10.1.3`): *PC diagnostics*, *hardware stress test*, *SSD drive health*, *webcam microphone test*, *remote PC support*, *laptop battery check*, *system repair*.
   - Keep screenshots and copy strictly factual (Policy `10.1.1`): highlight transparent Windows native tools (`osquery`, `DISM`, `SFC`), thermal-safe stress testing, and explicit local-owner session controls.
3. **`winget` Packages for Technicians & MSP RMMs:** Publish `BudCribar.RemotePCDiagnostics` and `BudCribar.RemotePCDiagnostics.Agent` (declaring `namazso.PawnIO` under `PackageDependencies`) to `microsoft/winget-pkgs` so MSPs can deploy unattended fleet access, zero-UAC admin repairs, and full `PawnIO` hardware sensors silently with a single RMM command.

#### Phase 2: Repair Shop & Refurbisher Wedge (Weeks 5–10)

1. **Ship the Two "Money Deliverables":** White-Label Client Service Reports and Serial-Number Hardware QA Certificates with hosted verification links.
2. **Direct Outbound + Community Seeding:** Execute the segment-by-segment sales playbook in [Section 4.4](#44-tactical-b2b-sales-playbook-how-to-get-your-first-50-paying-shops) to sign the first 25 "Founding Shop" subscribers (\$25/mo locked for life in exchange for feedback and testimonials).

#### Phase 3: Product-Led Viral Loop & Fleet Retention (Months 3–6)

1. **Report Footer Attribution:** Every free and lower-tier exported Service Report / QA Certificate includes a clean *"Diagnosed & Verified with Remote PC Diagnostics"* badge linking to the product page. Every customer invoice or refurbished laptop listing becomes a warm impression.
2. **One-Click Tenant Agent Builder:** On the paid Admin Portal's **Computers** page, give subscribed shops a single button (and copyable `winget` RMM snippet) pre-bound to their tenant `group` and `enrollment_key` for recurring customer care plans.

---

### 4.4 Tactical B2B Sales Playbook (How to Get Your First 50 Paying Shops)

Do **not** buy Google or Facebook ads—ad clicks for *"PC diagnostics"* or *"PC repair"* attract consumers with broken computers looking for free help, not technicians. Use three zero-ad-spend channels where every lead is already a buyer:

#### Wedge 1 — Laptop Refurbishers on eBay, BackMarket, Swappa & Whatnot *(Fastest Cold-Outreach Close)*

- **Where to pull 200 leads in 1 hour:** Search eBay, Swappa, and BackMarket for *"ThinkPad T14 Grade A refurbished"* or *"Dell Latitude 5420 refurbished"*. Filter for sellers with **200–10,000 feedback** who manually type `"Battery: Good, 512GB SSD"` in plain text instead of attaching a QA report. Pull their contact email/phone from eBay Business Seller Info or their matching Shopify storefront.
- **Prep 1 live asset & send 10 messages/day:** Run the 10-minute QA check on a real laptop, host one live sample **Hardware QA Certificate** (`Serial + Battery 89% + NVMe 99% + Thermal Stress Pass + Webcam/Mic/Speaker Loopback Pass + QR Code`), and send:
  > *"Hey [Name] — saw your ThinkPad T14 listings and noticed you type battery/SSD health manually in each description. I built an MIT-open-source Windows tool that tests Battery, SMART, Thermal Stress, Webcam, Mic-to-Speaker loopback, and Keyboard in 10 minutes off a USB stick and prints a QR-verified Hardware QA Certificate buyers can scan right in your listing photos (like Carfax for laptops, without Blancco's \$3k contract). Here's a live sample: [link]. Local tool is free forever; hosted QR certificates with your logo are \$39/mo. Want a free 30-day shop login?"*

#### Wedge 2 — Independent PC Repair Shops & Solo Mobile Techs *(Recurring Core)*

- **Record one 60-second silent-friendly Loom/GIF demo:**
  - **0:00–0:25:** Customer opens Microsoft Store (zero SmartScreen warning), clicks Install, types `acme-repair`, and appears on the technician's browser dashboard with live voice.
  - **0:25–0:60:** Technician runs the workflow and clicks **Publish Report** $\rightarrow$ outputs a branded **Before/After Service Report** (`ClientReport.cs`) with the shop's logo, boot/RAM/disk improvements, and plain-English summary of fixes applied.
- **Two distribution motions:**
  1. **Technician Communities (Lead with the Free MIT Tool—Never Hard-Sell):** Post in **Technibble** (*Computer Repair Tools*), `r/computertechs`, **The Tech Tribe**, and `r/msp` open-source/vendor threads: *"I got tired of juggling CrystalDiskInfo + FurMark + HWiNFO + manual tune-up notes, so I open-sourced an all-in-one Windows bench & before/after report tool (MIT, no ads, runs off USB or Store). Looking for 15 shop owners to roast it."* Technicians respect inspectable MIT code; your hosted relay + white-label report tier converts naturally when they ask about remote sessions and custom branding.
  2. **Local Google Maps Outbound:** Target independent 1-to-5 person `"computer repair"` shops with 50+ reviews (skip Geek Squad/uBreakiFix franchises). Email the owner the 60-second GIF with one hook: *"Stop talking elderly clients past SmartScreen warnings or explaining what `DISM`/`SFC` did on a \$129 tune-up invoice."*

#### Wedge 3 — PC Repair & Refurbishment YouTubers *(Inbound Multiplier)*

- Mid-sized repair creators (*Salem Techsperts*, *Parts-People*, *Electronics Repair School*, ThinkPad refurbishment/flipping channels) film laptop diagnostics weekly across 5 separate utilities.
- DM 15 creators offering a **free lifetime white-labeled Pro account** preloaded with their channel logo on the Hardware QA Certificate. Live thermal curves, speaker-to-mic loopback visuals, and a printable scorecard film well on camera—one video from a 50k-subscriber repair channel can drive 100+ shop trials.

#### Pricing Wedge for First 25 Customers

- Offer a **"Founding Shop Tier" (\$25/month locked for life, normally \$39/month)** to the first 25 shops who upload their logo and run 5 real customer machines. Twenty-five Founding Shops generate **\$625/month MRR** (covering hosting costs ~20x over), real shop testimonials, and direct feedback on what makes them renew.

---

### 4.5 First 5 Concrete Steps (\$0 Out-of-Pocket Execution Plan)

Ordered so you spend **\$0 up front** and get a sellable product into buyers' hands within Week 1–2:

1. **Step 1 — \$0 Store Registration & Free SignPath Foundation Prep *(Day 1 — Async Lead Time)*:**
   - Open your **free Microsoft Store Developer account** at `storedeveloper.microsoft.com` (\$0 for both Individual and Company accounts).
   - Enable GitHub 2FA, switch `budcribar/RemotePCDiagnostics` to **Public**, add the required `## Code signing policy` section to `README.md` (describing `SecurityAuditModule` / `HardeningKitty` strictly as local Windows CIS configuration compliance), publish one unsigned release from GitHub Actions, and apply to **SignPath Foundation** (`signpath.org/apply.html` — \$0) for standalone installer signing.
2. **Step 2 — Ship White-Labeled `ClientReport` + Hosted Hardware QA Certificate *(Week 1 — \$0)*:**
   - Extend `src/RemotePCDiagnostics.Core/Workflow/ClientReport.cs` with shop logo/contact headers + technician notes, build the **1-page Hardware QA Certificate** (Model/Serial + Battery % + SMART + Stress + Audio Loopback + Webcam + QR link) + quick Keyboard/Dead-Pixel bench check, and add a hosted report endpoint (`reports.<domain>/r/<id>`).
   - *Why this comes second:* Refurbishers run bench checks locally off a USB stick—giving you a sellable \$39/mo product and a live sample QR certificate in **Week 1** before Microsoft Store certification even finishes.
3. **Step 3 — Wire `ASP.NET Core Identity` Shop Signup, Branding Upload, `Group` Onboarding & Stripe Checkout *(Week 2 — \$0)*:**
   - Implement `ShopIdentityAuthorization : IRelayAuthorization` + `IUserService` using **MIT `ASP.NET Core Identity` + SQLite/PostgreSQL**, with a 2-step signup wizard (Shop Name/`Group` slug + skippable Logo/Phone/Website/Warranty upload) and **Stripe Checkout** (\$0/mo fixed cost).
   - Add `-g=<group>` to `SessionLaunchOptions.cs` + **"Connect to Technician"** in `MainLayout.razor`, validate active tenant groups on `RemoteWebViewService`, and serve `GET /api/shops/{group}/branding` so client apps display the shop's logo on connect and embed it inline in reports.
4. **Step 4 — De-Elevate `Host.exe` (`asInvoker`), Build `Admin.exe --mode=helper` & Publish Free MSIX to Microsoft Store *(Weeks 3–4 — \$0)*:**
   - Switch `src/RemotePCDiagnostics.Host/app.manifest` to `asInvoker`, move privileged operations into the Named-Pipe gRPC helper (`--mode=helper --parent-pid=<pid>`), verify zero `.sys` drivers in publish output, and upload to Partner Center as an **MSIX** (`runFullTrust` + `allowElevation`). **Microsoft signs all your `.exe`s and every unsigned NuGet `.dll` for \$0.** *(If Partner Center ever declines `allowElevation`, publish `runFullTrust`-only MSIX for \$0 immediately, and turn on \$9.99/mo Azure Artifact Signing + `Policy 10.2.9` Win32 installer only after your first \$25/mo Founding Shop pays you).*
5. **Step 5 — Record the 60-Second Demo & Close Your First 10–25 Founding Shops (\$25/mo) *(Weeks 4–5 — Before Building `Agent.exe`)*:**
   - Host 1 live sample Hardware QA Certificate, record the 60-second Store-to-Report Loom/GIF, send 10 refurbisher messages/day, post the open-source showcase on Technibble / `r/computertechs`, and DM 15 repair YouTubers. **Defer building the unattended `Agent.exe` Windows Service (`--mode=service`) and `winget` RMM bundle until your first paying shops ask for recurring fleet monitoring.**

---

## 5. Technical Architecture: User/Admin Split, gRPC & Microsoft Store Strategy

### 5.1 Why Split User Mode and Admin Mode

Currently `RemotePCDiagnostics.Host` sets `<requestedExecutionLevel level="requireAdministrator" />` in `src/RemotePCDiagnostics.Host/app.manifest`, running the WPF shell, Chromium WebView2, Blazor UI, and `RemoteBlazorWebView` inside an elevated process.

Splitting into a **User-Mode UI Client (`asInvoker`)** and an **Elevated gRPC Backend** solves major technical and Store problems at once:

1. **Gets WebView2 & Remote UI out of Administrator mode:** Running WebView2 elevated is discouraged by Microsoft—it breaks Explorer drag-and-drop via UIPI, expands attack surface, and points `%LOCALAPPDATA%` / `HKCU` at the *admin* account rather than the signed-in standard user whenever UAC prompts for separate admin credentials.
2. **Matches natural Windows session boundaries:**
   - **Belongs in the User-Mode UI Process (`Medium` integrity, interactive user session):** WebView2 & `RemoteBlazorWebView`, WebRTC `--voice`, `HKCU` startup optimizations, browser `Local State` inspection, WASAPI speaker/microphone tests, WinRT `MediaCapture` webcam test, Direct3D 12 / DXCore NPU & GPU tests, battery/power reads, and unprivileged `osqueryi.exe` tables.
   - **Belongs in the Elevated gRPC Backend (`High` / `LocalSystem` integrity):** `DISM` and `SFC` repairs, `IServiceControlBackend` (`ServiceController` start/stop/start-type with `ServiceProtection` enforced server-side), `HKLM` policy/remediation writes, `%ProgramData%\RemotePCDiagnostics\state` (`ProtectedState` change journal & workflow state), Windows Event Log source creation and privileged log queries, `HardeningKitty` baseline checks that read security policy, and admin-only SMART / `LibreHardwareMonitor` fan & MSR sensors.
3. **Reuses existing seams in `RemotePCDiagnostics`:**
   - `RemotePCDiagnostics.Core` already isolates OS mutations behind interfaces (`ISensorProvider`, `IServiceControlBackend`, `IMemorySystem`, `ISystemSettings`, `IProcessLauncher`).
   - `IHostQueries` (`src/RemotePCDiagnostics.Core/Plugins/HostQueries.cs`) already proxies `sensors.read`, `storage.drives`, `osquery.select`, and `eventlog.query` across process boundaries.
   - `RemotePCDiagnostics.Agent` (`src/RemotePCDiagnostics.Agent/Protos/agent.proto`) already establishes the gRPC service footprint.

```mermaid
flowchart LR
    subgraph UserSession["Interactive User Session (Medium Integrity / asInvoker)"]
        UI["RemotePCDiagnostics.Host<br/>(WPF + Blazor + WebView2)"]
        ModHost["ModuleHost / ModuleUiHost<br/>(Restricted Token)"]
        UserHW["User-Mode APIs<br/>(WASAPI, Webcam, D3D12/NPU,<br/>HKCU, WMI, User osquery)"]
        UI --> UserHW
        UI <--> ModHost
    end

    subgraph PrivBoundary["Elevated Process or Windows Service (Admin / SYSTEM)"]
        GrpcSrv["Elevated gRPC Server<br/>(On-Demand Helper or Agent Service)"]
        PrivOps["Privileged Operations<br/>(DISM/SFC, SCM + ServiceProtection,<br/>HKLM, ProtectedState, Admin LHM/SMART)"]
        GrpcSrv --> PrivOps
    end

    subgraph Cloud["Hosted SaaS Infrastructure"]
        Relay["RemoteWebViewService Relay<br/>(UI Mirror, TURN Voice, AgentHub)"]
    end

    UI <-->|"gRPC over Named Pipe<br/>(ACL + PID/Identity Check)"| GrpcSrv
    UI <-->|"HTTPS / WSS / WebRTC"| Relay
    GrpcSrv -.->|"Outbound gRPC Stream<br/>(When running as Agent Service)"| Relay
```

---

### 5.2 Approaches That Do *Not* Work (OS, Driver License & Store Policy Pitfalls)

Before locking in the packaging design, avoid four dead ends:

1. **Downloading an Extension `.dll` to add Admin functionality fails on both Windows and Store rules:**
   - **OS boundary:** Windows UAC tokens exist at the **process (`.exe`)** boundary, never at the DLL boundary. If a user-mode server downloads and loads `AdminExtension.dll` into `AssemblyLoadContext`, that code **still runs as a standard user** (`Access Denied` on `sfc`, `dism`, `HKLM`, and SCM). Conversely, if the host process was *already* elevated, hiding code in a downloaded DLL didn't avoid Store elevation review—and created an elevated remote-code-loading risk.
   - **Store Policy `10.2.2`:** Explicitly prohibits changing or extending core/privileged functionality after certification via *"dynamic inclusion of code"*.
   - **Filesystem boundary:** MSIX `WindowsApps` directories are immutable, and `%ProgramFiles%\RemotePCDiagnostics\modules` requires prior elevation to write.
2. **A separate user-mode gRPC server is unnecessary for non-admin hardware access:**
   - Desktop WPF apps in the Microsoft Store run at `Medium` integrity (normal Win32 user mode, **not** inside a UWP AppContainer). `RemotePCDiagnostics.Host` already has direct access to non-admin WMI, `osqueryi.exe`, WASAPI, WinRT camera, GPU, and NPU APIs without an extra user-mode gRPC hop.
3. **An in-app Store paywall link that downloads an external NT Service or `PawnIO` gets rejected:**
   - **Store Policy `10.1.5`:** Allows post-install add-ons with user consent **"excluding non-Microsoft drivers or NT services."**
   - **Store Policy `10.3.1`:** Requires providing test credentials so Store reviewers can exercise paid/gated flows—putting a prohibited service/driver download behind a paywall still fails certification (and public `winget` URLs cannot be paywalled anyway).
4. **Bundling `PawnIO` (or extracting `PawnIO.sys`) violates Store rules and `PawnIO`'s redistribution license:**
   - **Store Policy `10.2.4`:** Prohibits dependencies on non-Microsoft drivers or NT services (exceptions are considered case-by-case *only* for WHCP-certified hardware vendor drivers; `PawnIO` is attestation-signed, not WHCP-certified).
   - **`PawnIO` license & symlink safety:** The official signed `PawnIO` binary is proprietary freeware whose redistribution permission covers *only* the unmodified `PawnIO_setup.exe` installer—extracting `PawnIO.sys` directly violates its license and causes `\\.\PawnIO` device symlink collisions across tools.
   - **Clean fallback already built:** `LibreHardwareMonitorLib` `0.9.6` in `RemotePCDiagnostics.Host.csproj` already removed legacy `WinRing0.sys` (embedding only inert user-mode PawnIO bytecode blobs used by `LenovoEcFanSource`), and `LhmSensorProvider.Read` falls back automatically to WDDM GPU temperatures (`D3dkmtGpuTemperatureSource`), APU shared-die temps, and WMI/ACPI thermal zones when `PawnIO` is absent.

---

### 5.3 Recommended Strategy: One Codebase, One Dual-Mode Binary, Two Channels

Rather than maintaining separate consumer and MSP codebases, build **one shared `RemotePCDiagnostics.Admin` / `Agent` executable** (`net10.0-windows`) that runs in two CLI modes alongside `RemotePCDiagnostics.Host` (`asInvoker`):

- **`--mode=helper --parent-pid=<pid>` (On-Demand Elevated Helper):** Spawned via `ShellExecute` (`Verb = "runas"`) only when a local user clicks **"Enable Admin Repair Mode"** (one standard Windows UAC prompt). Hosts the Named-Pipe gRPC admin server and exits automatically as soon as `Host.exe` closes.
- **`--mode=service` (Always-On MSP Windows Service):** Runs as `LocalSystem`, combining the `AgentHub.Connect` outbound relay stream (`roadmap.md#1-agent-program`) with the exact same Named-Pipe gRPC admin server—unlocking unattended access and zero-UAC admin repairs.

#### Channel 1 — Walk-In / Break-Fix Customers: Microsoft Store (\$0 MSIX First $\rightarrow$ Optional `Policy 10.2.9` Win32 Later)

| Store Packaging Choice | Up-Front Cost | Needs `rescap:allowElevation`? | Verdict |
| :--- | :--- | :--- | :--- |
| **Stage 1 (\$0 Pre-Revenue Bootstrap): MSIX Package** | **\$0** | **Yes** (or `runFullTrust` only) | **Start here at \$0.** Microsoft automatically signs your `.exe`s **and every unsigned NuGet `.dll`** (`LibreHardwareMonitorLib.dll`, `Vortice.*.dll`, `NAudio.Wasapi.dll`) for free. Submit with `runFullTrust` + `allowElevation` (justifying `DISM`/`SFC`/SCM); if ever declined pre-revenue, ship `runFullTrust`-only MSIX immediately for \$0. |
| **Stage 2 (Post-Revenue Upgrade): Unpacked Win32 Installer (`Policy 10.2.9`)** | **\$9.99/mo** (Azure Artifact Signing) | **No** | **Turn on only after Customer #1 pays you.** Submits a versioned HTTPS URL to your signed Inno Setup installer (`installer/RemotePCDiagnostics.iss`). Installs outside an MSIX container into `%ProgramFiles%`, bypassing `rescap:allowElevation` gatekeeping and showing your own publisher name on UAC. |

- **Keep drivers and NT services 100% out of the Store package:** Exclude `PawnIO_setup.exe`, verify zero `.sys` files exist in `dotnet publish`, and do **not** register a Windows NT Service in the Store build (`Policy 10.2.4`).
- **Still unlocks ~90% of technician repair work:** Even without `PawnIO`, UAC-elevating `Admin.exe --mode=helper` unlocks `DISM`, `SFC`, Windows Service start/stop/restart, protected Event Logs, `HKLM` inspection/fixes, `HardeningKitty` security baselines, and admin NVMe/SATA SMART health, while temperatures use the built-in ACPI + WDDM fallbacks.

#### Channel 2 — Managed MSP Endpoints: Silent `winget` / RMM Fleet Deployment (\$0 Signing via SignPath Foundation)

Employees on MSP-managed corporate PCs (law firms, clinics, accounting offices) are typically **Standard Users without local Admin passwords**—they *cannot* click "Yes" on a UAC prompt. Meanwhile, every MSP already runs a management agent (**Microsoft Intune**, **NinjaOne**, **Datto RMM**, or **ConnectWise ScreenConnect**) as `NT AUTHORITY\SYSTEM` across every managed machine.

The MSP technician pastes **one silent background command** into Intune, NinjaOne, or ScreenConnect:

```powershell
winget install --id BudCribar.RemotePCDiagnostics.Agent --silent --accept-package-agreements --accept-source-agreements --override "install --server=https://relay.yourdomain.com --group=acme-msp --key=<enrollment-key> --consent=unattended"
```

Because the RMM runs as `SYSTEM`, **zero windows, zero installers, and zero UAC prompts appear on the employee's screen.** Within ~15 seconds, three capabilities unlock automatically:

1. **Full `PawnIO` Hardware & EC Fan Sensors:**
   - The `winget` manifest for `BudCribar.RemotePCDiagnostics.Agent` declares `namazso.PawnIO` under `Dependencies: PackageDependencies:`.
   - `winget` automatically downloads, SHA-256 verifies, and silently executes `PawnIO_setup.exe -install -silent` from the official `winget` repository before installing the agent—respecting `PawnIO`'s redistribution license and avoiding Store restrictions.
   - `PawnIoProbe.Check` detects `\\.\PawnIO`, enabling `LhmSensorProvider` and `LenovoEcFanSource` to read Intel/Ryzen CPU MSR die temperatures, voltages, motherboard SuperIO fans, and Lenovo ACPI EC fan RPMs.
2. **Unattended `AgentHub` Fleet Access:**
   - `RemotePCDiagnostics.Agent.exe install ...` writes `%ProgramData%\RemotePCDiagnostics\agent.json` (`group=acme-msp`, enrollment key, `consent=unattended`, writable only by `SYSTEM`/Admins) and starts the `RemotePCDiagnosticsAgent` Windows NT Service.
   - The service holds an outbound `AgentHub.Connect` gRPC stream (`src/RemotePCDiagnostics.Agent/Protos/agent.proto`) to the relay, so every office PC appears **Online** under `acme-msp`'s **Computers** tab on `RemoteWebViewAdmin`. Clicking **Start diagnostics** verifies `manifest.json` + `manifest.sig`, launches the cached app, and opens `/mirror/<session_id>` in the technician's browser.
3. **Zero-UAC Admin Repairs on Locked-Down Employee PCs:**
   - Because `RemotePCDiagnosticsAgent` is already running as `LocalSystem`, it hosts the Named-Pipe gRPC admin server (`--mode=service`) continuously.
   - When `Host.exe` (`asInvoker`) launches on the employee's desktop, it connects directly to that Named Pipe instead of calling `ShellExecute("runas")`—giving the technician full `DISM`, `SFC`, Service, Registry, `HardeningKitty`, and `PawnIO` capabilities even when a restricted Standard User is signed in.

#### Side-by-Side Channel Summary

| Feature | Channel 1: Microsoft Store (Walk-In / Break-Fix) | Channel 2: `winget` / RMM Agent (MSP Fleet) |
| :--- | :--- | :--- |
| **How it's installed** | Customer clicks **Install** in Microsoft Store (\$0 MSIX $\rightarrow$ optional `10.2.9` Win32) | MSP pushes 1 silent `winget` command via Intune / NinjaOne / ScreenConnect |
| **Code signing cost** | **\$0** (Microsoft signs MSIX + all NuGet `.dll`s) | **\$0** (**SignPath Foundation** signs `.exe`s + installer; unsigned NuGet `.dll`s allowed inside) |
| **How tech finds the PC** | Customer enters tech's `Group` code in **Connect to Technician** | PC is permanently listed in tech's `Group` on **Computers** (`AgentHub`) |
| **How Admin repairs run** | On-demand `Admin.exe --mode=helper` (**1 UAC click** by local user) | Always-on `Admin.exe --mode=service` (**Zero UAC**, works on Standard-User PCs) |
| **Kernel Driver (`PawnIO`)** | Excluded (uses WDDM GPU + APU + ACPI thermal fallbacks) | Auto-installed via `winget` dependency (full CPU MSRs + SuperIO/EC fans) |
| **Monetization** | Free Store app (0% Store fee); tech pays \$25–\$39/mo SaaS seat | Tech / MSP pays \$99–\$199/mo SaaS fleet subscription |

---

### 5.4 Mandatory Microsoft Store Certification & Security Rules (`Policies 10.1–10.4`)

To pass Microsoft Store review (Policies v7.20) and prevent Local Privilege Escalation (EoP), enforce six strict rules on the Store build and elevated helper:

1. **Zero UAC at Startup & Full Standard-User Mode (`10.1.2`, `10.3`, `10.4.2`):**
   - Change `src/RemotePCDiagnostics.Host/app.manifest` from `requireAdministrator` to `asInvoker`. Store reviewers automatically reject apps that prompt for UAC on launch.
   - If the user is a Standard User—or clicks **No** on UAC—the app must keep running cleanly in read-only diagnostic mode without crashes or nag loops. Admin actions must carry a shield badge and prompt for UAC **only** when clicked.
2. **No Store NT Service & Automatic Helper Exit (`10.2.4`, `10.4.2`):**
   - Never register a persistent Windows NT Service or Scheduled Task from the Store build.
   - Per `10.4.2`, all app-started processes must exit when the UI closes. Pass `--parent-pid=<HostPid>` and bind `Admin.exe --mode=helper` to a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) so the elevated helper terminates immediately if `Host.exe` closes or crashes.
3. **Zero Local Privilege Escalation (EoP) Surface (`10.2`):**
   - **Named Pipes only** (`ListenNamedPipe("RemotePCDiagnostics.Admin.<SessionId>")`)—never `127.0.0.1` TCP, which untrusted local processes or browser tabs could hit via SSRF/DNS rebinding.
   - Apply strict `PipeSecurity` ACLs (interactive user SID + `Administrators`/`SYSTEM`, denying `Anonymous` and `AppContainer`), and call `GetNamedPipeClientProcessId` on connect to verify the caller process carries your exact **MSIX Package Identity** (for MSIX builds) or **Authenticode signature** (for Win32 builds).
   - **Fixed domain `.proto` allowlist** (`RunDismScanHealth`, `RunDismRestoreHealth`, `RunSfcScanNow`, `ControlService`, `ApplyCatalogFix`, `UndoChange`, `QueryAdminSensors`, `QueryEventLog`) with `ServiceProtection.Protected`, `HostCapabilities.AllowedSql`, and fix-catalog checks enforced server-side. **Never** expose generic `RunCommand` or `RunPowerShell` RPCs.
4. **No Downloaded or Unsigned Code in the Elevated Helper (`10.2.2`):**
   - `Admin.exe` executes only compiled-in or verified built-in modules. Unsigned third-party plugins remain strictly isolated inside the non-elevated `RemotePCDiagnostics.ModuleHost` process (`docs/module-plugins.md`).
5. **Explicit Local User Consent, Supported Windows APIs & Audit Trail (`10.2.8`):**
   - Require explicit local consent (e.g., clicking **"Enable Admin Repair Mode"** locally to trigger UAC, plus displaying a live local repair log) before a remote technician can mutate system settings, and write tamper-evident Windows Event Log entries (`2000–2006`, `1100`, `1400`) from the privileged backend.
   - Never write undocumented Windows user-choice protected registry keys (such as `UCPD.sys`-guarded default browser, file association, or taskbar pinning keys).
6. **Signing Rules by Package Type (MSIX vs. `Policy 10.2.9` Win32):**
   - **MSIX (\$0):** No pre-signing required—Microsoft signs all `.exe` and third-party NuGet `.dll` files in the package upon certification.
   - **Unpacked Win32 (`Policy 10.2.9`, post-revenue optional):** Every shipped `.exe` and `.dll` (`Host.exe`, `Admin.exe`, NuGet `.dll`s, bundled `osqueryi.exe`, and the Inno Setup installer) must be pre-signed with a Trusted Root CA cert (e.g., Azure Artifact Signing), support `/VERYSILENT /SUPPRESSMSGBOXES`, and avoid runtime web downloader stubs.

---

### 5.5 Multi-Tenant Group Onboarding & Single-Relay Isolation

Instead of asking a customer on the phone to read back a long `/mirror/<guid>` URL, one shared `RemoteWebViewService` relay can host many independent technicians and repair shops by routing sessions through **Group codes**:

```mermaid
sequenceDiagram
    participant Cust as Customer PC (Store App)
    participant Relay as Shared Relay (RemoteWebViewService)
    participant Admin as Technician (Admin Website)

    Note over Cust: Opens in Local mode from Microsoft Store
    Cust->>Cust: Clicks "Connect to Technician"<br/>Enters group "acme-repair" (+ optional name)
    Cust->>Cust: Relaunches with -u=<relay> -g=acme-repair --voice --restarted
    Cust->>Relay: CreateWebView(Group="acme-repair", OwnerKey=...)
    Note over Relay: SessionAccessHandler lets local window<br/>open /app/{id} via OwnerKey without login
    Admin->>Relay: GetClients(Oid) -> GetUserGroups(Oid) = ["acme-repair"]
    Relay-->>Admin: Streams ONLY clients where Group == "acme-repair"
    Admin->>Relay: Clicks client card -> opens /mirror/{id}
    Note over Relay: Other technicians outside "acme-repair"<br/>never see the card and get HTTP 403 on /mirror/{id}
```

#### What Already Exists in `RemoteBlazorWebView`

- **Admin Client List Filtering (`ClientIPCService.GetClients`):** Queries `IUserService.GetUserGroups(request.Oid)` for the signed-in technician and returns only connected sessions where `groups.Contains(x.Group)`.
- **Cross-Group URL Isolation (`SessionAccessHandler`):** Refuses (`403 Forbidden`) any signed-in user outside `state.Group` even if they obtain a `/mirror/{id}` link, while allowing the customer's local `MainWindow` to open `/app/{id}` unauthenticated via `OwnerKey`.
- **Client Property (`BlazorWebView.Group`):** Already transmitted in `CreateWebViewRequest.Group` (currently defaulting to `"test"`).

#### Open-Source Shop Auth & Branding Architecture (`ASP.NET Core Identity`)

Rather than deploying a separate heavyweight Java/Go auth server (like Keycloak or Authentik, which adds 512 MB–1 GB+ of container RAM and still cannot host shop branding or report metadata) or relying on Azure AD B2C (retired by Microsoft for new tenants in May 2025), plug **in-process `ASP.NET Core Identity` (.NET 10, MIT license)** backed by **SQLite (WAL mode) or PostgreSQL** directly into `RemoteWebViewService.Lib`'s existing authorization seams:

1. **Drop-In `IRelayAuthorization` + `IUserService` Provider (~60 Lines):**
   - Add `ShopIdentityAuthorization : IRelayAuthorization` (`"Authorization:Provider": "ShopIdentity"`) with cookie/JWT auth, Passkeys/2FA, and free *"Sign in with Google / Microsoft"* OAuth.
   - Implement `IUserService.GetUserGroups(oid)` (mapping `ClaimTypes.NameIdentifier` in `ClaimsPrincipalExtensions.GetUserObjectId`) to return `[shop.GroupSlug]` **only while `ShopTenant.SubscriptionStatus` is `trialing` or `active`**—so `SessionAccessHandler` automatically blocks expired accounts with zero session-routing changes.
2. **2-Step, 60-Second Shop Signup + Branding Upload:**
   - **Step 1 (Account & Group Slug):** Email/Password (or Google/Microsoft) + **Shop Name** (`Acme PC Repair`) $\rightarrow$ live uniqueness check auto-fills `GroupSlug` (`acme-pc-repair`).
   - **Step 2 ("Brand Your Client Reports" — skippable, editable anytime in Settings):** Upload **Shop Logo** (resized to `<= 400x120 px` WebP/PNG, `< 40 KB`, stored alongside a pre-encoded `data:image/webp;base64,...` URI), plus `Phone`, `WebsiteUrl`, `Address`, `DefaultTechName`, and `WarrantyFooter` *(e.g., "90-Day Hardware & Tune-Up Warranty — Call (555) 019-2834")*. Multi-tech shops (\$99/mo) can invite extra technician emails to the same `ShopTenant`.
3. **Live Client Trust Header & Offline-Proof HTML/PDF Reports:**
   - Expose a read-only `GET /api/shops/{group}/branding` endpoint so when a customer installs from the Microsoft Store and enters `acme-pc-repair`, the app header immediately shows **"Connected to [Shop Logo] Acme PC Repair · (555) 019-2834"**.
   - Pass `ShopBranding` (including the inline `data:image/webp;base64,...` logo) directly into `ClientReport.Build` and the **Hardware QA Certificate** so downloaded HTML files, printed PDFs, and hosted QR certificates never suffer from broken external image links.

#### Required Wiring in `RemotePCDiagnostics` & the Relay

1. **In-App "Connect to Technician" Flow (Handling Store Launch + `HostPage` Ordering):**
   - Microsoft Store launches `RemotePCDiagnostics.Host.exe` with no arguments (Local mode), and `BlazorWebView.Group` must be assigned *before* `RemoteBlazorWebView.HostPage` is set.
   - Add a **"Connect to Technician"** button/dialog in the top bar accepting the technician's **Group / Shop Code** (e.g., `acme-repair`) and an optional **Customer Label** (e.g., *"Mary — Front Desk"*, rendered into `RemoteBlazorWebView.Markup` so busy shops can tell waiting PCs apart).
   - Submitting saves the group preference and uses the existing `--restarted` handoff (`SessionLaunchOptions`) to relaunch with `-u=<relay> -g=<group> --voice --restarted`, setting `RemoteBlazorWebView.Group = launch.Group` before `HostPage` in `MainWindow.xaml.cs`.
   - Persist `Group` in `SessionLaunchOptions.RestartArguments` and `PendingRebootState` so browser-triggered restarts and mid-workflow Windows reboots reconnect directly into the same technician's group.
2. **Group Validation & Anti-Spam on Connect:**
   - Entering a group name only *publishes* the customer's own session into that group (unauthenticated clients can never list a group's computers).
   - Validate `request.Group` on the relay against registered active tenant groups (or map short rotating/static 6-character support codes like `ACME42` $\rightarrow$ `acme-repair`) so customer typos fail fast with a clear *"Unknown technician code"* message rather than stranding the session in a nonexistent group.
3. **Unified Group Scoping for `RemotePCDiagnostics.Agent` (`agent.proto`):**
   - Bind each tenant `enrollment_key` on the relay to its owning `group`, filter `AgentAdmin.GetAgents` / `WatchAgents` by `IUserService.GetUserGroups(oid)`, and pass `-g=<group>` in `LaunchCommand`. Both ad-hoc Microsoft Store sessions (**Clients** page) and persistent enrolled endpoints (**Computers** page) then share one multi-tenant relay and authorization model.

---

### 5.6 Recommended Engineering Build Order (Revenue-First, \$0 Out-of-Pocket)

1. **Phase 1 — Commercial Deliverables & Bench Checks (Week 1):** Upgrade `ClientReport.cs` with `ShopBranding` white-labeling + hosted share links, add the **1-page Hardware QA QR Certificate**, ship the Keyboard/Display + BSOD/WHEA bench modules, and add the 1-click **"10-Minute Hardware Intake / QA Check"** preset.
2. **Phase 2 — `ASP.NET Core Identity` Shop Auth, Branding Upload, `Group` Onboarding & Stripe Checkout (Week 2):** Build `ShopIdentityAuthorization : IRelayAuthorization` + 2-step `ShopBranding` signup + `GET /api/shops/{group}/branding` + \$0-fixed-fee Stripe Checkout, add `-g=<group>` to `SessionLaunchOptions` (including `RestartArguments` and `PendingRebootState`), and add **"Connect to Technician"** in `Host`/`UI`.
3. **Phase 3 — De-Elevate `Host.exe` (`asInvoker`) & Build `Admin.exe --mode=helper` (Week 3):** Switch `src/RemotePCDiagnostics.Host/app.manifest` to `asInvoker`, gracefully badge admin-only modules/fixes when un-elevated, and build the Named-Pipe gRPC helper (`PipeSecurity` ACLs, `GetNamedPipeClientProcessId` MSIX Package Identity / Authenticode check, Job Object / `--parent-pid` exit, and local **"Enable Admin Repair Mode"** UAC flow).
4. **Phase 4 — \$0 MSIX Store Launch + SignPath Foundation USB/`winget` Release (Week 4):** Package and submit the driverless **MSIX** (`runFullTrust` + `allowElevation`) to Partner Center for free Microsoft Store signing, and wire **SignPath Foundation** into GitHub Actions for free signing of standalone USB bench / `winget` installers.
5. **Phase 5 — `--mode=service` MSP Fleet Agent (Post-First Paying Customers):** Wire `--mode=service` into `RemotePCDiagnostics.Agent.Core`, scope `AgentAdmin` by tenant `Group`, and publish `BudCribar.RemotePCDiagnostics.Agent` (with `namazso.PawnIO` dependency) to `winget`.
