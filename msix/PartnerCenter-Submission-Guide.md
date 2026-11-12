# Microsoft Partner Center Submission Guide — Remote PC Diagnostics (`$0` MSIX Store Path)

> **Account Status Reminder:** Once your Microsoft Partner Center developer account opens, publish your first submission **within 90 days** to keep the account active permanently. Partner Center signs the `.msix` package with Microsoft's trusted Store certificate for **$0** (eliminating SmartScreen warnings on `RemotePCDiagnostics.Host.exe` and every bundled `.dll` with zero EV certificate cost).

---

## Step 0: 1-Click GitHub Actions Build (No Local Windows SDK Required)

As soon as Partner Center opens and you reserve the app name **`Remote PC Diagnostics`**, navigate to **Product management → Product identity** in Partner Center and copy two values:

1. **`Package/Identity/Name`** (for example: `12345BudCribar.RemotePCDiagnostics`)
2. **`Package/Identity/Publisher`** (for example: `CN=A1B2C3D4-E5F6-7890-ABCD-1234567890AB`)

### Option A — Instant 1-Click `workflow_dispatch` Run (Fastest)
1. Open **[GitHub Actions → CI](https://github.com/budcribar/RemotePCDiagnostics/actions/workflows/ci.yml)** in your browser.
2. Click **Run workflow** (branch: `main`) and paste your two Partner Center values:
   - **`msix_identity_name`**: `<your Package/Identity/Name>`
   - **`msix_publisher`**: `<your CN=... Publisher string>`
   - **`release_tag`**: *(leave empty for a Store submission build, or enter e.g. `v1.2.0` to also publish a tagged GitHub Release)*
3. Click **Run workflow**. When the run turns green (~10–14 minutes), scroll to the **Artifacts** section at the bottom of the workflow summary page and download:
   - **`RemotePCDiagnostics-Msix-win-x64`** → extract `RemotePCDiagnostics-1.2.0-win-x64.msix` and drag it straight into Partner Center (**Packages**)!
   - **`partner-center-screenshots`** → extract the four `1920x1080` PNG desktop screenshots and drag them straight into Partner Center (**Store listings → Screenshots**)!

### Option B — Save Once as Repository Variables (Automatic on Every Push)
So you never have to paste those values again on future updates, save them once under **GitHub Repo → Settings → Secrets and variables → Actions → Variables**:
- `MSIX_IDENTITY_NAME` = `<your Package/Identity/Name>`
- `MSIX_PUBLISHER` = `<your CN=... Publisher string>`

Every subsequent `main` build and release will automatically stamp your exact Partner Center identity into `AppxManifest.xml`.

*(Equivalent CLI one-liner if you use `gh` locally:)*
```bash
gh workflow run ci.yml --repo budcribar/RemotePCDiagnostics \
  -f msix_identity_name="12345BudCribar.RemotePCDiagnostics" \
  -f msix_publisher="CN=00000000-0000-0000-0000-000000000000"
```

---

## Step 1: Application Overview & Properties

| Partner Center Field | Copy-Paste Value |
| :--- | :--- |
| **Reserved App Name** | `Remote PC Diagnostics` |
| **Package Type** | **MSIX / PWA** *(do NOT select "EXE or MSI installer" — MSIX gives you Microsoft's trusted Store signature + automatic background updates)* |
| **Primary Category** | `Utilities & tools` |
| **Subcategory** | *(Leave blank / None)* |
| **Pricing** | **Free** |
| **Markets** | All markets *(or exclude any region where you prefer not to distribute)* |
| **System Requirements** | Windows 10 version 19041.0 or higher (`x64`), 4 GB RAM minimum (8 GB recommended) |
| **Privacy Policy URL** | `https://github.com/budcribar/RemotePCDiagnostics#privacy--security-policy` |
| **Website URL** | `https://github.com/budcribar/RemotePCDiagnostics` |
| **Support Contact / URL** | `https://github.com/budcribar/RemotePCDiagnostics/issues` |

---

## Step 2: Store Listing Copy (`en-US`)

### Short Description *(Max 200 characters — 178 chars below)*
```text
Complete Windows 10/11 hardware diagnostics, thermal-safe stress tests, 10-minute refurbisher QA with scannable QR certificates, before/after speedup reports, and remote support.
```

### Full Store Description *(Copy-Paste Ready)*
```text
Remote PC Diagnostics is an open-source (MIT) Windows 10 and Windows 11 hardware diagnostic, bench QA, and system health suite built for PC owners, repair shops, laptop refurbishers, and IT support technicians.

It launches immediately in Standard User Mode with zero sign-in, zero account required, and zero upfront UAC prompt—so anyone can inspect hardware health, run benchmarks, verify refurbished laptops, or share a live diagnostic session with a trusted technician in seconds.

KEY CAPABILITIES

• Instant Hardware & System Health Overview
Inspect SMBIOS system details, CPU/GPU/RAM configuration, NVMe & SATA SMART drive health, laptop battery wear and cycle history, device driver errors, WHEA hardware error logs, recent BSOD/application crashes, startup resource hogs, and Windows security posture.

• Thermal-Guarded Stress Tests & Benchmarks
Verify stability under load with dedicated CPU, memory, disk speed, GPU, NPU, and network tests featuring automatic thermal safety cutoffs. Measure real-world system responsiveness before and after maintenance.

• 10-Minute Laptop Refurbisher Bench QA & Buyer QR Certificates
Run an automated intake pass covering SMBIOS, SMART, battery wear, WHEA errors, short thermal burn-in, dongle-free WASAPI speaker-to-mic audio loopback, webcam framing, full-key NKRO keyboard matrix testing, and dead-pixel display checks—then export a 1-page printable HTML/PDF Buyer Hardware QA Certificate with a scannable QR code.

• Guided Windows Repair & Before/After Client Service Reports
Unlock optional Admin Repair Mode on demand (via standard Windows UAC) to run DISM component store checks, System File Checker (SFC), startup cleanup, and safe system optimizations—complete with a plain-English Before/After HTML report showing exact measured speedups and reversible change history.

• Optional "Connect to Technician" Remote Diagnostics
Working with a PC repair shop or IT helpdesk? Enter your technician's Shop Code to verify their shop identity and collaborate in a live, user-controlled diagnostic session over HTTPS with zero inbound firewall ports.

PRIVACY & TRANSPARENCY
• 100% usable locally offline with zero account or registration.
• Zero telemetry, ads, or background services in the Store package.
• No diagnostic data leaves your PC unless you explicitly connect to a technician's relay server or publish a hosted QR certificate.
• MIT-licensed open-source software: https://github.com/budcribar/RemotePCDiagnostics
```

### What's New in This Version *(Release Notes)*
```text
• Standard User Mode (asInvoker) instant launch with on-demand "Enable Admin Repair Mode" UAC helper for DISM/SFC system repairs.
• 10-Minute Hardware Intake / Bench QA preset with interactive Keyboard NKRO, Display Dead-Pixel check, dongle-free WASAPI audio loopback, and 1-page Buyer QR Certificates.
• "Connect to Technician" Shop Code verification dialog for customer-initiated remote diagnostic sessions.
```

### Key Features *(Bullet List Fields in Partner Center, up to 20 bullets, max 200 chars each)*
1. `Instant hardware inventory, NVMe/SATA SMART drive health, battery wear, and WHEA error checks`
2. `Thermal-safe CPU, RAM, Disk, GPU, and Network stress tests with live sensor monitoring`
3. `10-Minute Refurbisher Bench QA with Keyboard NKRO, Dead-Pixel, Webcam, and WASAPI audio tests`
4. `Export 1-page Buyer Hardware QA Certificates with scannable verification QR codes`
5. `Guided DISM & SFC Windows repair workflow with Before/After client HTML speedup reports`
6. `Launches in Standard User Mode without UAC; optional Admin Repair Mode on demand`
7. `Optional Connect to Technician mode with verified Shop Code identity`

### Search Keywords *(Partner Center Strict Limit: Max 7 terms, max 30 chars each, <= 21 words total)*
1. `pc diagnostics`
2. `hardware test`
3. `ssd smart health`
4. `battery health check`
5. `cpu stress test`
6. `pc repair tool`
7. `system benchmark`

*(7 terms, 17 words total — 100% within Partner Center's 7-term / 21-word cap.)*

---

## Step 3: Screenshots (`partner-center-screenshots` CI Artifact)

Upload all four `1920x1080` PNG files from the **`partner-center-screenshots`** GitHub Actions artifact under **Store listings → Screenshots → Desktop**:

| Order | File Name | Suggested Partner Center Caption *(Max 200 chars)* |
| :---: | :--- | :--- |
| **1** | `01-dashboard-overview.png` | `Full Windows 10/11 hardware diagnostics, SMART drive health, battery wear, and 1-click 10-Minute Bench QA—running immediately in Standard User Mode.` |
| **2** | `02-bench-qa-and-qr-certificate.png` | `10-Minute Refurbisher Bench QA with Physical Keyboard/Display verification, custom Shop Branding, and 1-page Buyer Hardware QA QR Certificates.` |
| **3** | `03-connect-to-technician.png` | `Optional Connect to Technician workflow: verify your repair shop's code before opening a user-controlled remote diagnostic session.` |
| **4** | `04-service-workflow-report.png` | `Automated Service Workflow: scan all checks, review recommended fixes once, and generate a Before/After client speedup report.` |

---

## Step 4: Age Ratings (`IARC` Questionnaire)

Select **Utilities / Productivity** as the app type and answer **"No"** to every content question:
- Violence, Blood, Fear, Sexual Content, Profanity, Controlled Substances, Gambling: **No**
- Does the app allow users to interact or exchange content with random other users online (open chat / forums / UGC)? **No** *(Technician sessions are private, point-to-point diagnostic sessions initiated only with a known Shop Code.)*
- Does the app share the user's physical location with other users? **No**
- Does the app allow purchase of digital goods inside the app? **No**
- Does the app provide unrestricted web browsing? **No**

Expected Result: **IARC `3+` / ESRB `Everyone`**.

---

## Step 5: Restricted Capabilities & Commerce Compliance (`10.2.9`, `10.8.1`, `10.8.6`)

### Restricted Capabilities Declaration (`Submission options`)
Partner Center will prompt you to explain the two restricted capabilities declared in `AppxManifest.xml` (`rescap:runFullTrust` and `rescap:allowElevation`). Paste this exact declaration:

```text
Remote PC Diagnostics is a native .NET 10 WPF desktop hardware diagnostic and Windows repair utility:
1. runFullTrust: Required to query local Windows WMI/SMBIOS hardware inventory, NVMe/SATA SMART storage health, battery wear telemetry, Windows Event Logs (WHEA/crashes), WASAPI audio loopback, and bundled read-only diagnostic helpers (osqueryi.exe, HardeningKitty). The package contains ZERO kernel-mode (.sys) drivers and installs ZERO background Windows services.
2. allowElevation: The main application (RemotePCDiagnostics.Host.exe) launches as a Standard User (asInvoker) with no UAC prompt. Elevation (RemotePCDiagnostics.Admin.exe via ShellExecute "runas") is invoked ONLY when the user explicitly clicks "Enable Admin Repair Mode" or "Relaunch as Administrator" to run Windows system maintenance tools (DISM.exe /ScanHealth, sfc.exe /verifyonly, and user-approved Windows repairs).
```

### Commerce Positioning (`Policy 10.8.1` & `10.8.6`)
- **Zero In-App Purchases / Zero Payment Links in the Store Binary:** Every local diagnostic check, stress test, benchmark, Before/After service report, Shop Branding customization, and offline Buyer QR Certificate works **100% free forever** inside the app with no paywall, no trial timer, and no external checkout links.
- **External B2B Multi-Seat Relay Infrastructure:** Repair shops and MSPs that operate a multi-technician `RemoteBlazorWebView` relay server configure their external Server URL / Shop Code or enterprise API key outside the Store app (B2B organizational infrastructure under Microsoft Store Policies `10.8.1` / `10.8.6`).

---

## Step 6: Notes for Certification Reviewers *(Copy-Paste Into "Notes for certification")*

Paste the block below verbatim into **Submission options → Notes for certification**:

```text
TESTING & CERTIFICATION NOTES FOR MICROSOFT STORE REVIEWERS

1. ZERO SIGN-IN / FULL OFFLINE LOCAL MODE (DEFAULT):
   • No account, login, license key, or network connection is required to test Remote PC Diagnostics.
   • Launch the app and test any feature directly: Dashboard ("Run all checks"), Checks, Stress tests, Security audit, Benchmark, Service workflow, and QA & branding (/certificates -> "Save 1-page HTML certificate" + live QR preview).

2. STANDARD USER LAUNCH (Policy 10.2.9 Compliant — asInvoker, Zero .sys Drivers):
   • RemotePCDiagnostics.Host.exe runs as a Standard User (executionLevel="asInvoker") with zero upfront UAC prompt, zero bundled .sys kernel drivers, and zero persistent background services.
   • Hardware inventory, SMART health, battery wear, stress tests, Physical Keyboard/Display QA, and Buyer QR Certificate generation all run without Administrator privileges.

3. OPTIONAL ON-DEMAND ELEVATION ("Enable Admin Repair Mode" — rescap:allowElevation):
   • Clicking "Standard User · Enable Admin Repair" in the top bar (or on the Service workflow page) opens an explanation dialog.
   • Only if the user clicks "Enable Admin Repair Mode" or "Relaunch as Administrator" does Windows display a standard UAC consent prompt for RemotePCDiagnostics.Admin.exe so privileged Windows tools (DISM /ScanHealth, SFC, and user-approved system repairs) can run. Declining UAC leaves the app running normally in Standard User Mode.

4. OPTIONAL "CONNECT TO TECHNICIAN" REMOTE SUPPORT FEATURE:
   • The top-bar "Connect to Technician" button is strictly an optional, user-initiated remote support feature for end users working with an IT helpdesk or PC repair shop (similar to Quick Assist).
   • Nothing connects to any external server unless the user enters a Shop Code and clicks Connect. Reviewers can inspect the modal UI and test all diagnostics locally without a relay server.
```
