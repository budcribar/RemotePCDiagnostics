# RPCD browser workflows

Use this guide for the RPCD technician UI. Start in Remote Web View Admin, select the authorized computer, and open its session. Admin account roles govern access to the session. Once in RPCD, use the controls present on the running build. Hardware, Windows privileges, installed modules, and session control can affect availability independently of the Admin role.

Confirm the shop and computer in the header. A second browser can show results while another viewer holds control. For an action, confirm that this viewer is in control, and let the current operator hand control over through the normal UI. Reopen the session from Admin if the link redirects to sign-in or becomes stale. After reconnecting, inspect the existing run before clicking again.

## Dashboard and Checks

Use **Dashboard** for an overview and shortcuts. Dashboard cards can show startup or earlier results. For a fresh individual result, open **Checks**, expand the relevant group, select the named row, verify the details heading, and choose **Run just this**. The **Include** checkbox changes batch selection. Use **Run selected** only when the requested set matches the selected rows. Wait for a terminal status and verify a new completion time or run ID. Inspect details and report missing fields separately. See the [Hardware Inventory walkthrough](hardware-inventory.md) for freshness and recovery.

| Check | What to read |
| --- | --- |
| Hardware inventory | Computer model, CPU model, physical cores and logical threads, installed memory, and physical drives. |
| Temperatures & fans | Sensor and component labels, units, observed temperatures and fan speeds. Missing fan readings mean unavailable. |
| Device Manager & drivers | Device issues, affected devices, and driver details. |
| Drive health | Per-drive status and warnings, with unknown or unsupported readings identified explicitly. This differs from Disk speed test. |
| Resource hogs & uptime | CPU and memory pressure, uptime, and the processes shown as top consumers. |
| Battery & power plan | Health, charge, power source and plan where shown. A missing battery may be expected on a desktop. |
| Network & Wi-Fi | Active adapters and connection details, signal when reported, and errors. This differs from Network stability test. |
| Services | Running services and automatic services that are stopped. Inspect before considering service actions. |
| Windows error log | Counts, time window, event source and affected application where shown. |
| Crashes & unexpected restarts | Preserve the time window for each count. Distinguish crashes, freezes, and unexpected restarts. Older blue-screen results may appear in History. |
| Programs & updates | Windows version, update information, and installed program details where relevant. |
| Security essentials | Report the individual findings and any unavailable checks. |
| Windows component store (DISM) | Report the scan finding and whether repairable corruption was detected. A scan result does not authorize a repair. |
| Protected system files (SFC) | Report verification findings. Keep verification and repair separate. |
| NPU (AI accelerator) test | Locate the check if the build and hardware expose it. Report detection and the test result separately. |

Some details pages have sortable tables, drawers, review marks, service actions, remediation, and diagnostic evidence tools. Open drawers to read the underlying findings. Treat marking reviewed, starting or stopping services, applying repairs, copying data for external review, and sending evidence to Copilot as separate user-directed actions.

## Other RPCD screens

| Screen | Workflow and evidence |
| --- | --- |
| Stress tests | Verify the intended CPU, memory, disk speed, GPU, or network stability test and selected scope. Run only the requested test or suite. Record measurements and units, each terminal outcome, and cancellation or skipped tests. Check the suite still has control after reconnecting. Use a designated test machine for release verification because stress tests can load the PC. |
| Interactive tests | Choose the individual test or verify the exact selection before starting. Coordinate with the person at the PC when physical input, a visual judgment, or audio is required. Capture the test's measured evidence separately from a person's pass or fail judgment. |
| Security audit | Open the audit and read its findings, severity, and unavailable sections. Review the details of each requested check. Keep remediation separate from inspection. |
| Benchmark | Select the measurements, run and record the **before** baseline, then use the matching **after** pass. Compare like-for-like metrics and units. Record whether each pass included a restart. Use a restart action only when explicitly requested, and verify the pending phase before resuming. **Start over** clears the comparison. |
| Service workflow | Run the diagnostics phase, inspect the findings and proposed fixes, and verify exactly which actions are selected. The action that starts restart, benchmark, fixes, and reporting changes the PC. Review the scope with the user before starting. Follow progress through reconnects, and report completed, skipped, and failed actions separately. Let the user handle Windows credentials directly. |
| QA & branding | Inspect the bench QA scope before running it. Keep QA results, branding changes, and certificate generation or sharing as separate tasks. Verify the branding preview before a requested save. Verify the finished certificate and requested output destination before export or sharing. |
| History | Identify the computer, check name, capture time, and status before reading an earlier run. Attribute every historical result to its timestamp. For a requested export, verify the scope and destination first. |
| About | Read the app version and any available build details. Use the running RPCD version to choose a tested guide. |

For **Keyboard**, compare layout candidates with the actual keyboard and have the person at the PC confirm the layout and press the keys. Browser-generated key presses are not physical keyboard evidence. For **Display**, have the person look at the panel and report defects. For **Webcam**, verify the selected device and ask the person to confirm the preview and outcome. For **Speaker to microphone** and **Microphone to speaker**, verify the direction and devices, coordinate playback or speech with the person, and record what was measured and what they confirmed. Treat reset, pass with note, failure, cancellation and unavailable hardware as distinct outcomes.

## Metadata and verification

See the [page-by-page browser contract plan](browser-contract.md) for existing selectors, proposed additions, and release test requirements.

Use the [inventory metadata proposal](hardware-inventory.md#proposed-browser-metadata) across diagnostics. Add stable IDs for the screen, check, action and result fields. For batch actions, expose the selected check IDs and the accepted run ID for each check. Expose exact timestamps, result source, explicit units, and separate missing values from zero. For interactive tests add a waiting-for-person state and the source of the recorded outcome. For restarts and workflows expose the pending phase and action scope. For remote sessions expose whether the viewer has control and whether the session is connected. Keep credentials and session tickets out of metadata.

Before release, check every navigation destination and exercise each read-only check where hardware permits. Use a test machine and a person at the PC to verify interactive tests, and a disposable setup for repairs, restarts and state changes. Include earlier results, failures, unavailable hardware, view-only mode, reconnects and two runs in the same minute. Record app version, workflow, starting state, observed transitions, final result and which steps needed a person.

### Live verification on BUDSLAPTOP

Hardware Inventory previously ran to completion in the remote browser. In the follow-up TestShop session, I verified page content for Checks, Service workflow, Stress tests, Interactive tests, Security audit, Performance benchmark, QA & branding, History, and About. The Dashboard link left the prior screen visible, so Dashboard navigation remains unverified.

The remote browser sometimes still showed the prior page immediately after navigation. Wait for the exact destination heading or a unique page marker before reading results or clicking actions. A completed link click alone does not establish that the destination is ready.

Dashboard baseline on build `1.2.0-ci.650.1+db0628f92a0f5cf792b32ea6b972c4300d71a7b5`: the Dashboard anchor had an empty `href` when inspected from both About and Checks. After clicking from each screen, the browser path and heading stayed on the starting page. No `dashboard-title` appeared within five seconds. Add a regression check that Dashboard navigates from both routes and renders its destination marker.

The follow-up verified navigation and visible controls. It did not verify fresh runs beyond the earlier Hardware Inventory test. Benchmark's no-restart option was visible, and the After pass was disabled without a baseline. Interactive batch start was disabled in the observed state; the reason was not verified. History grouped earlier results by day and displayed outcome counts. About showed version 1.2.0 and a separate build version field.
