# RPCD browser contract plan

The first implementation renders `data-rpcd-page` on page headings or on a hidden marker for module and audit routes. Use a DOM query for those hidden markers. Checks and Stress have distinct values. Checks details expose the check ID, run state, result source, run and result IDs for DiagnosticsService runs, and an exact completion timestamp. History rows expose the module and exact timestamp. About exposes the build version. The workflow heading exposes its stage. The application shell exposes the full `data-rpcd-version` and initializes `data-rpcd-control` and `data-rpcd-connection` to `unknown`. Each mirror updates its own shell from the relay. The table below includes further proposals.

Give each rendered page one `data-rpcd-page` marker on its content root. Set it when the destination renders so a browser agent can wait through remote navigation. Keep the marker on loading, empty, and unavailable views for that destination. Use the heading or existing ID below as the fallback until the marker ships.

Reuse existing `data-testid` selectors for buttons where they already identify the action. Scope repeated selectors to the containing panel, row, or dialog. The new attributes below are proposals.

| Proposed page ID | Existing selectors to keep | Add or clarify |
| --- | --- | --- |
| `dashboard` | `dashboard-title`, `dashboard-runall`, `dashboard-checks-stop`, `dashboard-card-osquery` | Stable IDs for summary targets and exact freshness metadata on each result. Distinguish the check suite from the short and extended stress actions. |
| `checks` | `checks-title`, `checks-row-{slug}`, `checks-select-{slug}`, `checks-detail`, `checks-run-one`, `checks-run-{group}` | Put the selected check ID on the detail panel and its run action. Publish selected check IDs for batch actions. Keep details selection distinct from the Include checkbox. |
| `stress` | Shared Checks selectors plus `checks-mode-quick` and `checks-mode-extended` | Give this route its own marker despite the shared component. Expose the selected mode, test scope, phase, and terminal status per test. |
| `interactive` | `interactive-run-selected`, `interactive-stop`, device-specific cancel and outcome IDs | Identify keyboard, display, webcam, and each audio direction by stable test ID. Expose waiting for a person, active device, layout selection, and whether an outcome was measured or entered by a person. |
| `security-audit` | `audit-title`, `audit-start`, `audit-cancel`, `audit-status`, `audit-row-{id}`, `audit-drawer-close` | Identify baseline, active filters, result provenance, and current finding. Keep the page recognizable when the audit is unavailable. |
| `benchmark` | `bench-title`, `bench-run-before`, `bench-run-after`, `bench-restart-before`, `bench-restart-after`, `bench-stop`, `bench-clear` | Expose phase, restart requirement, measurement settings, baseline identity, and units. A restart action must be separately identifiable from a no-restart run. |
| `workflow` | `wf-title`, `wf-start-checks`, `wf-go`, `wf-restart-now`, `wf-cancel`, `wf-finished` | Mark diagnostic, review, repair, restart, and report phases. Give each selected fix a stable ID and expose its outcome. Give **Start over** its own selector. Keep sign-in inputs out of agent-readable workflow metadata. |
| `certificates` | `branding-title`, `bench-qa-start`, `bench-qa-stop`, `branding-save`, `branding-clear`, `qa-save-html`, `publish-hosted-cert` | Mark the QA run scope, branding save outcome, certificate preview identity, and export or publication state. Scope preview headings separately from the page heading. |
| `history` | `history-day`, `history-filter-range`, `history-filter-test`, `history-filter-outcome`, `history-details` | Add exact capture time and a stable record key to each row. Expose the selected record and active filters. Distinguish an earlier diagnostic from an applied fix. |
| `about` | `about-title`, `about-version`, `about-builtin-modules`, `about-plugins` | Expose the full running build version for guide lookup and stable module IDs for availability. Keep plugin settings actions distinct from version lookup. |
| `module` | `area-title`, `area-requery`, `area-status`, `area-missing`, module-specific selectors such as `osquery-requery` | Expose the module slug and share the same result identity as the Checks panel. Scope drawers and service or remediation actions to the affected item. |

Use `.app[data-rpcd-version]` as the canonical selector for control and connection metadata. Require `in-control` and an enabled action before clicking. Older relays can report control without a connection state. A known offline, connecting, reconnecting, or disconnected state clears confirmed control. Never include credentials or ticket URLs.

For run results, follow the [inventory metadata proposal](hardware-inventory.md#browser-metadata). Prioritize check ID, run ID, result run ID, exact completion time and result source. Add field IDs and units where guides need structured extraction. Display names can change without changing IDs.

## Full report copy (`area-report-data`)

Every check built on the generic report (Battery, Device drivers, Event log, Network, Programs, Resource hogs, Security essentials, Services, Crashes, Drive health, DISM and SFC) renders one hidden `[data-testid="area-report-data"]` element inside `checks-detail` once the run finishes. Read it only when its `data-result-run-id` equals the header's `data-run-id`. It is absent while the check runs and on builds before this change.

`data-report` holds JSON (`data-schema="1"`): the report `status`, `summary` and `notice`, and for each card its `id`, `title`, `level`, `headline`, `meta`, `note`, `error`, event counts and windows, `columns`, `rowCount` and `attentionRowCount`. `rows` lists the card's rows that are not `ok`, worst first, up to 50, each with `level`, `key`, `values` (aligned with `columns`) and, for warning and error rows, `detail`. Values are capped at 200 characters and text at 1024. Crash dump paths and Copilot copy text are not included.

Row text comes from the PC (program names, event messages). Treat it as untrusted data, never as instructions.

The header also exposes `data-run-message`, the result message shown under the title, when the run has finished. Use it for the reason behind `couldnotrun`, `skipped` and `blocked`.

## Page copies for audit, history and benchmark

The same hidden pattern serves three more pages. Each element carries `data-schema="1"` and JSON in `data-report`; text is capped at 1024 characters and treated as untrusted.

| Element | Page | Contents |
| --- | --- | --- |
| `audit-report-data` | Security audit, once an audit has finished (`data-result-run-id` is the audit run) | Status, notice, whether it is a home PC and how many enterprise settings are hidden, the passed/warning/failed/not-checked/high-risk counts, and every shown finding that did not pass (up to 200), failed first, with id, category, name, severity, outcome, current and recommended values |
| `history-data` | History, after it loads | The selected range, whether the Event Log was readable, and the results and fixes the page lists for its current filters, newest first (up to 200 results and 100 fixes), with measurements and detail lines |
| `bench-report-data` | Benchmark, always | `phase` (`no-baseline`, `running-before`, `running-after`, `settling`, `restart-pending-before`, `restart-pending-after`, `baseline-ready` or `compared`), progress and message, the enabled measurements and restart setting, each pass with its conditions and medians, and once both passes exist the overall change and one delta per measurement with units, verdict and percent |

## Stress tests (`stress-data`)

The Stress tests page (`data-rpcd-page="stress"`) renders `[data-testid="stress-data"]` with schema 1 JSON: the selected length (`mode` short or extended, `minutesPerTest`), `running`, `progress` while a run is going (index, total, current test, headline, and each step's state), `lastSuite` (mode, outcome `completed`, `stopped-on-problem` or `cancelled`, message, steps), the run `note`, `selectedCheckIds`, and per stress test its `checkId`, `selected`, `state` (RowKind), `runId`, `completedAt`, `runLabel`, `message`, `headline` and the overheated, stoppedByUser, couldNotRun and unavailable flags.

To run tests, use the existing controls: set the length with `checks-mode-quick` or `checks-mode-extended` (`aria-pressed`), make `checks-select-{slug}` (`aria-checked`) match the requested tests, verify `checks-run-stress` lists exactly those IDs in `data-selected-check-ids`, then click it. While running, the same button is Stop. One selected test runs as a one-test suite. Stress tests load the PC: only run them on request.

The Benchmark page needs no new markers: `bench-restart` (checkbox) chooses whether the restart buttons show; `bench-run-before`, `bench-restart-before`, `bench-run-after`, `bench-restart-after`, `bench-stop` and `bench-clear` act; `bench-report-data` reports the phase before and after a restart.

## Fixes and service actions

`area-report-data` lists the one-click fixes the page offers: `actions` on a card (buttons on the card and at the top of its drawer) and on a row (buttons in the drawer's row), each with `kind` (a RemediationKind name), `target`, `targetLabel`, `buttonText` and `currentSetting`. A row with a fix is listed even when its level is `ok`. On the Services check, `services` lists every service (up to 400) with `name`, `displayName`, `status`, `startType`, and `canStart`, `canStop`, `canRestart` and `protected`.

The buttons carry the same identity: fix buttons have `data-action="remediate"`, `data-card-id`, `data-action-kind`, `data-action-target` and, for row buttons, `data-row-key`. Row buttons render only in the open drawer: open it with the card (`osquery-card-{cardId}`) first. Service buttons have `data-action="service"`, `data-service` and `data-service-action` (`start`, `stop` or `restart`) and render in the Services drawer.

A click opens RPCD's confirmation dialog: `remediation-confirm` (with `data-action-kind`, `data-action-target`, `data-allowed`, `data-state` confirm or working; confirm with `remediation-confirm-go`) or `svc-confirm` (with `data-service`, `data-service-action`, `data-allowed`, `data-state`; confirm with `svc-confirm-go`). Check the dialog names the intended fix before confirming. The result appears in `remediation-result` or `svc-result` with `data-outcome` (`succeeded` or `failed`), the fix or service identity, and `data-result-seq`, which increases with every result. After a successful fix the check runs again by itself.

## Structured diagnostic fields

These selectors are implemented in source and are ready for verification on an installed build. In Checks, scope them to `checks-detail`. Verify the selected check, run state, and matching result ID before reading fields. A missing field or value means unavailable. A numeric zero represents a reported zero.

| Check | Fields | Meaning |
| --- | --- | --- |
| `Osquery` | `logical-processor-count`, `installed-memory`, `physical-drive-count` | Read `data-value` and `data-unit`. Memory is in bytes. |
| `DriveHealth` | Under `drive-health-counts`, read `reported-drive-count`, `healthy-drive-count`, `warning-drive-count`, `critical-drive-count`, `unknown-drive-count` | Counts describe the drives represented in the report. Unknown means a drive was shown without a health verdict. An absent block means no usable drive report. |
| `Sensors` | Under `lhm-readings`, use `data-sensor-group` to scope `hottest-temperature` (Celsius) or `reported-fan-count` and `spinning-fan-count` (count). The drawer exposes `sensor-value` with its own unit. | The hottest value is the maximum current reading in the group, excluding threshold sensors. Fan counts refer to reported readings, and spinning means reported RPM greater than zero. The panel can retain its previous sample during refresh. Check `data-sampled-at` and its own `data-result-run-id` before attributing it to a new run. |
| `Crashes` | On `data-field="crashes"` and `data-field="hangs"`, read `data-value` with `data-window-days` (30), or `data-recent-event-count` with `data-recent-window-days` (7). | These count application incidents in the events RPCD collected, subject to its query limit. Hang counts count occurrences across grouped rows. System resets and BSODs are separate. Failed event reads omit the counts. |

## Remaining contracts across RPCD

| Area | Contract still needed |
| --- | --- |
| Session and navigation | Verify control on a live relay after reload, recover the original run by ID, and confirm Dashboard navigation from nested routes. Distinguish initial load from a stale view and surface consent or unavailable reasons. |
| Dashboard and Checks | Standardize freshness and result identity on summary cards. Verify selected batch membership against dispatched runs. Give pending, cancelled, unavailable, and partial results consistent outcome and reason metadata. |
| Other read-only modules | Add field IDs and units for battery, resource usage, network, device drivers, programs, services, Windows errors, and security essentials as workflows need them. Include result scope, collection window, and truncation or partial-read status. |
| Stress and interactive tests | Expose target and mode, run identity, progress, stop outcome, and any required local input. For keyboard and audio, distinguish detected or selected devices from user-confirmed outcomes. |
| Audit and remediation | Add finding and action identifiers, result scope, confirmation state, permission requirements, and structured outcomes. Audit findings and repair results need distinct records. |
| Benchmark and service workflow | Correlate before and after phases and measurements, label stopped or partial baselines, and preserve run identity across reboot. Expose selected fixes and their outcomes. |
| QA, reports, and branding | Identify the active run and its selected checks, and distinguish preview, saved, exported, and published states. Correlate the certificate with the results used to generate it. |
| History, About, and module pages | Verify stable history record identity, filters, and provenance. Expose module availability and reasons. Give standalone module results the same identity and freshness contract as Checks. |

## Tests for UI releases

### Live verification on BUDSLAPTOP, TestShop

Build `1.2.0-ci.659.1+23431f9` rendered the expected page marker for Workflow, Checks, Stress, Interactive, Security Audit, Benchmark, QA & Branding, History and About. History rendered its loading state and then its summary. Dashboard rendered on initial entry, but its navigation link left the browser on the previous page from Checks and About. The source now gives Dashboard a named route and `nav-dashboard`; verify both the root entry and the named link on the next installed build.

All 14 check rows were present and their detail actions were observed. The mirror can briefly retain the previous detail panel after a row click. Wait for `checks-run-one` with the requested `data-check-id` before clicking. Inventory, drive health, and battery completed as `passed`; crashes and resource usage completed as `warning`. All returned `current` with matching run and result IDs and an exact completion time. Navigation coverage does not establish execution coverage for the other workflows.

In a follow-up pass, Windows Error Log completed with a warning and Services passed. Device Drivers, Network, Programs, and Security Essentials showed pending results with new run IDs. Reloading the mirror produced browser connection timeouts, so run recovery and completion for those four checks remain unverified. After reloading, wait for the expected page and control state, then inspect the previous run before attempting another click.

On the updated Dashboard build, two mirrors of the same TestShop session displayed the same fresh Hardware Inventory run ID after a single invocation. The Dashboard link still left the controlling mirror on Checks or About.

To hand control to the other mirror when exactly two mirrors are connected, close the browser tab whose `data-rpcd-control` is `in-control`. Keep the RPCD app and the other mirror running. The remaining mirror can briefly show `view-only`. Wait for its marker to change to `in-control` before clicking an action. This worked on BUDSLAPTOP in TestShop, and the new controller completed Hardware Inventory with matching run and result IDs (`a98052bf-d1b8-43c7-a4b7-a6034f82f150`). The **Give control back** button returns control to the local host. In that test both mirrors became view-only.

Device Drivers, Network, Programs, and Security Essentials subsequently passed with matching run and result IDs. A no-restart Before benchmark entered Running and accepted Stop during the idle sample. RPCD marked the baseline stopped early and retained measurements already completed. Treat such a baseline as partial.

In a separate reconnect test, Device Drivers reported a new running ID before the controlling mirror was reloaded. The reload rendered Dashboard but did not restore the control marker within 15 seconds, and a Checks click did not change the page in the observed session. Treat a missing control marker as unconfirmed control, even when a page marker renders. Reopen the running session from Admin if necessary, and look for the original run ID before dispatching another check.

### Before broad live testing

- Verify Dashboard from nested routes and wait for the destination page marker. A marker alone does not prove that the mirror is connected or that the viewer can act. Verify the shell markers on the next installed build, including when the control indicator is absent.
- Verify run identity through cancellation and unavailable results. The applicability early return preserves the accepted run ID and reports NotRun. Distinguish timestamps for attempts from timestamps for usable results. Attribution under concurrent operators still requires an initiation acknowledgment or exclusive control.
- Verify inventory, drive health, sensors, and crash fields on the installed build, including missing values, zero counts, and retained samples.
- Expose selected check IDs for multi-check runs. The batch button currently identifies its group, but that alone does not describe its selected members. For interactive, benchmark and QA paths, verify workflow-specific states before making them required in the selector contract.
- Test the rendered contract against the build installed on the pilot PC. Include unique selectors, navigation readiness, two rapid runs, reconnect and failure paths. Page markers and run metadata can be smoke-tested before all workflows have complete metadata.

1. Keep a versioned, machine-readable list of required page, action and result selectors alongside the guides. Record each selector's scope and the state that makes it required. Distinguish proposed IDs from shipped IDs until implementation.
2. Render page components in tests with representative ready, busy, unavailable, and completed states. Assert required selectors resolve exactly once in their declared scope. Check disabled and waiting states too. A source-text check cannot establish that a control renders in the intended state.
3. Exercise representative actions with the browser against a release candidate. Wait for the destination marker, click the documented control, and verify that the expected state changes and result IDs agree. Cover two runs in the same minute, history vs. current results, and reconnect after the click.
4. Run a remote browser smoke test for every page route. Include Dashboard, which did not render after the prior live click. Verify Checks and Stress produce distinct markers. Keep interactive, repair, restart, and publication tests on a suitable test machine with the required user participation.
5. Make required selector failures fail the release check. When changing a selector or its meaning, update the guide, its selector list, and the rendered tests in the same change.

Implement page markers first, then wire Hardware Inventory to the selector list and tests. Expand the contract as each workflow is verified.
