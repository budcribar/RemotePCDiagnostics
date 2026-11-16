# Hardware inventory

Guide ID: `hardware-inventory`. Use the copy from the Git tag for the RPCD build under test.

1. In Admin, open the authorized computer in **Computers**. If a session is already running, choose **Open session**. Otherwise request a session and wait for the technician UI to open. Relay any consent prompt to the person at the PC and honor the response. If Admin reports that RPCD cannot be started, report its reason.
2. Open **Checks** and select **Hardware inventory** to show its details. If it is already querying, wait for the current run to finish. Record the completion time in the details and select **Run just this**. On the standalone **Hardware inventory** page, use **Check again**.
3. Wait for the status to settle and verify that the completion time advanced. On the standalone page, read the `datetime` attribute of the hidden `osquery-completed` test element before and after the run. A progress bar may be brief. If the session disconnects, reopen the same session and inspect the status before retrying.
4. Report the final status, completion time, logical processor count from **Processor**, installed memory from **Memory**, and physical drive count from **Storage**. Report unavailable fields as unavailable. If the time did not advance or the check failed, report that outcome separately from any earlier readings.

## Session entry and recovery

- Start from Admin with a signed-in technician account and the intended shop and computer. A mirror link can redirect to Admin sign-in even when it includes a ticket. After sign-in, reopen the computer's session from Admin if the original link no longer works. Keep ticket URLs out of guides and verification logs.
- Confirm the computer name and shop in the RPCD header before running anything. If the session is view-only, follow its normal control request flow and wait for approval. Treat offline, waiting for consent, declined, and disconnected as distinct outcomes.
- On **Checks**, expand **System checks** if collapsed. Select the **Hardware inventory** row to open **Details**. The **Include** checkbox controls batch selection. Verify the details heading and use **Run just this** so unrelated checks do not run.
- If the panel says **Earlier result**, treat it as history. A fast run may finish before progress is seen. On builds with only a minute-resolution time, two runs in the same minute can look identical. Report freshness as unverified if there is no other reliable indication.
- Read the processor thread count separately from physical cores. Preserve the memory and storage units shown, and distinguish missing values from zero. Record a failed, canceled, or partial run as such even if earlier cards remain visible.
- If the connection drops after the click, return to the same computer and inspect the check before retrying. Use a bounded wait. If the outcome is still unclear, report it as unknown rather than claiming success.

## Browser metadata

In Checks, scope the check result and inventory fields to `checks-detail`. The standalone page exposes the same inventory fields and its own `osquery-completed` time marker.

| Attribute | Purpose |
| --- | --- |
| `data-rpcd-version` | Read the full build from the app shell or About. The guide ID is `hardware-inventory`. |
| `data-check-id="Osquery"`, `data-action="run-check"` | Scope the action and result to Hardware Inventory even if labels or layout change. |
| `data-run-id`, `data-run-state` | Publish an opaque ID when the run is accepted. Keep it through completion. Use explicit states such as running, passed, failed, canceled, and unavailable. |
| `data-result-run-id`, `data-result-source` | Tie the displayed cards to the run that produced them and distinguish live results from history. After a reconnect, verify the result belongs to the requested run before reporting it. |
| `data-completed-at` | Read the ISO 8601 completion timestamp in Checks or the `datetime` value of `osquery-completed` on the standalone page. |
| `data-field` | Read `logical-processor-count` (count), `installed-memory` (bytes), and `physical-drive-count` (count). Read the number from `data-value`. If the marker or its value is absent, report the field as unavailable. |

Metadata should describe only the authorized UI state. Keep credentials, session tickets, and extra inventory fields out of it. Use visibly labeled controls and accessible status text as the fallback for agents that cannot inspect the DOM. A run ID identifies a run, but the UI also needs exclusive control or an initiation acknowledgment to attribute it confidently when multiple operators can start checks.

## Release verification

Run this guide against the release candidate through the remote technician UI. Record the build, starting state, old and new completion times, and whether the reported fields match the UI.

| Starting state | Expected outcome |
| --- | --- |
| Session open | Reuse the running session and verify a fresh inventory. |
| RPCD available but closed | Start the app through Admin and verify a fresh inventory. |
| RPCD absent on a disposable test PC | Verify the agent can fetch its signed app package and start RPCD after approval. Verify separately that declining prevents download and launch. |

The existing agent can use an installed app or download a signed package to its app cache. An installation-specific approval prompt is a prerequisite for passing the absent-app case when unattended sessions are allowed.

Repeat the existing-session test with two runs in the same minute, an earlier result, a disconnect after starting, a failed or partial result, and a view-only session. Verify that the agent distinguishes sign-in, session consent, installation approval, and control approval. Check that the running build resolves to a tested guide and that the agent reports an unavailable guide clearly. The existing-session flow was verified previously on BUDSLAPTOP. The latest supplied mirror link reached Admin sign-in, so it did not provide a new authenticated run.
