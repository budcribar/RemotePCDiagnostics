# Hardware inventory

Guide ID: `hardware-inventory`. Use the copy from the Git tag for the RPCD build under test.

1. In Admin, open the authorized computer in **Computers**. If a session is already running, choose **Open session**. Otherwise request a session and wait for the technician UI to open. Relay any consent prompt to the person at the PC and honor the response. If Admin reports that RPCD cannot be started, report its reason.
2. Open **Checks** and select **Hardware inventory** to show its details. If it is already querying, wait for the current run to finish. Record the completion time in the details and select **Run just this**. On the standalone **Hardware inventory** page, use **Check again**.
3. Wait for the status to settle and verify that the completion time advanced. A progress bar may be brief. If the session disconnects, reopen the same session and inspect the status before retrying.
4. Report the final status, completion time, logical processor count from **Processor**, installed memory from **Memory**, and physical drive count from **Storage**. Report unavailable fields as unavailable. If the time did not advance or the check failed, report that outcome separately from any earlier readings.

## Release verification

Run this guide against the release candidate through the remote technician UI. Record the build, starting state, old and new completion times, and whether the reported fields match the UI.

| Starting state | Expected outcome |
| --- | --- |
| Session open | Reuse the running session and verify a fresh inventory. |
| RPCD available but closed | Start the app through Admin and verify a fresh inventory. |
| RPCD absent on a disposable test PC | Verify the agent can fetch its signed app package and start RPCD after approval. Verify separately that declining prevents download and launch. |

The existing agent can use an installed app or download a signed package to its app cache. An installation-specific approval prompt is a prerequisite for passing the absent-app case when unattended sessions are allowed.
