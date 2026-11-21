# Building RPCD features for browser agents

Use the same RPCD workflow and diagnostic code for technicians and browser agents. The agent opens an authorized technician session, runs the check through the UI, and reads the result from RPCD.

- Keep the visible UI focused on what the technician needs: the action, progress, outcome, and results. Put exact timestamps and stable identifiers in DOM metadata when they help the agent verify a run. Use accessible labels for controls and status text that also help people.
- Verify freshness before reporting results. Compare the exact completion timestamps before and after the action. If a check exposes run IDs, use the ID to match completion to the requested run. If freshness cannot be verified, report that explicitly.
- Write one short guide per workflow. Include the visible controls, the result fields to read, and how to handle earlier results, failures, and reconnects. Keep guides in Git with the UI and use the guide for the RPCD build under test.
- Before relying on a guide for a release, run it through the remote technician UI on an authorized test PC. Verify that the agent can find the action, run only the intended check, and read the fresh result. Record which build and starting state were tested.

[Hardware Inventory](hardware-inventory.md) is the first example. The existing-session browser workflow has been verified. Startup, installation consent, and serving version-matched guides through Admin are separate pilot checks.
[RPCD browser workflows](rpcd-workflows.md) covers the navigation, checks, interactive tests, benchmarks, service workflow, QA, and history. Start there for a walkthrough or release test plan. A requested benchmark runs only after the enabled list is set to what was asked. [Performance benchmark](rpcd-workflows.md#performance-benchmark) is the sequence: turn every test off, enable only what was asked, confirm the enabled list, then run.
