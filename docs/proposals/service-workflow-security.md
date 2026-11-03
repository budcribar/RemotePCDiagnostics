# Draft proposal for security in Service workflow

## Review before applying fixes

Run the existing Security audit as an explicit option during workflow checks. Carry each finding into the review with the observed state, the affected scope, the collection time, and the source. Keep separate outcomes for passed, needs attention, managed by policy, and unable to verify.

| Finding | Proposed workflow behavior |
| --- | --- |
| Antivirus disabled, out of date, or unable to verify | Show the registered provider and its status. Offer a signature update for Microsoft Defender when it is the active provider. |
| Firewall profile disabled | Show the affected profile and policy ownership. Offer an opt-in fix only when local policy permits it and the technician can assess remote connectivity. |
| Security updates pending | Show available evidence and offer the existing Windows Update action. Flag a pending restart in the service report. |
| BitLocker or device encryption, Secure Boot, and TPM | Report current state and refer policy or firmware changes to the technician. |
| Suspicious exclusions or weakened protections | List the observed settings and explain the risk. Require explicit review before any change. |

## Applying and verifying

Use the existing workflow approval and action results for supported changes. Leave security fixes unchecked by default. Re-read the relevant setting just before execution and skip a fix if the condition is already resolved or now managed by policy. After the action, rerun the affected check and log the verified outcome, including any restart requirement. Keep recovery keys and other secrets out of reports.

## First increment

Start with Security audit findings and a read-only review summary. Add Defender signature updates and Windows Update as explicit actions after verifying the detection and post-action checks. Add firewall remediation after testing policy enforcement and remote session behavior.
