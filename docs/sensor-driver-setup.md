# Optional sensor driver: PawnIO 2.2.0

This companion package contains the unmodified official PawnIO installer. It is optional and is not installed automatically by Remote PC Diagnostics.

Official project: https://pawnio.eu/
Pinned release: https://github.com/namazso/PawnIO.Setup/releases/tag/2.2.0
Redistribution terms: https://github.com/namazso/PawnIO.Modules/wiki/Using-PawnIO-Modules#licensing-considerations

The author permits redistribution of the installer. It retains its original signature and installer notices. The official binary edition has its own license; review the terms in the installer. This package does not rebuild or modify the driver.

## Try fan readings

1. Save your work and close Remote PC Diagnostics normally.
2. Run `PawnIO_setup.exe`, approve Windows' administrator prompt, and use the official signed edition. Do not select the unrestricted/unsigned edition or change Windows security protections.
3. Follow the installer's restart instructions, if any, then reopen Remote PC Diagnostics as administrator. Restarting the app is necessary because driver availability is cached.
4. Open Checks & tests, select Temperatures & fans, and run that check. Look at the Fans card.

The current custom embedded-controller fan reader supports only Lenovo IdeaPad 1 15ALC7, machine type 82R4. It reads allowlisted EC values without changing fan settings. RPM scaling is experimental and has not been confirmed on real hardware. Installing PawnIO enables access; it does not guarantee that the firmware exposes a usable fan speed. CPU temperature access through LibreHardwareMonitor may also improve.

If no fan appears, inspect the Application event log's RemotePCDiagnostics source (event 1200: fan diagnostic; event 1300: sensor driver). If `RPD_LOG_FILE` was set before starting the app, the same diagnostic messages are written there. Missing/implausible readings remain hidden.

Packaging verifies SHA-256 and a valid Authenticode signature from namazso.eu. Nothing in this companion download installs or launches automatically.
