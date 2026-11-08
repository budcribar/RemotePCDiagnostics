# RemotePCDiagnostics hardware test proposals

**Status:** Proposed. Not implemented.

Publishing this document grants no implementation approval. It is planning only: USB diagnostics with bounded local history, video-memory integrity testing, and prioritized headless display checks.

## USB diagnostic scope

1. Inventory USB controllers, hubs, connected devices, device classes, and available topology through Windows device APIs/WMI, supplemented by osquery where supported.
2. Show current device problem codes and relevant Windows event-log errors, separating historical errors from current faults.
3. Offer a small transfer check when a writable USB drive is present: create a unique test file, read it back, verify contents, and delete it afterward, including cancellation cleanup. Never overwrite existing files. This validates that drive's connection, not every port or maximum throughput.
4. Display USB-C power-delivery or charging information only where reliably exposed. Missing information is not a failed port.

## Bounded local device history

1. Record connection and disconnection times, device class, available identifiers, controller/hub location, and associated errors. Aggregate repeated events into reconnect counts.
2. Store changes rather than constant snapshots. Retain records for 30 days and apply a finite size cap, removing oldest records first; the cap value remains to be chosen before implementation.
3. Mark monitoring gaps explicitly. Do not infer precise disconnect times from missing snapshots; snapshots can miss brief reconnects.
4. Keep history on the diagnosed PC by default, with controls to clear individual device history or delete all history.
5. Treat device names and serial numbers as sensitive. Collect no file contents and omit identifying details from exports by default.
6. Use history to highlight frequent reconnects, enumeration failures, and devices no longer detected. These are diagnostic clues, not proof of a bad port.

## Blazor presentation

Retain the existing colors, fonts, and sidebar. Present current devices, current problems, historical errors, and transfer-test results distinctly. Add a history section beside current devices, highlighting frequent reconnects and newly reported errors. Show monitoring gaps and unavailable fields clearly.

## Physical limits

Software cannot certify signal integrity, connector damage, actual power output, or whether an unused port works. A person must connect a known-good device to each port; cable and charging faults may require a USB power meter. A device disappearing from history may simply mean it was unplugged.

## Video-memory integrity proposal

1. **Automatic inventory:** read GPU identity, driver version, dedicated/shared memory and memory budgets through DXGI/Windows APIs, supplemented by WMI/osquery where supported. Memory type may be unavailable; do not rely solely on WMI memory-size values.
2. **Automatic context:** collect GPU resets, display-driver errors, and relevant hardware errors from Windows event logs. Compare exact GPU/driver versions against documented known issues; version matching alone does not diagnose a defect.
3. **Controlled offscreen workload:** allocate a bounded portion of available GPU memory, write known patterns, read them back, and count mismatches. Report the amount actually tested, duration, errors, and device resets. No screen observation is required for these comparisons.
4. Keep an optional visible artifact test separate from the automatic integrity test. It requires a person to observe the physical display.
5. On the Lenovo integrated GPU, explain that graphics memory shares system RAM rather than being separate VRAM, so results overlap with RAM testing.
6. **Safety:** start with a short run, retain memory headroom, support cancellation and runner-owned cleanup, enforce a watchdog, monitor temperature when available, and stop on overheating or device errors. A GPU reset may interrupt the remote session.
7. **Limits:** a pass covers only allocated memory and the patterns exercised. Software cannot certify the GPU chip, solder joints, cooling hardware, or every memory location. Physical diagnosis remains necessary for those.

## Headless display checks

Prioritize checks that explain reported symptoms. Most checks on a working laptop will return normal data; no measured detection or false-negative rates are available.

1. **Top priority — configuration:** inspect active resolution, refresh rate, HDR state/capability, scaling, enabled monitors, primary display, and arrangement. Distinguish physical displays from virtual or remote-session displays. Useful for configuration complaints, but an unwanted supported setting is not necessarily a hardware fault.
2. **Top priority — stability correlation:** correlate display connection/mode changes with recorded driver crashes, GPU resets, and disconnects. This offers useful evidence for intermittent failures, but cannot conclusively distinguish driver, cable, dock, power, or hardware causes, or prove the physical panel went black.
3. **Supporting information — identity/EDID:** collect available model identity, supported modes, and reported HDMI/DisplayPort/eDP connection type. Missing or malformed EDID can be a clue; docks/adapters may alter results. Identity has low standalone fault-finding yield.
4. **Next — load/throttling:** reuse existing GPU-load telemetry rather than duplicate it. Observe supported temperatures, clocks, throttling indicators, and resets during bounded workloads. Useful for load-triggered symptoms; normal laptop power limits can also reduce clocks and are not inherently faults.
5. **Lower priority — brightness readout:** read supported WMI brightness values; contrast may require supported DDC/CI controls. Low fault-finding yield: a reported value cannot establish physical brightness or backlight condition.
6. **Optional — active refresh-rate/brightness switching:** exercise supported changes and restore original settings. Useful mainly to reproduce a reported problem; may blank the display or disrupt remote access. Successful API calls do not prove correct physical output.
7. Driver versions are context, not a diagnosis: an old driver alone is not a fault. Documented issues matching the installed version and observed symptoms provide stronger evidence.

False negatives remain a major limitation: clean logs and successful checks can miss dead pixels, backlight defects, visible flicker, color faults, and black screens without a driver signal. Short workloads can miss intermittent faults. Physical image quality still needs human observation or controlled camera measurements; do not label it passed from headless checks.
