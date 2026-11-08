# RemotePCDiagnostics hardware test proposals

**Status:** Proposed. Not implemented.

Publishing this document grants no implementation approval. This proposal covers USB and Bluetooth diagnostics, bounded local device history, video-memory integrity testing, and headless display checks.

## USB diagnostic scope

1. Inventory USB controllers, hubs, connected devices, device classes, and available topology through Windows device APIs/WMI, supplemented by osquery where supported.
2. Show current device problem codes and relevant Windows event-log errors, separating historical errors from current faults.
3. Offer a small transfer check when a writable USB drive is present: create a unique test file, read it back, verify contents, and delete it afterward, including cancellation cleanup. Never overwrite existing files. This validates that drive's connection, not every port or maximum throughput.
4. Display USB-C power-delivery or charging information only where reliably exposed. Missing information is not a failed port.

## Bluetooth diagnostic scope

1. **First release, alongside USB inventory.** Show detected Bluetooth adapters, radio state where available, driver version, and Windows device problem codes. Distinguish an absent adapter, a disabled radio, and a driver fault. Show paired peripherals and their current connection state where Windows exposes it. A paired device can be disconnected normally when asleep or out of range. [Windows Bluetooth connection status](https://learn.microsoft.com/windows/uwp/api/windows.devices.bluetooth.bluetoothdevice.connectionstatus)
2. **Follow-up for intermittent faults.** Correlate observable disconnects and reconnects with adapter or driver errors. Reuse the bounded local history design below. Report monitoring gaps and avoid storing device addresses or names unless needed locally for diagnosis.
3. **Optional functional test.** Let the user choose a known-good device and verify a profile-specific action, such as audio playback or an input event. A generic inventory check cannot certify range, audio quality, or every Bluetooth profile. Keep pairing, unpairing, and radio resets out of the read-only diagnostic.

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

## Additional device tests in priority order

1. **Keyboard, touchpad, and touchscreen.** Add a guided local test for key presses, clicks, scrolling, gestures, and touch across the panel. Show which inputs were observed and identify untested areas. Require local participation and distinguish physical input from remote or injected input where Windows exposes the source. If the source cannot be established, report that the physical device could not be verified.
2. **Sleep, wake, and resume.** Add a standalone read-only check for the last wake source, sleep blockers, and abnormal standby drain on supported systems. Correlate recorded resume times with USB, Bluetooth, display, and network failures. Use existing evidence during a remote session. [Windows power diagnostics](https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options)
3. **Dock and USB-C connection health.** Combine USB, display, network, and audio observations in one view. During a guided connection, show which displays, Ethernet adapters, audio endpoints, and hubs appeared. Flag missing functions only when the expected dock capabilities are known, and highlight multiple devices dropping around the same time.
4. **External storage and card readers.** Check whether Windows sees the reader, detects inserted media, and reports I/O errors. Extend the USB transfer-integrity check to removable media on a user-selected writable volume, using the same temporary-file and cancellation cleanup rules.
5. **Charging and AC adapter stability.** Extend Battery & power plan with a guided plug/unplug check and an AC-to-battery transition timeline. Show whether the PC detected external power and whether the battery began charging. Report adapter wattage only when Windows exposes it.
6. **Ethernet and Wi-Fi adapter diagnostics.** Extend the network checks with negotiated Ethernet speed, local link drops, adapter resets, and Wi-Fi reconnects. Correlate adapter events with connectivity loss to help separate a local link fault from an upstream problem.

## Working-set tradeoffs when splitting tests into executables

A separate executable lets a diagnostic run under a restricted user token while the main application stays elevated. It also adds a process and a .NET runtime while the test runs. The experiments used one module DLL per `ModuleHost.exe` worker as a proxy for a standalone test executable. The current app shares workers across bundled modules at the same privilege level, so the per-worker measurements below do not predict the current cost per bundled module. Module connections close after two idle seconds by default. A module can opt into a persistent connection with `keepAlive` in its manifest. See [the bundled module design](../host-queries.md#implemented-modules-that-ship-with-the-app).

### In-process versus out-of-process

The same lightweight sample uptime check ran three times per configuration. A small .NET parent loaded the module directly in one configuration. In the other, `ModuleHost.exe` loaded it and returned a result over stdout, then exited on request. The table shows median increases over the parent baseline. The loaded measurement was taken after the result arrived, while the code or worker was still resident.

| Execution model | Added working set while loaded | Added private working set while loaded | Added private working set after completion and any worker exit |
|---|---:|---:|---:|
| Module loaded in the parent | 15.5 MiB | 3.7 MiB | 3.7 MiB |
| Separate worker, then exit | 38.6 MiB | 7.5 MiB | 0 MiB measured |

Keeping idle workers connected after the same check accumulated private working set. Across three trials, the medians were:

| Idle workers | Combined working set | Combined private working set |
|---:|---:|---:|
| 1 | 39 MiB | 8 MiB |
| 4 | 156 MiB | 31 MiB |
| 8 | 311 MiB | 61 MiB |

All workers exited cleanly on `exit`. A fresh worker took 274 ms median to start, run the sample, and exit. A warm worker returned the same result in 0.3 ms median. Combined working set can count the same shared pages in each process. Private working set measures resident pages private to each process.

### Shared DLLs and custom UI

- The Host and ModuleUiHost build directories contained 18 byte-identical DLLs totaling 29.6 MiB. `Microsoft.Windows.SDK.NET.dll` accounted for 23.7 MiB. These are unpacked file sizes. A page-sharing probe returned the maximum share count for both separate copies and shared files, so it could not quantify physical RAM savings.
- Two `ModuleUiHost` instances rendered the same sample clock through a local relay. After warm-up, separate folders measured 291.77–291.81 MiB total and 76.71–76.79 MiB private working set. A shared folder measured 291.51–292.28 MiB total and 76.52–77.27 MiB private. The file layout made no measurable difference to these counters in this workload. Production instances of ModuleUiHost already launch from the same folder.
- In a separate navigation trial, one rendered module UI host used 168 MiB working set, including 56 MiB private, and exited cleanly when the browser navigated away. The UI measurements cover the host processes alone. WebView2 children, the browser, and the relay were outside those totals.

### Implications for the conversion

Use on-demand workers where restricted execution matters. Use the default short idle exit for finite hardware tests. Reserve `keepAlive` for modules that need a persistent process, and account for those workers in the memory budget. Limit concurrency so active workers cannot accumulate across a batch. Keep the result in the main application for display. Sharing DLLs can reduce deployment duplication, but the experiments found no working-set improvement from moving the same workload to one DLL folder.

Before estimating the effect of converting all modules, compare the same representative heavy checks in the full WPF app and in restricted workers. Measure peak private working set during each run and idle private working set after completion across the full process tree, including subprocesses started by the checks. The sample established the direction of the tradeoff for a lightweight module. It did not measure the full application's peak or unique physical RAM.
