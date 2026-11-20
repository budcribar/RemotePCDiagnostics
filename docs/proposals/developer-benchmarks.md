# RemotePCDiagnostics developer benchmarks

**Status:** Phases 1–2 implemented (Developer setup check, C# clean build + AV comparison, opt-in Dev Drive comparison, Agent rules & startup sweep). Phases 3–4 (Rust, Go, TypeScript, Python, C/C++, calibrated baselines) planned.

Publishing this document grants no implementation approval. It is planning only: a timed clean build of pinned open-source projects, a fast read-only setup check, scores against CPU-class baselines, and an opt-in Dev Drive comparison.

The most useful numbers are the ones that compare the PC with itself: the antivirus cost (current policy against a temporary exclusion), the Dev Drive gain (NTFS against Dev Drive), and cold against warm. They need no baseline, and they point at a fix. They are the headline result. The CPU-class bands come later, once real samples exist (see Scoring).

The app never runs as admin. Every step that needs admin (the temporary Defender exclusion, reading Defender exclusions, and the Dev Drive disk) goes through the Agent (elevated helper or agent service) over the admin pipe, as new, narrow entries in the Agent's allowlist (`MachineTweakRules`). The Agent never runs a script the app sends. See "Agent changes" below.

## Clean build

The core test is a clean build of a fixed, pinned project. Build time is what a developer feels. A clean build exercises cores, disk, and memory together, which a processor-only score does not.

1. Run it cold and warm. Cold clears that project's build outputs and incremental cache, then builds. Warm is the same clean build again, with the downloaded packages and the OS file cache left in place, so Defender's scan cache and the disk cache are hot. Delete the outputs before every repeat, so the compiler still does the work. A second build that leaves the outputs in place is a no-op, and it is not the warm run.
2. Time restore on its own and keep it out of the build score: `dotnet restore`, `cargo fetch`, `go mod download`, `npm ci`, and the Python install. A slow network must not read as a slow PC. The timed build uses a shipped or cached package store. When that store is missing and a download would be required, the build is "could not run", and the download time is reported on its own.
3. Antivirus scanning of build folders is often the largest hidden slowdown, so measure it. Record whether real-time protection is on and whether the build folder is excluded, using the Defender probe the app already has (`DefenderProbe`). The timed build runs under the PC's current policy. An optional second warm median, only after explicit approval, asks the Agent to add a temporary exclusion for the RPCD build temp folder, repeats the warm build, then asks the Agent to remove the exclusion, including on cancel. Today's allowlist only excludes code folders and Visual Studio build tools, so this needs its own Agent rule (see "Agent changes"). The difference is the antivirus cost. The default number stays the one taken with the PC's own policy.
4. Repeat the timed command and take the median. Use hyperfine when it is on `PATH`. Otherwise use the same loop in the app. On the warm run, discard one warmup, then take the median of the rest (on the order of five). Cold uses fewer repeats (three), with the cache cleared before each, and also takes the median. Report cold and warm separately. The score uses the warm median.

## Workloads

A language runs only when its toolchain is installed. Detection is below. Every machine builds the same commit.

1. **C#.** `dotnet build` (Release) of one pinned mid-size open-source solution. `dotnet restore` is timed on its own and is not part of the build score. The solution is chosen before implementation.
2. **Rust.** `cargo build --release` of one pinned commit of ripgrep (`BurntSushi/ripgrep`). This is the heaviest run, and the one that should scale with core count.
3. **Go.** `go build` of one pinned commit of Hugo (`gohugoio/hugo`).
4. **JavaScript / TypeScript.** `npm ci`, then `tsc`, on one pinned TypeScript project that has a lockfile. Time the two steps separately. `npm ci` is the many-small-files step (disk and antivirus). `tsc` is the compile. Both use the shipped store (`npm ci --offline --ignore-scripts`, or the cache equivalent).
5. **Python.** A subset of pyperformance, or `pip install` of a pinned requirements file into a fresh virtual environment. The install shows disk and antivirus cost. pyperformance shows the runtime. Phase 3 picks one so the run stays on the order of minutes. Wheels come from the shipped store.
6. **C/C++, optional.** MSBuild or CMake, and only when that tool is installed. One pinned project, one configuration.

**What the build may run.** The builds run as the normal user, and a build runs code from its sources: npm install scripts, Cargo `build.rs`, Go generate steps, MSBuild targets, setup.py. Only the pinned, hash-checked tree is built. Package install scripts are off (`npm ci --ignore-scripts`, `pip install --only-binary :all:` from the shipped wheels). Cargo `build.rs` and MSBuild targets are part of the compile and can't be turned off, so each pin is reviewed for what they do before it ships, and a pin moves only after that review again. Nothing in a build reaches the network.

## Toolchain detection

1. Look for `dotnet`, `cargo`, `go`, `node` (with `npm` and `tsc`), `python`, and MSBuild / CMake, on `PATH` and in the usual install locations. Record the version string. Detection is read-only. It does not install a toolchain or download anything.
2. A language whose toolchain is absent is left out entirely: no row, no checkbox, no disabled control, and no "Skipped" result. That is the NPU rule. The NPU test is omitted when the PC has no NPU (`ModuleState.NotPresent`, History only). A missing compiler is the same case. `ModuleState.Disabled` stays for a plugin that was turned off.
3. The setup check reports the toolchains it found and their versions. It does not add empty rows for the rest. When none are installed, the check still runs (disk, Defender, Dev Drive, power plan) and says that no toolchain was found. The build kinds stay hidden.

## Scoring

Each language that ran gets its own score. An overall developer score is taken from those languages only.

The developer kinds have no weight in the Benchmark screen's overall before/after score. They are reported on their own, so turning them on does not move that score.

Baselines are the weak part of this plan. A band needs at least three reference machines for every CPU class, language, pin, and toolchain major, which is many machines for one shop. Until a cell has them, the result is the times, the self-comparisons (antivirus cost, Dev Drive gain, cold against warm), and "no baseline yet". That is the expected state for a long time, and the UI is designed for it rather than for the bands.

1. Higher is better, in the same direction as the existing processor scores: `100 * (class baseline warm seconds / this PC's warm median seconds)`. Also store the cold median, the warm median, the repeat count, and the restore time kept out of the score.
2. The overall score is the geometric mean of the per-language scores that ran. A hidden language is omitted, not entered as zero. One language alone is the overall score. The result names the languages it includes.
3. Compare a time only with the same workload, the same source pin, the same toolchain major, and the same CPU class, on AC power, off a power-saver plan, and while the CPU is not thermally throttling. A run on battery, on a power-saver plan, or while throttling is the finding. Leave it out of the baseline, and do not fail it for missing that baseline. Point a power-saver result at the existing Battery & power plan check and its Balanced power-plan fix.
4. CPU class comes from the hardware inventory (CPU name and core count), in coarse buckets: mobile low-power, mobile mainstream, and desktop. The same split as the browser performance proposal. A bucket is wider than one CPU model. Store the CPU name on the sample so the buckets can be revised.
5. **Gathering baselines.** Run the same pins on a few reference machines in each class and record the median warm and cold times, with Defender on its normal policy and the build folder not excluded. A class baseline is used once that class has at least three machines. Below that, show the times and "no baseline yet".
6. **Storing baselines.** Ship them in a versioned file with the app, one row per class, language, pin, and toolchain major: class, CPU names of the reference machines, core counts, cold median seconds, warm median seconds, sample count, and measured date. Old pins stay in the file so a stored result can still be read after the pin moves. Each finished run on the diagnosed PC also appends one sample in the protected state folder, in its own file beside `benchmarks.json` and separate from it, so a before/after pass is left alone. The sample has workload, pin, toolchain, CPU class, CPU name, core count, on battery, power plan, whether Defender was scanning, cold median, warm median, and time. No computer name, account, serial, or path. Those local samples are the record. The band uses the shipped class baseline. A shop-wide aggregate of the local samples would be later, and anonymous.
7. Bands, once a class baseline exists. Starting point, to confirm on real times before it ships: pass at or below 1.25× the class warm median, warning above that and at or below 2×, fail above 2×. No baseline means the times and "no baseline yet".

## Developer setup check

A normal check: `ModuleKind.Check`, slug `DeveloperSetup`, display name "Developer setup", Programs group (`ModuleGroups.Apps`), included in Run All. It finishes in seconds and builds nothing.

1. Toolchain versions for what is installed.
2. Free space on the volume the temp build would use. Below a floor (starting point: 10 GB), the build is "could not run". The check itself warns. Low disk is not a failed PC.
3. Whether real-time antivirus is on, and whether the development folders and build tools the existing Defender probe already looks for are excluded. The check reads the exclusions through the Agent, the same Defender read the app already makes there (`AgentMachineTweaks`). Only when the Agent is missing or too old, and the app's own read returns the non-admin "N/A", are they "not readable", with the usual hint to repair the Agent.
4. Whether that volume is a Windows Dev Drive (`fsutil devdrv query` on Windows 11). Context for the antivirus number. Older Windows has no Dev Drive; say so. Not a Dev Drive is not a failure. When the volume is not a Dev Drive, the check can say "Dev Drive not used; the opt-in test can show how much it would help."
5. The active power plan, and whether the PC is on battery. The same conditions the benchmark pass already records.

The check may offer these fixes. It lists them and applies none. Each one needs the same explicit approval as every other repair, remote or local:

1. Add the Defender exclusions the existing probe already computed for code folders, the NuGet cache, and compiler processes (`AddDefenderExclusions`). Admin, journaled, undoable. This changes the user's real folders. It is separate from the temporary exclusion used to measure antivirus cost, and that temporary exclusion is removed when the measurement ends.
2. Switch to the Balanced power plan (`SetBalancedPowerPlan` on Battery & power plan). The previous plan is kept for undo. On battery, say that a comparable score wants the PC plugged in.
3. A permanent Dev Drive, as its own fix, separate from the opt-in comparison below. Listed, and applied only after its own approval. The comparison does not create one, and a real partition is not this fix.

## Where each test runs

1. Developer setup is a normal check. It is in Run All and starts from `run_check`.
2. The clean builds take several minutes and saturate the CPU and the disk, so they stay out of Run All and out of the stress suite. A stress run looks for faults under sustained load. These are scores. Add them as optional benchmark kinds on the Benchmark screen, one kind per language, off by default, so today's before/after pass keeps its length. `run_benchmark` starts the kinds that are selected. A pass that leaves them unselected does not run them.
3. Each run copies the pinned sources into a new temp folder under the user temp directory, one folder per run, builds there, and deletes that folder on success, failure, cancel, and app exit. It does not write into the user's repositories, and it does not leave `bin`, `target`, `node_modules`, or a venv behind.
4. Pinned sources are shipped with the app, or cached after a download whose hash matches the pin. Every machine builds that tree. The pin and its hash are stored with the result.
5. The Dev Drive comparison (phase 2) is a benchmark, run on request after its own yes for that run. It stays out of Run All and out of the stress suite. `run_benchmark` does not start it on its own.

## Dev Drive comparison (opt-in)

Phase 2. The same pinned project is built on NTFS and on a temporary Dev Drive, and the result is how the two times compare. It stays off unless the person says yes for that run. It is not part of the developer score and not part of the CPU-class bands.

1. One explicit yes per run, in local mode and in remote mode. The yes is consent for this run. It is not a permissions change, it is not remembered for the next run, and it does not replace the Agent helper's own elevation.
2. The disk is a dynamically expanding VHDX of about 50 GB, formatted ReFS as a Dev Drive. It is not a real partition, so the PC's existing disk layout is left alone.
3. Do not use `New-VHD`. It comes with the Hyper-V PowerShell module, which Windows Home does not have and Pro has only when Hyper-V is turned on. The Agent creates the disk in C# through the Virtual Disk API in `virtdisk.dll`, which every edition has: `CreateVirtualDisk` (VHDX, dynamically expanding, about 50 GB) into the Agent's RPCD-labeled temp folder, then `AttachVirtualDisk` to mount it. It then uses the Storage module, which is also in every edition: `Initialize-Disk -PartitionStyle GPT`, `New-Partition -UseMaximumSize`, and `Format-Volume -DevDrive -FileSystem ReFS` with an RPCD volume label. Cleanup reverses it: `DetachVirtualDisk`, then delete the file. The fallback, when the API call fails, is a fixed diskpart script the Agent writes itself (`create vdisk file=... maximum=51200 type=expandable`, `attach vdisk`), followed by the same Storage cmdlets. The app never sends that script. The volume label marks the disk as RPCD's, so cleanup only touches that disk.
4. The Agent (elevated helper or agent service) does the create, attach, format, detach, and delete, as new admin-pipe actions (see "Agent changes"). There is no separate elevation prompt. The builds run as the normal user, so the times are what the developer sees. Once the volume is formatted, the Agent grants the signed-in user modify rights on one build folder on it, because the Agent may run as SYSTEM. For this work the Agent only handles RPCD-labeled disks inside its own temp folder.
5. Pre-checks, before the yes is offered: Windows 11 build 22621.2338 or later, Dev Drive not turned off by policy (`fsutil devdrv query` reports it enabled), the Agent present and new enough to have the Dev Drive actions, at least 50 GB free on the volume that would hold the VHDX, and AC power. Otherwise omit the comparison and give the reason. That is not a disabled control and not a failed score.
6. The project comes from the cached archive of the pin. Nothing is downloaded during the timing. Place one copy in a temp folder on NTFS and one copy in a temp folder on the Dev Drive. Hyperfine, or the same in-app loop, takes the cold and warm medians on each, using the clean-build protocol above. Report the NTFS times, the Dev Drive times, and the percent faster for cold and for warm: `(NTFS median − Dev Drive median) / NTFS median`. When the Dev Drive is slower, say so with the same ratio. Record whether Defender performance mode is active on the Dev Drive. The order is NTFS, then the Dev Drive, and that order is stored with the result.
7. Cleanup always runs: dismount, delete the VHDX, and delete both temp folders. That includes failure and cancel. On Agent helper startup, sweep leftovers that carry the RPCD label inside that temp folder, from a run that did not get to clean up.
8. Remote mode shows the same busy-PC warning as the other builds. The connector exposes the comparison as an approval-gated action, the same way as a fix: it is listed, and it runs only after the yes for that run.
9. When the volume in use is not a Dev Drive, the read-only setup check can say "Dev Drive not used; the opt-in test can show how much it would help." A permanent Dev Drive is a separate fix, with its own approval. This comparison does not create one.
10. A real partition is deferred. If it is offered later, it is local-only, with its own confirmation, and with a warning to back up first. This phase does not include it.

## Agent changes

These are new entries in the Agent's admin-pipe allowlist (`MachineTweakRules`), each checked by the Agent before it acts. Each one takes data (a folder, a size), never a script.

1. **Temporary build exclusion.** `DefenderAdd` and `DefenderRemove` for the RPCD build temp folder only (the folder shape under the user's temp directory that the build creates). Every add is paired with a remove, including on cancel and failure, and on Agent startup any leftover RPCD build exclusion is removed.
2. **Dev Drive disk.** Create (Virtual Disk API, with the fixed diskpart fallback), attach, format as a Dev Drive, grant the signed-in user one build folder, detach, and delete. Only for VHDX files inside the Agent's own RPCD temp folder, and only for volumes with the RPCD label. A startup sweep detaches and deletes leftovers that match both.
3. **Defender read.** No change. The setup check reuses the Defender read the Agent already does.

Without the Agent, these steps are left out with the usual hint to repair the Agent. The app never falls back to doing them itself.

## Remote and local

1. The setup check and the builds are software-only, so they are allowed in a remote session.
2. The builds saturate the CPU and the disk for several minutes. The person at the PC will feel it. Say so before starting, in the UI and in the tool result. Leave the builds out of an unattended idle pass. The setup check can run unattended.
3. Hide a language that is not installed, rather than showing it disabled. See detection above.
4. Fixes stay off the read-only run. The Defender exclusion, the power-plan change, and a permanent Dev Drive go through the existing remediation path, one at a time, after explicit approval.
5. The Dev Drive comparison needs its own yes for that run, local or remote, and shows the busy-PC warning before it starts.

## Phased plan

1. **Phase 1.** Developer setup, and the C# cold and warm build, with restore timed separately and temp-folder cleanup. The antivirus comparison (temporary exclusion through the Agent, second warm median, exclusion removed) is the headline result of this phase, and runs only after approval. Record conditions and start saving samples. Show times and "no baseline yet"; no bands.
2. **Phase 2.** The opt-in Dev Drive comparison, on the C# pin: a temporary ~50 GB VHDX made by the Agent, the same cached pin on NTFS and on that Dev Drive, cold and warm medians, the percent faster, then cleanup. One explicit yes per run. A real partition is not in this phase. It comes before more languages because it is self-contained and needs no baseline.
3. **Phase 3.** Rust (ripgrep), Go (Hugo), and the TypeScript `npm ci` / `tsc` pair, each as its own benchmark kind, still off by default. Open question 5 (ship or cache the sources) is settled before this phase, since the Go and Rust dependency trees run to hundreds of MB.
4. **Phase 4.** Python (a pyperformance subset, or the pinned `pip install`) and C/C++ when MSBuild or CMake is present. CPU-class bands are turned on for any cell that has reached three reference machines.

A later phase does not change the check id or a benchmark kind from an earlier phase.

When a phase exists, the connector exposes it like this:

1. `run_check` and `get_check_result` with check id `DeveloperSetup`. That call does not start a build. A stored result is fine; say how old it is, as with the other checks.
2. `run_benchmark`, `get_benchmark_results`, and `stop_benchmark` for the developer build kinds, only when those kinds are selected. The result has the per-language medians, scores, and bands, the overall score, the languages included, cold and warm separately, the restore times kept out of the score, and the antivirus and power-plan notes. Hidden languages are absent from the payload. The first response says the PC will be busy for several minutes. `stop_benchmark` cancels, and the temp folder is still deleted.
3. Offered fixes come back from `list_fixes`. `apply_fix` runs one, after approval. The check never applies a fix. A permanent Dev Drive is one of those fixes, with its own approval, and it is separate from the comparison.
4. The Dev Drive comparison is approval-gated, like a fix. `list_fixes` can offer it, and it runs only after the explicit yes for that run. `run_benchmark` does not start it because a kind was selected. The result is the NTFS and Dev Drive medians, the percent faster, and whether Defender performance mode was active. The first response carries the busy-PC warning. Cancel and failure still run cleanup.

## Open questions

1. Which pinned C# solution and which pinned TypeScript project. Both need a license that allows shipping the sources, a size that fits the app or the cache, and a build that finishes in a few minutes on a 4-core laptop.
2. Python: a pyperformance subset, or `pip install` into a fresh venv. One of them goes in the score.
3. The CPU-class bucket edges, shared with the browser performance proposal, and the 1.25× / 2× cuts. Those cuts are a starting point.
4. The 10 GB free-space floor, and whether three reference machines are enough before a class baseline is used.
5. Ship the source trees in the installer, or download once and cache by hash. Shipping keeps every machine identical offline. The download keeps the installer smaller. Lean toward download-and-cache, since the Go and Rust trees run to hundreds of MB. Settle this before phase 3.
6. C/C++: one CMake project or one MSBuild project when both tools exist. One of them, so two generators are not scored against each other.
7. Whether a shop-wide baseline is in scope after local samples exist, and who may upload them.
