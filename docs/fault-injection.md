# Fault-injection UI tests

The record and replay tests ([record-replay.md](record-replay.md)) check each check's result on the answers real PCs gave, and break those
answers one at a time. These tests go one step further: the real pages run on a recorded PC, each answer is broken in turn (errors,
timeouts, hangs, empty or garbage answers, the Agent not connected), and Playwright checks that every page copes.

They run anywhere .NET and Node do (no Windows, no Agent, no PC), so they run locally rather than on GitHub Actions.

## Running them

```
dotnet build tools/RpcdReplayHost
NODE_PATH=$(npm root -g) node tests/ui-faults/run.cjs --recording <recording folder> [--tier quick|full] [--check <Name>] [--store] [--out <dir>]
```

(Or `npm install` in `tests/ui-faults` and leave out `NODE_PATH`.) Real recordings are in the private Admin repo under
`test-data/rpcd-recordings`; the hand-made sample in `tests/RemotePCDiagnostics.Tests/Replay/Recordings` works too.

The run writes `report.md` (one line per problem, with a screenshot), `report.json`, and a screenshot of every check on the recorded
answers (`baseline-<check>.png`). It exits with 1 when anything failed.

- **quick** (the default, about 8 minutes per recording): the first two questions each check asks, each broken five ways (access denied,
  class missing, timed out, no rows, garbage).
- **full**: every question, broken nine ways (also namespace missing, provider failure, cut off, slow).
- **--store**: the Store edition's readers without an Agent (osquery, PowerShell, powercfg) instead of WMI through the Agent.

## What a run does

1. **Dashboard, Agent not connected:** every WMI answer fails as when the Agent isn't connected; Run all must finish and the page must
   not crash.
2. **Dashboard, every read hangs:** nothing answers; the Stop button must end the run within 5 s.
3. For each check, a **baseline** run on the recorded answers (and the questions it asked), then for each fault: run the check, judge the
   page, clear the fault, run it again and require the baseline back (**recovery**).

A page fails when:

- it is still running 30 s after it started (timing faults answer after 1.5 s), or Stop doesn't stop a hang;
- it shows its error banner (`page-error`, `page-fault-notice`), the Blazor error UI, a browser error, or the host logs an error;
- it shows a number no PC has: `NaN`, `Infinity`, `undefined`, `null`, `-1`, `4294967295`, `9000000000000000000`, `18446744073709551615`
  (garbage text in a text field, such as a device name, is shown as Windows gave it and isn't a failure);
- the check's page has no status line, or a card overflows its box;
- after the fault is cleared, the page isn't the same as the baseline.

The report's notes list, for review: faults that never applied, faults after which the page looked exactly like the baseline (a fallback
was used, or the fault was hidden), questions the recording doesn't hold (record the PC again), and the status line after each fault.

## The pieces

- `FaultPlan` and `FaultingSources` (`src/RemotePCDiagnostics.Core/Recording`): rules such as
  `{ "source": "wmi", "match": "Win32_Battery", "fault": "missing-class" }`, applied to every source a check reads (WMI, the registry, Store
  packages, Security Center, Core Audio, programs such as osquery, PowerShell, powercfg and wevtutil, and report files). `match` is plain
  text the answer's key contains, case ignored, or `*`. Errors use the wording and code Windows gives (`SystemWmiSource`: "InvalidClass
  (0x80041010): Invalid class"); when the recording holds the recorder's error probes (`ErrorProbes`, recorder v9 on), the PC's own errors
  are used instead. `disconnected` and
  `drop-after` give the Agent's "isn't connected" answer to every WMI read. The faults are listed in `Faults`.
- `ReplayedPc` (`tests/RemotePCDiagnostics.Tests/Replay/ReplayedPc.cs`): builds the checks on a recording, through a fault plan when given
  one. The replay tests and the host share it.
- `tools/RpcdReplayHost`: a Blazor Server app serving the real `RemotePCDiagnostics.UI` pages and checks on one recording. Its test-only
  endpoints (`/_test/faults`, `/_test/questions`, `/_test/misses`, `/_test/errors`) set the faults and report what happened. It is a test
  tool and never shipped; fixes, benchmarks and history have no backend in it.
- `tests/ui-faults/run.cjs`: the Playwright run described above.

## The Agent's scheduled metrics

`AgentMetricsReplayTests` runs the Agent's scheduled metrics pass (drive health and battery, `CoreMetricsProbes`) on every recording:
it must see the drives and battery the checks see, fill the outbox, finish under every whole-answer fault and each question broken
alone, and never send Admin a number no PC has. A hang is cut off by the pass's time limit and the next check still runs.

## Not covered yet

- The Agent's alerts (event log watchers, disk, memory and power levels) and the security audit's report: not recorded yet.
- Live sensors (LibreHardwareMonitor), the Lenovo EC fan, interactive tests and benchmarks: they measure live hardware and aren't recorded.
- The real app on Windows (WebView2, the module host out of process, the Agent's pipe). The plan is a Debug-only switch that starts the
  Host on a recording and fault plan, driven by `tests/smoke`'s CDP attach.
