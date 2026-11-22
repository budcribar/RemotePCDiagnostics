# Record and replay testing

Each PC answers the checks a little differently. Record and replay tests run the checks against the raw answers real PCs gave, so a
change that breaks one make or model shows up in the tests rather than on that PC.

## Recording a PC

On the PC (Windows, no administrator rights needed, nothing is changed):

```
dotnet run --project tools/RpcdRecorder -c Release -- --out <folder> [--osquery <path to osqueryi.exe>] [--note "text"]
```

It writes `<folder>/<product id>-<date>/` with:

- `machine.json`: which PC (the BIOS product identifier, make, model, SKU, board, BIOS, Windows build, app version).
- `calls.json`: every answer the checks got, in order (WMI rows, osquery and command output).
- `scrub-report.txt`: what was replaced before saving.

The PC name, user names and serial numbers are replaced with placeholders (`<pc:…>`, `<user:…>`, `<serial:…>`) before the files are
written, and so is the SMBIOS UUID. Even so, a recording lists the PC's hardware and software, so real recordings stay out of this public
repo: they are kept in the private Admin repo under `test-data/rpcd-recordings`. Point `RPD_RECORDINGS_DIR` at that folder.

## Running the tests

The tests in `tests/RemotePCDiagnostics.Tests/Replay` run every recording in `Replay/Recordings` (hand-made samples) and, when it is set,
every recording under `RPD_RECORDINGS_DIR`. For each one they check:

- **Snapshot:** the check's result matches `snapshots/<Check>.json` in the recording's folder. On a difference the new result is
  written as `.received.json`; rerun with `RPD_ACCEPT_SNAPSHOTS=1` to approve it.
- **Parity:** while a check moves from osquery or PowerShell to WMI, the capture records both, and the old and new code must agree.
- **Damaged answers:** each answer is broken one at a time (fails, times out, empty, garbage, each value missing, null, zero,
  negative, 0xFFFFFFFF, huge or garbage). The check must not crash, show nonsense numbers, or call something good without a reading.
- **Known failures:** a recording edited to a known bad state (worn battery, power saver) must give the known verdict.

A question the recording doesn't hold fails the snapshot test: the check now asks something new, so record the PC again.
