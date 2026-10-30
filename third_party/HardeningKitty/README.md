# HardeningKitty (bundled third-party PowerShell module)

- What: HardeningKitty, a PowerShell module that audits Windows security settings against finding lists
  (used by the **Security audit** page, in `Audit` mode only — it never changes settings).
- Version: **0.9.4** (GitHub release tag `v.0.9.4`, published 2026-07-21)
- Source: https://github.com/scipag/HardeningKitty/releases/tag/v.0.9.4
  - Downloaded: https://github.com/scipag/HardeningKitty/archive/refs/tags/v.0.9.4.zip (the release has no extra assets; this is the release's source archive)
  - Zip SHA256: `cb1b9e8ec531de2e22f5dc0d178059e4a4836b54935dcd856ef4414a7ffdc14d`
- Contents: `module/` = the zip's `HardeningKitty-v.0.9.4/` folder, **unmodified** (all 132 finding lists + signed list manifest).
  - `HardeningKitty.psm1` SHA256: `01eba5f0f4f11fa21616946bd9ea7eccd56079abb9cafdc7b8e7c60c75f63aee` (Authenticode-signed by upstream)
  - `HardeningKitty.psd1` SHA256: `9789ff549f0e9d4fff0d1dd31620459b9af3bb47968d202a83c24b0ea5641bde`
  - `lists/finding_list_0x6d69636b_machine.csv` (default list used by the app) SHA256: `cc6cf409c7cb0f7dc0caeb82b8323dcc13ddb4dcb88e35e9e2cc4f52874816f4`
- Size: ~9.8 MB on disk (mostly the CSV finding lists).
- License: MIT, Copyright (c) 2020 scip ag (see `LICENSE`).
- `.gitattributes` marks `third_party/**` as `-text` so Git never rewrites line endings (that would break the signatures/hashes).

## How it ships
There is no installer in this repo yet. "Installed" currently means **bundled into the Host build/publish output**:
the Host csproj copies `module/**` to `<output>\tools\HardeningKitty\` (next to `RemotePCDiagnostics.Host.exe`),
which is where `HardeningKittyRunner` looks (`AppContext.BaseDirectory`; override with `RPD_HARDENINGKITTY_PATH`).
When an installer is added it just needs to include the whole output folder.

## How it runs
On demand only (Start button on the Security audit page; not auto-run, not part of Run All):
`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Import-Module <bundled>\HardeningKitty.psd1; Invoke-HardeningKitty -Mode Audit -Report -ReportFile <temp csv> -SkipMachineInformation -SkipLanguageWarning"`.
The execution-policy bypass applies to that one process only; no system settings are changed.
The CSV goes to a per-run folder under `%TEMP%\RemotePCDiagnostics\` and is deleted after it is read.
Admin rights are needed for a complete audit (the app manifest already requests elevation); without them some checks are skipped.

To upgrade: replace `module/` with the new release folder and update the version/hashes above.
