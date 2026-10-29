# osquery (bundled third-party binary)

- File: `osqueryi.exe` (osquery interactive shell, Windows x86_64), unmodified.
- Version: 5.24.0 (released 2026-10-09)
- Source: https://github.com/osquery/osquery/releases/download/5.24.0/osquery-5.24.0.windows_x86_64.zip
  (path inside zip: `osquery-5.24.0.windows_x86_64/Program Files/osquery/osqueryi.exe`)
- Zip SHA256: `2a55cf9d27765f0c7ce9e3484bdf1aee560df65442f39189d7201107f21544a5` (matches the digest GitHub publishes for the release asset)
- osqueryi.exe SHA256: `b161ab14d51df8995811d4af8d89957819b7887f974b5b314aab4945f88ac156`
- Authenticode: signed by "OSQUERY a Series of LF Projects, LLC" (signature verified OK with `signify` on Linux).
- License: Apache-2.0 OR GPL-2.0-only (see LICENSE.txt, LICENSE-Apache-2.0, LICENSE-GPL-2.0).

The Host project copies it to `<output>/tools/osquery/osqueryi.exe` on build and publish,
which is where `OsqueryRunner` looks (relative to `AppContext.BaseDirectory`).
To upgrade: replace the exe and update the version/hashes above.
