# Build identification

The release version is maintained once in `Directory.Build.props` (currently 1.2.0). Bump it for each release.

GitHub Actions builds use `1.2.0-ci.<run-number>.<attempt>+<git-commit>`; the .NET SDK adds the source revision automatically. Developer builds use `1.2.0-local+<git-commit>`. Local builds can contain uncommitted changes; the commit alone does not describe those changes. Builds without Git metadata show an unavailable commit.

Open **About** from the navigation to see the release, full build identity, commit, session, computer, runtime, OS and process architecture. These values describe the app hosting the session, including in remote mode.

Every newly written text-log record includes the full build identity. Every Windows Event Log entry includes a Build field, and structured diagnostic/remediation history records use the full identity for App version (including CSV history exports). The network prototype records it in diagnostics.json. Older saved records keep their original version; no version is guessed retroactively.

CI's UI smoke test checks the About page against the Git commit and CI run that produced the executable.
