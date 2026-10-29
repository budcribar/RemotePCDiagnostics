osqueryi.exe is bundled from third_party/osquery (osquery 5.24.0, see third_party/osquery/README.md).
The Host build/publish copies it to <app>\tools\osquery\osqueryi.exe, where OsqueryRunner looks for it.
Override at runtime with the RPD_OSQUERYI_PATH environment variable.
If it is missing, the Osquery page shows a "not found" message with the expected path.
