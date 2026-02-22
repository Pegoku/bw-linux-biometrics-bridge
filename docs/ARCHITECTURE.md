# Architecture

- Browser extension talks to `com.8bit.bitwarden` native host.
- Native host (`bw-native-host`) reads/writes Native Messaging frames on stdin/stdout.
- Native host forwards payloads to `bw-daemond` over a per-user Unix socket.
- Daemon performs:
  - session key exchange (`setupEncryption`)
  - encrypted command dispatch
  - system auth checks through Polkit
  - in-memory user key release after successful auth

## Threat model notes

- Daemon socket is local to user session (`$XDG_RUNTIME_DIR` by default).
- Per-app symmetric channel keys are ephemeral and in-memory.
- User keys are in-memory only in this initial version.
- Browser extension origin filtering is enforced by the native messaging manifest.
