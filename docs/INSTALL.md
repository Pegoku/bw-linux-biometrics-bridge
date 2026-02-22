# Install notes (Linux)

## Native messaging manifests

Copy templates and replace `__NATIVE_HOST_PATH__` with the absolute path to `bw-native-host`.

- Chromium/Chrome/Edge: place `com.8bit.bitwarden.json` in one of:
  - `~/.config/google-chrome/NativeMessagingHosts/`
  - `~/.config/chromium/NativeMessagingHosts/`
  - `~/.config/microsoft-edge/NativeMessagingHosts/`

- Firefox: place `com.8bit.bitwarden.json` in:
  - `~/.mozilla/native-messaging-hosts/`

## Polkit policy

Install `packaging/polkit/com.bitwarden.Bitwarden.unlock.policy` to:

- `/usr/share/polkit-1/actions/com.bitwarden.Bitwarden.unlock.policy`

Root privileges are required.

## Systemd user service

Copy `packaging/systemd/user/bw-daemond.service` to:

- `~/.config/systemd/user/bw-daemond.service`

Then run:

```bash
systemctl --user daemon-reload
systemctl --user enable --now bw-daemond.service
```
