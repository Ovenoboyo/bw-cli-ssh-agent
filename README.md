# bw-ssh-agent

![AI Generated](https://img.shields.io/badge/AI-Generated-blueviolet)

Use your Bitwarden vault as an SSH agent on Linux. Authenticate SSH connections using keys stored in Bitwarden without ever saving private key files to your disk, protected by desktop authentication prompts and native password dialogs.

---

## Features

- **No Private Keys on Disk:** Keeps your SSH private keys safely inside Bitwarden and only fetches them in memory for the split second needed to sign an SSH login.
- **Fast SSH Connections:** Caches your public keys locally so `ssh` and `ssh-add -L` respond immediately without waiting for Bitwarden on every connection.
- **Desktop Authentication Prompts:** Asks for approval via your desktop authentication dialog (Polkit—supporting passwords, fingerprint readers, and security keys) before signing SSH requests.
- **Native Password Dialogs:** Prompts for your Bitwarden master password using native desktop dialogs (`pinentry`, `zenity`, `kdialog`, `yad`) or directly in your terminal when running headless.
- **Automatic Session Persistence:** Remembers your unlocked Bitwarden session in your desktop keyring (GNOME Keyring, KWallet, KeePassXC) or Linux user session keyring so you aren't prompted on every single SSH command.
- **Optional Master Password Caching:** Disabled by default for maximum security, with a one-flag opt-in (`--store-master-password`) if you prefer unlocking solely with your system authentication.
- **Agent Forwarding Protection:** Blocks forwarded SSH agent sessions from signing requests by default so a compromised remote server cannot misuse your local keys.
- **Built-In Health Check (`doctor`):** Diagnoses missing dependencies, keyring availability, vault status, and shell environment setup with a single command.

---

## Prerequisites

- **Bitwarden CLI (`bw`)** installed and available in your `PATH`
- **Polkit (`pkcheck`)** and an active desktop Polkit agent (such as `hyprpolkitagent`, `polkit-gnome`, or KDE Polkit)
- **Recommended:** `pinentry` (e.g., `pinentry-gnome3` or `pinentry-qt`) and a desktop keyring (`gnome-keyring`, `kwallet`, or KeePassXC)

---

## Building from Source

Ensure you have **Go 1.23 or newer** installed, then clone the repository and compile the binary:

```bash
git clone [https://github.com/Ovenoboyo/bw-cli-ssh-agent.git](https://github.com/Ovenoboyo/bw-cli-ssh-agent.git)
cd bw-cli-ssh-agent
go mod tidy
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ~/.local/bin/bw-ssh-agent ./cmd
```

Make sure `~/.local/bin` is in your `PATH`, then verify the build:

```bash
bw-ssh-agent doctor
```

---

## Quick Start

### 1. Log In to Bitwarden CLI Once
If your Bitwarden account uses two-factor authentication (2FA), authenticate `bw` once using your Bitwarden Personal API Key:

```bash
bw-ssh-agent --login-apikey
```

### 2. Start the Agent & Configure Your Shell

#### Fish (`~/.config/fish/config.fish`)
```fish
if test -n "$XDG_RUNTIME_DIR"
    set -l bw_sock "$XDG_RUNTIME_DIR/bw-ssh-agent.sock"
    if not pgrep -x bw-ssh-agent >/dev/null
        bw-ssh-agent --log-file "$XDG_RUNTIME_DIR/bw-ssh-agent.log" &
        disown
    end
    set -gx SSH_AUTH_SOCK "$bw_sock"
end
```

#### Bash / Zsh (`~/.bashrc` or `~/.zshrc`)
```bash
if [ -n "$XDG_RUNTIME_DIR" ]; then
    BW_SOCK="$XDG_RUNTIME_DIR/bw-ssh-agent.sock"
    if ! pgrep -x bw-ssh-agent >/dev/null; then
        bw-ssh-agent --log-file "$XDG_RUNTIME_DIR/bw-ssh-agent.log" &
        disown
    fi
    export SSH_AUTH_SOCK="$BW_SOCK"
fi
```

#### Optional: Systemd User Service (`~/.config/systemd/user/bw-ssh-agent.service`)
```ini
[Unit]
Description=Bitwarden CLI SSH Agent
After=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/bw-ssh-agent
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now bw-ssh-agent.service
```

---

## Common Commands & CLI Flags

| Command / Flag | Description |
| :--- | :--- |
| `bw-ssh-agent doctor` | Check dependencies, prompt backend, keyring availability, vault status, and agent socket. |
| `bw-ssh-agent --login-apikey` | Prompt for your Bitwarden Client ID and Client Secret to log in `bw` once. |
| `bw-ssh-agent --store-master-password` | Save your Bitwarden master password in your system keyring and enable automatic unlock. |
| `bw-ssh-agent --clear-master-password` | Delete any saved master password from your keyring and disable automatic unlock. |
| `bw-ssh-agent --polkit-on-unlock` | Require a Polkit authentication prompt even when entering your master password manually. |
| `bw-ssh-agent --no-polkit-on-unlock` | Skip the extra Polkit prompt when you are already typing your master password (default). |
| `bw-ssh-agent --allow-forwarding` | Allow SSH signing requests over forwarded agent sessions (`ssh -A`). |
| `bw-ssh-agent --no-allow-forwarding` | Block SSH signing requests from forwarded agent sessions (default). |
| `bw-ssh-agent --show-config` | Print your active configuration file path and settings. |
| `bw-ssh-agent --refresh-cache` | Reload SSH public keys from Bitwarden after adding or updating keys in your vault. |
| `bw-ssh-agent --socket <path>` | Custom Unix socket path (defaults to `$XDG_RUNTIME_DIR/bw-ssh-agent.sock`). |
| `bw-ssh-agent --pid-file <path>` | Custom PID file path (defaults to `$XDG_RUNTIME_DIR/bw-ssh-agent.pid`). |
| `bw-ssh-agent --config <path>` | Custom config file path (defaults to `~/.config/bw-ssh-agent/config.json`). |
| `bw-ssh-agent --log-file <path>` | Write logs to a file instead of `stderr`. |

---

## Configuration

`bw-ssh-agent` automatically creates `~/.config/bw-ssh-agent/config.json` on first run:

```json
{
  "store_master_password": false,
  "require_polkit_on_unlock": false,
  "allow_agent_forwarding": false
}
```

Restart the running daemon after updating configuration settings so changes take effect.

---

## Everyday Usage

- **List available SSH keys:**
  ```bash
  ssh-add -L
  ```
- **Lock the agent immediately (clears cached session, master password, and keys):**
  ```bash
  ssh-add -x
  ```
- **Sync new keys added to Bitwarden:**
  ```bash
  bw sync && bw-ssh-agent --refresh-cache
  ```