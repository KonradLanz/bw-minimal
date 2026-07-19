# bw-minimal

Minimal Vaultwarden/Bitwarden client in **pure Python 3 stdlib** — zero dependencies.

Portable across:
- macOS (system Python 3 or Homebrew)
- Linux (Ubuntu, Alpine, Debian)
- QNAP QTS via Entware (`/opt/bin/python` 3.11)
- Windows (Python 3.x from python.org)

## Why

The official `bw` CLI is ~100MB and requires Node.js to build.
On embedded systems (NAS, routers) or during bootstrap (before package managers are set up),
you need a way to read secrets from Vaultwarden using only what's already there.

`bw-minimal` uses only Python 3 stdlib: `urllib`, `hashlib`, `hmac`, `json`, `base64`, `getpass`.

## Usage

```sh
# Read a secret
python3 bw_minimal.py get "nas/ssh_pass"

# Write a secret
python3 bw_minimal.py set "nas/ssh_pass" "mysecret"

# Unlock and print session token (for use with bw CLI)
python3 bw_minimal.py unlock
```

## Environment variables

| Variable | Description | Default |
|---|---|---|
| `BW_SERVER` | Vaultwarden server URL | `https://vault.bitwarden.com` |
| `BW_EMAIL` | Account email | prompted |
| `BW_MASTER` | Master password | prompted |
| `BW_SESSION` | Existing session token | auto-derived |

## Clients

| File | Platform | Notes |
|---|---|---|
| `bw_minimal.py` | Any Python 3.6+ | Primary client |
| `clients/bw_qnap.sh` | QNAP QTS | Shell wrapper, auto-detects `/opt/bin/python` |
| `clients/bw_windows.cmd` | Windows | Wrapper for `py -3 bw_minimal.py` |

## Item naming convention

All keys are stored as Vaultwarden secure notes named `kl: <key>`.
Example: `nas/ssh_pass` → item name `kl: nas/ssh_pass`.

## Status

- [x] Repo structure
- [ ] `bw_minimal.py` — prelogin + PBKDF2 + login + decrypt
- [ ] `clients/bw_qnap.sh`
- [ ] `clients/bw_windows.cmd`
- [ ] Tests
