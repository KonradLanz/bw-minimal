#!/usr/bin/env python3
# bw_minimal.py — Minimal Vaultwarden/Bitwarden client, pure stdlib
#
# Supports: macOS, Linux, QNAP/Entware (Python 3.6+), Windows
# Zero external dependencies — only Python 3 stdlib.
#
# Usage:
#   python3 bw_minimal.py get "nas/ssh_pass"
#   python3 bw_minimal.py set "nas/ssh_pass" "value"
#   python3 bw_minimal.py unlock
#
# Environment (priority: shell env > dotfiles env > .env > prompt):
#   KL_DOTFILES_ENV  Path to dotfiles env file (default: ~/git/dotfiles/env)
#   BW_SERVER        Vaultwarden URL       (default: https://vault.own.dedyn.io
#                                           if dotfiles env found, else bitwarden cloud)
#   BW_EMAIL         Account email
#   BW_MASTER        Master password (prefer prompt over setting this)
#   BW_SESSION       Existing session token
#
# Item convention: keys stored as secure notes named "kl: <key>"

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SELF_HOSTED_DEFAULT = "https://vault.own.dedyn.io"
CLOUD_DEFAULT       = "https://vault.bitwarden.com"
ITEM_PREFIX         = "kl: "

# Stable device identifier — derived from hostname so it's consistent across
# runs on the same machine but unique per host. Vaultwarden requires a UUID.
_DEVICE_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, os.uname().nodename
                             if hasattr(os, "uname") else "bw-minimal"))


# ---------------------------------------------------------------------------
# Env loading (shell env > dotfiles env > .env file)
# ---------------------------------------------------------------------------

def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=VALUE env file, ignoring comments and blank lines."""
    result: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if val and not val.startswith("\u2190"):
                result[key] = val
    except (OSError, UnicodeDecodeError):
        pass
    return result


def _load_env() -> None:
    """
    Load env variables in priority order (lowest first, higher overwrites):
      1. .env in script directory
      2. KL_DOTFILES_ENV or ~/git/dotfiles/env
      3. Existing shell environment (never overwritten)
    """
    script_dir = Path(__file__).parent

    # Layer 1: .env next to script
    for k, v in _parse_env_file(script_dir / ".env").items():
        os.environ.setdefault(k, v)

    # Layer 2: dotfiles env
    dotfiles_env_path = os.environ.get("KL_DOTFILES_ENV") or \
        str(Path.home() / "git" / "dotfiles" / "env")
    dotfiles_env = Path(os.path.expanduser(dotfiles_env_path))
    if dotfiles_env.is_file():
        for k, v in _parse_env_file(dotfiles_env).items():
            os.environ.setdefault(k, v)
        os.environ.setdefault("BW_SERVER", SELF_HOSTED_DEFAULT)
    else:
        os.environ.setdefault("BW_SERVER", CLOUD_DEFAULT)


# ---------------------------------------------------------------------------
# Crypto helpers (stdlib only)
# ---------------------------------------------------------------------------

def _pbkdf2(password: str, salt: str, iterations: int, keylen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=keylen,
    )


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869)."""
    t = b""
    okm = b""
    for i in range(1, -(-length // 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), "sha256").digest()
        okm += t
    return okm[:length]


def _stretch_key(master_key: bytes) -> tuple[bytes, bytes]:
    enc_key = _hkdf_expand(master_key, b"enc", 32)
    mac_key = _hkdf_expand(master_key, b"mac", 32)
    return enc_key, mac_key


def _decrypt_cipher_string(cipher_str: str, enc_key: bytes, mac_key: bytes) -> bytes:
    """
    Decrypt Bitwarden CipherString type 2 (AES-256-CBC + HMAC-SHA256).
    Format: 2.<iv_b64>|<ct_b64>|<mac_b64>
    Always returns raw bytes — callers decode to str when needed.
    """
    if not cipher_str.startswith("2."):
        raise ValueError(f"Unsupported CipherString type: {cipher_str[:2]}")
    _, payload = cipher_str.split(".", 1)
    parts = payload.split("|")
    iv  = base64.b64decode(parts[0])
    ct  = base64.b64decode(parts[1])
    mac = base64.b64decode(parts[2])

    expected_mac = hmac.new(mac_key, iv + ct, "sha256").digest()
    if not hmac.compare_digest(expected_mac, mac):
        raise ValueError("HMAC verification failed — wrong key or corrupted data")

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), 16)
    except ImportError:
        return _decrypt_aes_openssl(ct, enc_key, iv)


def _decrypt_aes_openssl(ct: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC decrypt via openssl subprocess (fallback, no pycryptodome)."""
    import subprocess
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(ct)
        ct_path = f.name
    try:
        result = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-d", "-nosalt",
             "-K", key.hex(), "-iv", iv.hex(), "-in", ct_path],
            capture_output=True,
        )
        if result.returncode != 0:
            raise ValueError(f"openssl decrypt failed: {result.stderr.decode().strip()}")
        return result.stdout  # raw bytes — caller decodes
    finally:
        os.unlink(ct_path)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} {e.reason} — {body}") from e


def _post_json(url: str, data: dict, token: Optional[str] = None) -> dict:
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} {e.reason} — {body}") from e


def _get_json(url: str, token: str) -> dict:
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} {e.reason} — {body}") from e


# ---------------------------------------------------------------------------
# Vaultwarden session
# ---------------------------------------------------------------------------

class BwSession:
    def __init__(self, server: str, email: str, master: str):
        self.server = server.rstrip("/")
        self.email  = email
        self.master = master
        self.access_token: Optional[str] = None
        self.enc_key: Optional[bytes]    = None
        self.mac_key: Optional[bytes]    = None

    def unlock(self) -> str:
        """Login + derive keys. Returns access token."""
        # 1. Prelogin — get KDF params
        prelogin   = _post_json(f"{self.server}/api/accounts/prelogin",
                                {"email": self.email})
        iterations = prelogin.get("kdfIterations", 600000)

        # 2. Derive master key + master password hash
        # Bitwarden spec: email salt must be lowercased + stripped
        # Step 1: PBKDF2(password=master_password, salt=email.lower().strip(), iter=N) -> master_key
        master_key  = _pbkdf2(self.master, self.email.lower().strip(), iterations)
        # Step 2: PBKDF2(password=master_key_bytes, salt=master_password, iter=1)
        #         NOTE: master_key is raw bytes here, salt is the plain password
        #         This is Bitwarden's specific two-step derivation.
        master_hash = base64.b64encode(
            hashlib.pbkdf2_hmac(
                "sha256",
                master_key,                        # bytes — NOT re-encoded
                self.master.encode("utf-8"),        # plain password as salt
                1,
            )
        ).decode()

        # 3. Login — get access token
        #    deviceIdentifier MUST be a valid UUID (Vaultwarden enforces this)
        token_resp = _post_form(
            f"{self.server}/identity/connect/token",
            {
                "grant_type":       "password",
                "username":         self.email,
                "password":         master_hash,
                "scope":            "api offline_access",
                "client_id":        "cli",
                "deviceType":       "8",
                "deviceIdentifier": _DEVICE_ID,
                "deviceName":       "bw-minimal",
            },
        )
        self.access_token = token_resp["access_token"]

        # 4. Fetch profile — get encrypted vault key
        profile          = _get_json(f"{self.server}/api/accounts/profile",
                                     self.access_token)
        vault_key_cipher = profile["key"]

        # 5. Decrypt vault key with stretched master key
        #    vault_key_raw is 64 raw bytes: [0:32] = enc key, [32:64] = mac key
        enc_key, mac_key  = _stretch_key(master_key)
        vault_key_bytes   = _decrypt_cipher_string(vault_key_cipher, enc_key, mac_key)
        self.enc_key = vault_key_bytes[:32]
        self.mac_key = vault_key_bytes[32:64]

        return self.access_token

    def _find_item(self, key: str) -> Optional[dict]:
        """Return the raw cipher dict for 'kl: <key>', any type."""
        name_target = f"{ITEM_PREFIX}{key}"
        ciphers = _get_json(f"{self.server}/api/ciphers", self.access_token)
        debug = os.environ.get("BW_DEBUG")
        for item in ciphers.get("Data", []):
            raw_name = item.get("Name", "")
            try:
                item_name = _decrypt_cipher_string(
                    raw_name, self.enc_key, self.mac_key
                ).decode("utf-8")
            except Exception:
                # Name may already be plaintext (older Vaultwarden / bw CLI items)
                item_name = raw_name
            if debug:
                print(f"  [debug] item: {repr(item_name)!s:40s} type={item.get('Type')}", file=sys.stderr)
            if item_name == name_target:
                return item
        return None

    def get(self, key: str) -> Optional[str]:
        """Secure note (type 2): return decrypted Notes field."""
        item = self._find_item(key)
        if item is None:
            return None
        if item.get("Type") != 2:
            raise RuntimeError(f"Item 'kl: {key}' is not a secure note (type {item.get('Type')}). Use get-user/get-pass for login items.")
        notes = item.get("Notes")
        if not notes:
            return ""
        return _decrypt_cipher_string(notes, self.enc_key, self.mac_key).decode("utf-8")

    def get_user(self, key: str) -> Optional[str]:
        """Login item (type 1): return decrypted username."""
        item = self._find_item(key)
        if item is None:
            return None
        login = item.get("Login") or {}
        username = login.get("Username")
        if not username:
            return ""
        return _decrypt_cipher_string(username, self.enc_key, self.mac_key).decode("utf-8")

    def get_pass(self, key: str) -> Optional[str]:
        """Login item (type 1): return decrypted password."""
        item = self._find_item(key)
        if item is None:
            return None
        login = item.get("Login") or {}
        password = login.get("Password")
        if not password:
            return ""
        return _decrypt_cipher_string(password, self.enc_key, self.mac_key).decode("utf-8")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

_SESSION_FILE = os.path.expanduser("~/.bw_session")

def _load_session_file() -> str:
    """Read cached session token from ~/.bw_session (600 perms)."""
    try:
        with open(_SESSION_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

def _save_session_file(token: str) -> None:
    """Persist session token to ~/.bw_session with mode 600."""
    import stat
    with open(_SESSION_FILE, "w") as f:
        f.write(token)
    os.chmod(_SESSION_FILE, stat.S_IRUSR | stat.S_IWUSR)

def _get_session() -> BwSession:
    server = os.environ.get("BW_SERVER", SELF_HOSTED_DEFAULT)
    # Defer email prompt — only needed if BW_SESSION is absent or expired
    email  = os.environ.get("BW_EMAIL") or None

    # Reuse existing session token — env takes priority, then ~/.bw_session
    existing_token = os.environ.get("BW_SESSION", "").strip() or _load_session_file()
    if existing_token:
        print(f"  Reusing BW_SESSION ({server}) ...", file=sys.stderr)
        if not email:
            email = input("Email: ")
            os.environ["BW_EMAIL"] = email
        s = BwSession(server, email, "")
        s.access_token = existing_token
        # We still need enc/mac keys — fetch profile and derive from token
        # Vaultwarden tokens carry the encrypted vault key; we need the master
        # password to decrypt it. If BW_SESSION is set but BW_MASTER is not,
        # prompt once and cache in env so subshells inherit it.
        master = os.environ.get("BW_MASTER") or getpass.getpass("Master password: ")
        os.environ["BW_MASTER"] = master  # cache for this process
        try:
            profile          = _get_json(f"{server}/api/accounts/profile", existing_token)
            iterations       = _post_json(f"{server}/api/accounts/prelogin",
                                          {"email": email}).get("kdfIterations", 600000)
            master_key       = _pbkdf2(master, email.lower().strip(), iterations)
            enc_key, mac_key = _stretch_key(master_key)
            vault_key_bytes  = _decrypt_cipher_string(profile["key"], enc_key, mac_key)
            s.enc_key = vault_key_bytes[:32]
            s.mac_key = vault_key_bytes[32:64]
            return s
        except Exception as e:
            # Token expired or invalid — fall through to full unlock
            print(f"  BW_SESSION invalid/expired ({e}), re-authenticating ...", file=sys.stderr)
            os.environ.pop("BW_SESSION", None)

    if not email:
        email = input("Email: ")
        os.environ["BW_EMAIL"] = email
    master = os.environ.get("BW_MASTER") or getpass.getpass("Master password: ")
    os.environ["BW_MASTER"] = master
    print(f"  Connecting to {server} ...", file=sys.stderr)
    s = BwSession(server, email, master)
    s.unlock()
    _save_session_file(s.access_token)
    return s


def main() -> None:
    _load_env()

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(
            "Usage: bw_minimal.py <command> [args]\n"
            "\n"
            "Commands:\n"
            "  get <key>          Secure note 'kl: <key>' — print Notes\n"
            "  get-user <key>     Login item 'kl: <key>'  — print Username\n"
            "  get-pass <key>     Login item 'kl: <key>'  — print Password\n"
            "  unlock             Print session token (set as BW_SESSION)\n"
            "  set <key> <value>  Write secret  [not yet implemented]\n"
            "\n"
            "Environment:\n"
            "  BW_SERVER          Vaultwarden URL\n"
            "  BW_EMAIL           Account email\n"
            "  BW_MASTER          Master password (prefer prompt)\n"
            "  BW_SESSION         Existing session token — skips re-auth\n"
            "  KL_DOTFILES_ENV    Path to dotfiles env file\n",
            file=sys.stderr,
        )
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "unlock":
        s = _get_session()
        _save_session_file(s.access_token)
        print(s.access_token)

    elif cmd in ("get", "get-user", "get-pass"):
        if len(sys.argv) < 3:
            print(f"Usage: bw_minimal.py {cmd} <key>", file=sys.stderr)
            sys.exit(1)
        key = sys.argv[2]
        s   = _get_session()
        if cmd == "get":
            val = s.get(key)
        elif cmd == "get-user":
            val = s.get_user(key)
        else:
            val = s.get_pass(key)
        if val is None:
            print(f"Not found: {key}", file=sys.stderr)
            sys.exit(2)
        print(val)

    elif cmd == "set":
        print("set: not yet implemented", file=sys.stderr)
        sys.exit(1)

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
