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
# Environment:
#   BW_SERVER   Vaultwarden URL (default: https://vault.bitwarden.com)
#   BW_EMAIL    Account email
#   BW_MASTER   Master password (avoid in production — use prompt)
#   BW_SESSION  Existing session token
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
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_SERVER = "https://vault.bitwarden.com"
ITEM_PREFIX = "kl: "


# ---------------------------------------------------------------------------
# Crypto helpers (stdlib only)
# ---------------------------------------------------------------------------

def _pbkdf2(password: str, salt: str, iterations: int, keylen: int = 32) -> bytes:
    """Derive master key via PBKDF2-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
        dklen=keylen,
    )


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869) — used to derive enc/mac keys from master key."""
    t = b""
    okm = b""
    for i in range(1, -(-length // 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), "sha256").digest()
        okm += t
    return okm[:length]


def _stretch_key(master_key: bytes) -> tuple[bytes, bytes]:
    """Stretch master key into enc_key + mac_key (Bitwarden key expansion)."""
    enc_key = _hkdf_expand(master_key, b"enc", 32)
    mac_key = _hkdf_expand(master_key, b"mac", 32)
    return enc_key, mac_key


def _decrypt_cipher_string(cipher_str: str, enc_key: bytes, mac_key: bytes) -> str:
    """
    Decrypt a Bitwarden CipherString (type 2 = AES-CBC-256 + HMAC-SHA256).
    Format: 2.<iv_b64>|<ct_b64>|<mac_b64>
    """
    # Lazy import — AES not in stdlib, use openssl via subprocess as fallback
    try:
        from Crypto.Cipher import AES  # pycryptodome if available
        _decrypt_aes = _decrypt_aes_pycrypto
    except ImportError:
        _decrypt_aes = _decrypt_aes_openssl

    if not cipher_str.startswith("2."):
        raise ValueError(f"Unsupported CipherString type: {cipher_str[:2]}")

    _, payload = cipher_str.split(".", 1)
    parts = payload.split("|")
    iv = base64.b64decode(parts[0])
    ct = base64.b64decode(parts[1])
    mac = base64.b64decode(parts[2])

    # Verify HMAC
    expected_mac = hmac.new(mac_key, iv + ct, "sha256").digest()
    if not hmac.compare_digest(expected_mac, mac):
        raise ValueError("HMAC verification failed — wrong key or corrupted data")

    return _decrypt_aes(ct, enc_key, iv)


def _decrypt_aes_openssl(ct: bytes, key: bytes, iv: bytes) -> str:
    """AES-256-CBC decrypt via openssl subprocess (no pycryptodome needed)."""
    import subprocess, tempfile
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
            raise ValueError(f"openssl decrypt failed: {result.stderr.decode()}")
        return result.stdout.decode("utf-8")
    finally:
        os.unlink(ct_path)


def _decrypt_aes_pycrypto(ct: bytes, key: bytes, iv: bytes) -> str:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16).decode("utf-8")


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _post(url: str, data: dict, headers: Optional[dict] = None) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _get_json(url: str, token: str) -> dict:
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


# ---------------------------------------------------------------------------
# Vaultwarden session
# ---------------------------------------------------------------------------

class BwSession:
    def __init__(self, server: str, email: str, master: str):
        self.server = server.rstrip("/")
        self.email = email
        self.master = master
        self.access_token: Optional[str] = None
        self.enc_key: Optional[bytes] = None
        self.mac_key: Optional[bytes] = None

    def unlock(self) -> str:
        """Login + derive keys. Returns access token."""
        # 1. Prelogin — get KDF params
        prelogin = _post(
            f"{self.server}/api/accounts/prelogin",
            {"email": self.email},
            {"Content-Type": "application/json"},
        )
        # Vaultwarden returns JSON — re-post as JSON
        prelogin = self._post_json(f"{self.server}/api/accounts/prelogin",
                                   {"email": self.email})
        iterations = prelogin.get("kdfIterations", 600000)

        # 2. Derive master key
        master_key = _pbkdf2(self.master, self.email, iterations)

        # 3. Derive master password hash (sent to server)
        master_hash_raw = _pbkdf2(self.master, self.email, iterations)
        master_hash = base64.b64encode(
            hashlib.pbkdf2_hmac("sha256", master_hash_raw,
                                self.master.encode(), 1)
        ).decode()

        # 4. Login
        token_resp = _post(
            f"{self.server}/identity/connect/token",
            {
                "grant_type": "password",
                "username": self.email,
                "password": master_hash,
                "scope": "api offline_access",
                "client_id": "cli",
                "deviceType": "8",
                "deviceIdentifier": "bw-minimal",
                "deviceName": "bw-minimal",
            },
        )
        self.access_token = token_resp["access_token"]

        # 5. Get vault key + decrypt with master key
        profile = _get_json(f"{self.server}/api/accounts/profile",
                            self.access_token)
        vault_key_cipher = profile["key"]
        enc_key, mac_key = _stretch_key(master_key)
        vault_key_raw = _decrypt_cipher_string(vault_key_cipher, enc_key, mac_key)
        self.enc_key = vault_key_raw[:32].encode() if isinstance(vault_key_raw, str) \
            else vault_key_raw[:32]
        self.mac_key = vault_key_raw[32:64].encode() if isinstance(vault_key_raw, str) \
            else vault_key_raw[32:64]

        return self.access_token

    def _post_json(self, url: str, data: dict) -> dict:
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    def get(self, key: str) -> Optional[str]:
        """Find secure note by name and return decrypted value."""
        name = f"{ITEM_PREFIX}{key}"
        ciphers = _get_json(f"{self.server}/api/ciphers", self.access_token)
        for item in ciphers.get("Data", []):
            item_name = _decrypt_cipher_string(
                item["Name"], self.enc_key, self.mac_key
            )
            if item_name == name and item.get("Type") == 2:  # secure note
                return _decrypt_cipher_string(
                    item["Notes"], self.enc_key, self.mac_key
                )
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _get_session() -> BwSession:
    server = os.environ.get("BW_SERVER", DEFAULT_SERVER)
    email = os.environ.get("BW_EMAIL") or input("Email: ")
    master = os.environ.get("BW_MASTER") or getpass.getpass("Master password: ")
    s = BwSession(server, email, master)
    s.unlock()
    return s


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: bw_minimal.py get <key> | set <key> <value> | unlock",
              file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "unlock":
        s = _get_session()
        print(s.access_token)

    elif cmd == "get":
        if len(sys.argv) < 3:
            print("Usage: bw_minimal.py get <key>", file=sys.stderr)
            sys.exit(1)
        s = _get_session()
        val = s.get(sys.argv[2])
        if val is None:
            print(f"Not found: {sys.argv[2]}", file=sys.stderr)
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
