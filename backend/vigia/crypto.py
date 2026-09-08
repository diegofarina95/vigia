"""Encryption at rest for OAuth refresh tokens (Fernet / AES-128-CBC + HMAC).

The key comes from VIGIA_ENCRYPTION_KEY. If unset (self-host convenience)
a key is generated once and persisted to <data_dir>/fernet.key with 0600
permissions — losing that file means every org must reconnect.
"""
from __future__ import annotations

import logging
import os

from cryptography.fernet import Fernet

from .config import Settings

log = logging.getLogger(__name__)


def load_or_create_key(settings: Settings) -> bytes:
    if settings.encryption_key:
        return settings.encryption_key.encode()

    key_path = os.path.join(settings.data_dir, "fernet.key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as fh:
            return fh.read().strip()

    os.makedirs(settings.data_dir, exist_ok=True)
    key = Fernet.generate_key()
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    log.warning(
        "VIGIA_ENCRYPTION_KEY not set — generated a key at %s. "
        "Back it up; set it via env in production.",
        key_path,
    )
    return key


class TokenCipher:
    def __init__(self, key: bytes) -> None:
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        return self._fernet.decrypt(ciphertext.encode()).decode()
