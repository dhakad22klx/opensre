"""The envelope, the key it names, and the key material behind it.

Unit-level cover for the failure modes a sync cannot reach: a payload that is
not an envelope at all, an object sealed under a key generation this machine
does not hold, and key material that is damaged rather than merely wrong.
Feature behaviour — what a sync does with all this — lives in
``test_remote_sync_encryption.py``.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from config.constants.filestorage import REMOTE_SYNC_KEY_CACHE_ENV
from infrastructure.filestorage.encryption import envelope, keys
from infrastructure.filestorage.encryption.cipher import ManifestCipher
from infrastructure.filestorage.encryption.keys import (
    MIN_SCRYPT_N,
    ScryptParams,
    derive_root_key,
    generate_root_secret,
)
from infrastructure.filestorage.errors import UndecryptableObjectError, WrongPassphraseError

PASSPHRASE = "correct horse battery staple"
OBJECT_KEY = "sessions/abc.jsonl"
# The cheapest cost this machine will honour, so derivation tests stay fast.
CHEAP_PARAMS = ScryptParams(n=MIN_SCRYPT_N, r=8, p=1)
SALT = b"salt-of-sixteen!"


def _cipher() -> ManifestCipher:
    return ManifestCipher(derive_root_key(generate_root_secret()))


# ── A payload that is not an envelope ───────────────────────────────────────


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("plaintext written before encryption was on", b'{"turn": 1}'),
        ("too short to hold a header", envelope.MAGIC + b"\x01"),
        (
            "a version this release does not understand",
            envelope.MAGIC + bytes([envelope.VERSION + 1]) + b"\x00" * (envelope.HEADER_LEN - 5),
        ),
    ],
)
def test_a_payload_that_is_not_an_envelope_is_reported_as_such(label: str, payload: bytes) -> None:
    """Malformed input must be this feature's error, not an ``IndexError``."""
    with pytest.raises(UndecryptableObjectError):
        _cipher().unseal(OBJECT_KEY, payload)


def test_an_object_moved_to_another_key_will_not_open() -> None:
    """The object key is authenticated, so copies cannot be passed off."""
    # Arrange
    cipher = _cipher()
    sealed = cipher.seal("memory/real.md", b"contents")

    # Act / Assert
    with pytest.raises(UndecryptableObjectError):
        cipher.unseal("memory/impostor.md", sealed)


def test_an_altered_object_will_not_open() -> None:
    # Arrange
    cipher = _cipher()
    sealed = bytearray(cipher.seal(OBJECT_KEY, b"contents"))
    sealed[-1] ^= 0xFF

    # Act / Assert
    with pytest.raises(UndecryptableObjectError):
        cipher.unseal(OBJECT_KEY, bytes(sealed))


# ── Every envelope names the key that sealed it ─────────────────────────────


def test_an_object_sealed_under_a_retired_key_still_opens() -> None:
    """Carrying more than one generation is what keeps a re-keyed store readable."""
    # Arrange
    retired = derive_root_key(generate_root_secret())
    sealed = ManifestCipher(retired).seal(OBJECT_KEY, b"contents")
    current = ManifestCipher(derive_root_key(generate_root_secret()), retired=(retired,))

    # Act / Assert
    assert current.unseal(OBJECT_KEY, sealed) == b"contents"


def test_an_object_naming_a_key_this_machine_lacks_will_not_open() -> None:
    # Arrange
    stranger = ManifestCipher(derive_root_key(generate_root_secret()))
    sealed = stranger.seal(OBJECT_KEY, b"contents")

    # Act / Assert
    with pytest.raises(UndecryptableObjectError):
        _cipher().unseal(OBJECT_KEY, sealed)


# ── Wrapping the root secret ────────────────────────────────────────────────


def test_a_root_secret_survives_a_wrap_and_unwrap() -> None:
    # Arrange
    kek = keys.derive_kek(PASSPHRASE, SALT, CHEAP_PARAMS)
    secret = generate_root_secret()

    # Act / Assert
    assert keys.unwrap_root_secret(kek, keys.wrap_root_secret(kek, secret)) == secret


def test_truncated_key_material_is_reported_rather_than_indexed_into() -> None:
    """A damaged manifest must not reach AES-GCM as an empty ciphertext."""
    # Arrange
    kek = keys.derive_kek(PASSPHRASE, SALT, CHEAP_PARAMS)

    # Act / Assert
    with pytest.raises(WrongPassphraseError):
        keys.unwrap_root_secret(kek, b"\x00" * 8)


# ── The cache in front of the derivation ────────────────────────────────────


def _fresh_kek() -> bytes:
    """The KEK ``derive_kek`` must produce when no cache entry applies."""
    return Scrypt(
        salt=SALT, length=keys.KEK_LEN, n=CHEAP_PARAMS.n, r=CHEAP_PARAMS.r, p=CHEAP_PARAMS.p
    ).derive(PASSPHRASE.encode("utf-8"))


def _cache_entry(passphrase: str, kek: bytes) -> str:
    return json.dumps(
        {
            "fingerprint": keys._cache_fingerprint(passphrase, SALT, CHEAP_PARAMS),
            "kek": base64.b64encode(kek).decode(),
        }
    )


def test_a_matching_cache_entry_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard for the miss cases below: a hit must be observable at all."""
    # Arrange: a value scrypt would never produce, so a hit is unmistakable.
    planted = b"\x2a" * keys.KEK_LEN
    monkeypatch.setenv(REMOTE_SYNC_KEY_CACHE_ENV, _cache_entry(PASSPHRASE, planted))

    # Act / Assert
    assert keys.derive_kek(PASSPHRASE, SALT, CHEAP_PARAMS) == planted


@pytest.mark.parametrize(
    ("label", "raw"),
    [
        ("not JSON at all", "{{"),
        ("JSON that is not a mapping", "[]"),
        ("for another passphrase", _cache_entry("someone else's", b"\x2a" * keys.KEK_LEN)),
        ("key is not a string", '{"fingerprint": "x", "kek": 7}'),
        ("key is not base64", '{"fingerprint": "x", "kek": "!!!"}'),
        # A short key must not ride a matching fingerprint into AES-GCM: nothing
        # downstream re-checks the entry, so it failed there as a raw ValueError
        # that re-deriving could not clear.
        ("key too short to be one", _cache_entry(PASSPHRASE, b"\x00")),
    ],
)
def test_an_unusable_cache_entry_reads_as_a_miss(
    label: str, raw: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A miss costs one derivation; nothing here may raise out of ``derive_kek``."""
    # Arrange
    monkeypatch.setenv(REMOTE_SYNC_KEY_CACHE_ENV, raw)

    # Act / Assert
    assert keys.derive_kek(PASSPHRASE, SALT, CHEAP_PARAMS) == _fresh_kek()
