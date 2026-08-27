"""The crypto under remote sync: nothing readable leaves, nothing fails open.

Covers the envelope format, the cipher that picks a key per object, and key
derivation. Every failure — a wrong passphrase, a moved object, a manifest that
asks this machine for an absurd amount of work — must surface as this feature's
own error rather than as a ``cryptography`` exception or a silent plaintext
path. Wiring these into the sync engine lands separately.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from config.constants.filestorage import REMOTE_SYNC_KEY_CACHE_ENV, REMOTE_SYNC_PASSPHRASE_ENV
from infrastructure.filestorage.encryption import envelope, keys
from infrastructure.filestorage.encryption.cipher import ManifestCipher
from infrastructure.filestorage.encryption.keys import (
    MIN_SCRYPT_N,
    ScryptParams,
    derive_root_key,
    generate_root_secret,
    generate_salt,
)
from infrastructure.filestorage.errors import (
    MissingPassphraseError,
    RemoteSyncEncryptionError,
    UndecryptableObjectError,
    WrongPassphraseError,
)

PASSPHRASE = "correct horse battery staple"
# Planted in a payload. If any transformation ever fails open, this shows up in
# the sealed bytes and the assertion below fails loudly.
LEAKED_SECRET = b"db-password-CANARY-must-never-reach-the-store"

OBJECT_KEY = "sessions/abc.jsonl"
# The cheapest cost this machine will honour, so derivation tests stay fast.
CHEAP_PARAMS = ScryptParams(n=MIN_SCRYPT_N, r=8, p=1)
SALT = b"salt-of-sixteen!"


def _cipher() -> ManifestCipher:
    return ManifestCipher(derive_root_key(generate_root_secret()))


# ── The envelope ────────────────────────────────────────────────────────────


def test_sealing_hides_the_plaintext_and_unsealing_gives_it_back() -> None:
    # Arrange
    cipher = _cipher()

    # Act
    sealed = cipher.seal(OBJECT_KEY, LEAKED_SECRET)

    # Assert
    assert LEAKED_SECRET not in sealed
    assert cipher.unseal(OBJECT_KEY, sealed) == LEAKED_SECRET


def test_sealing_the_same_bytes_twice_is_byte_identical() -> None:
    """The engine compares a freshly sealed file against the store's ETag.

    A random nonce would make every file look modified, so every sync would
    re-upload everything. The nonce is derived from the plaintext instead.
    """
    # Arrange
    cipher = _cipher()

    # Act / Assert
    assert cipher.seal(OBJECT_KEY, b"contents") == cipher.seal(OBJECT_KEY, b"contents")


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
    """Malformed input must be this feature's error, not an IndexError."""
    with pytest.raises(UndecryptableObjectError):
        _cipher().unseal(OBJECT_KEY, payload)


# ── Choosing a key per object ───────────────────────────────────────────────


def test_an_object_sealed_under_a_retired_key_still_opens() -> None:
    """Carrying more than one generation is what keeps a re-key readable."""
    # Arrange
    retired = derive_root_key(generate_root_secret())
    sealed = ManifestCipher(retired).seal(OBJECT_KEY, LEAKED_SECRET)
    current = ManifestCipher(derive_root_key(generate_root_secret()), retired=(retired,))

    # Act / Assert
    assert current.unseal(OBJECT_KEY, sealed) == LEAKED_SECRET


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


def test_the_wrong_passphrase_does_not_unwrap_the_root_secret() -> None:
    # Arrange
    wrapped = keys.wrap_root_secret(
        keys.derive_kek(PASSPHRASE, SALT, CHEAP_PARAMS), generate_root_secret()
    )
    other = keys.derive_kek("not the right one", SALT, CHEAP_PARAMS)

    # Act / Assert
    with pytest.raises(WrongPassphraseError):
        keys.unwrap_root_secret(other, wrapped)


def test_truncated_key_material_is_reported_rather_than_indexed_into() -> None:
    """A damaged manifest must not reach AES-GCM as an empty ciphertext."""
    # Arrange
    kek = keys.derive_kek(PASSPHRASE, SALT, CHEAP_PARAMS)

    # Act / Assert
    with pytest.raises(WrongPassphraseError):
        keys.unwrap_root_secret(kek, b"\x00" * 8)


# ── Deriving the KEK, and the cache in front of it ──────────────────────────


def _fresh_kek(passphrase: str = PASSPHRASE) -> bytes:
    """The KEK ``derive_kek`` must produce when no cache entry applies."""
    return Scrypt(
        salt=SALT, length=keys.KEK_LEN, n=CHEAP_PARAMS.n, r=CHEAP_PARAMS.r, p=CHEAP_PARAMS.p
    ).derive(passphrase.encode("utf-8"))


def _cache_entry(passphrase: str, kek: bytes) -> str:
    return json.dumps(
        {
            "fingerprint": keys._cache_fingerprint(passphrase, SALT, CHEAP_PARAMS),
            "kek": base64.b64encode(kek).decode(),
        }
    )


def test_a_matching_cache_entry_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard for the miss tests below: a hit must be observable at all."""
    # Arrange: a value scrypt would never produce, so a hit is unmistakable.
    planted = b"\x2a" * keys.KEK_LEN
    monkeypatch.setenv(REMOTE_SYNC_KEY_CACHE_ENV, _cache_entry(PASSPHRASE, planted))

    # Act / Assert
    assert keys.derive_kek(PASSPHRASE, SALT, CHEAP_PARAMS) == planted


def test_a_warm_cache_cannot_answer_for_a_different_passphrase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cached KEK must not stand in for checking the passphrase.

    Keyed on the salt alone the cache answered before the supplied passphrase
    was looked at, so a wrong one opened the store — and unwrapping afterwards
    does not catch it, because the cached KEK unwraps the manifest correctly.
    """
    # Arrange: a cache warmed by one passphrase.
    monkeypatch.setenv(REMOTE_SYNC_KEY_CACHE_ENV, _cache_entry(PASSPHRASE, b"\x2a" * keys.KEK_LEN))

    # Act / Assert: another passphrase derives its own KEK instead.
    assert keys.derive_kek("not the right one", SALT, CHEAP_PARAMS) == _fresh_kek(
        "not the right one"
    )


@pytest.mark.parametrize(
    ("label", "raw"),
    [
        ("not JSON at all", "{{"),
        ("JSON that is not a mapping", "[]"),
        ("for another passphrase", _cache_entry("someone else's", b"\x2a" * keys.KEK_LEN)),
        ("key is not a string", '{"fingerprint": "x", "kek": 7}'),
        ("key is not base64", '{"fingerprint": "x", "kek": "!!!"}'),
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


def test_a_truncated_cached_key_reads_as_a_miss(monkeypatch: pytest.MonkeyPatch) -> None:
    """A short key must not ride a matching fingerprint into AES-GCM.

    The fingerprint says the entry is for this passphrase, so nothing later
    re-checks it; the key went straight to the unwrap and failed there as a raw
    ``ValueError`` that re-deriving could not clear.
    """
    # Arrange
    monkeypatch.setenv(REMOTE_SYNC_KEY_CACHE_ENV, _cache_entry(PASSPHRASE, b"\x00"))

    # Act / Assert
    assert keys.derive_kek(PASSPHRASE, SALT, CHEAP_PARAMS) == _fresh_kek()


# ── What a store's manifest may ask this machine to compute ─────────────────


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [
        ("n is not a power of two", {"n": 100_000}),
        ("n would allocate a terabyte", {"n": 2**30}),
        ("n below the supported floor", {"n": 1024}),
        ("n is not even a finite number", {"n": 1e400}),
        ("r past the supported ceiling", {"r": 1 << 20}),
        ("p past the supported ceiling", {"p": 1 << 20}),
    ],
)
def test_hostile_kdf_parameters_cannot_dictate_the_work_factor(
    label: str, kwargs: dict[str, object]
) -> None:
    """These values arrive from the store, so their cost is untrusted.

    scrypt allocates ``128 * n * r`` bytes before any passphrase is checked, so
    an unbounded ``n`` is a memory bomb anyone with write access to the store
    can plant. A floor matters too: a cost lowered to nothing would make the
    passphrase cheap to attack offline.
    """
    with pytest.raises(RemoteSyncEncryptionError):
        ScryptParams(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("label", "salt"),
    [("too short to be one", b"x"), ("implausibly long", b"x" * 4096)],
)
def test_an_implausible_salt_is_refused(label: str, salt: bytes) -> None:
    with pytest.raises(RemoteSyncEncryptionError):
        keys.validated_salt(salt)


def test_the_shipped_defaults_stay_inside_the_bounds() -> None:
    """The guard must not reject the parameters opensre itself writes."""
    # Act / Assert
    assert ScryptParams() == ScryptParams(n=keys.SCRYPT_N, r=keys.SCRYPT_R, p=keys.SCRYPT_P)
    assert keys.validated_salt(generate_salt()) is not None


# ── Finding the passphrase ──────────────────────────────────────────────────


def test_the_passphrase_resolves_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setenv(REMOTE_SYNC_PASSPHRASE_ENV, PASSPHRASE)

    # Act / Assert
    assert keys.resolve_passphrase() == PASSPHRASE


def test_no_passphrase_anywhere_is_refused_rather_than_prompted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """This runs headless as well as in a terminal; a hidden prompt reads as a hang."""
    # Arrange
    monkeypatch.delenv(REMOTE_SYNC_PASSPHRASE_ENV, raising=False)

    # Act / Assert
    with pytest.raises(MissingPassphraseError):
        keys.resolve_passphrase()
