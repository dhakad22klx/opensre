"""Decide whether a run may proceed, and with which cipher.

Every mismatch between "does this machine encrypt" and "is this store encrypted"
fails the run, in both directions. Encrypting over existing readable objects
would report success while leaving them exposed; syncing with encryption off
would push readable history into a store meant to hold none.
"""

from __future__ import annotations

from dataclasses import dataclass

from infrastructure.filestorage.contracts import ObjectStore, RemoteObject
from infrastructure.filestorage.encryption import envelope
from infrastructure.filestorage.encryption.contracts import Cipher
from infrastructure.filestorage.encryption.error_messages import (
    ENCRYPTED_STORE_MISMATCH,
    MANIFEST_GONE,
    PLAINTEXT_STORE,
)
from infrastructure.filestorage.encryption.keys import resolve_passphrase
from infrastructure.filestorage.encryption.manifest import (
    load_manifest,
    manifest_in_listing,
    new_manifest,
    open_manifest,
    save_manifest,
)
from infrastructure.filestorage.enums import SyncDirection, SyncRootName
from infrastructure.filestorage.errors import (
    EncryptedStoreError,
    ManifestMissingError,
    PlaintextStoreError,
)

_ROOT_HEADS = frozenset(root.value for root in SyncRootName)


@dataclass(frozen=True)
class ResolvedCipher:
    """The cipher for this run, plus the listing already fetched to decide it.

    The listing is handed back so the engine does not pay for a second one: the
    gate has to read the store before any transfer, and that is the same call
    the sync itself would have made.
    """

    cipher: Cipher | None
    listing: list[RemoteObject]


def holds_mirrored_objects(listing: list[RemoteObject]) -> bool:
    """Whether the store already holds sessions or memory.

    Only the mirrored roots count. Another tool's objects sharing the prefix are
    not this feature's business and must not decide whether a sync may run.
    """
    return any(obj.key.partition("/")[0] in _ROOT_HEADS for obj in listing)


def _holds_sealed_objects(store: ObjectStore, listing: list[RemoteObject]) -> bool:
    """Whether the store's mirrored objects are sealed, from one probe read.

    Runs only when there is no manifest to trust: without it a deleted manifest
    makes an encrypted store look plaintext, and the engine would write
    ciphertext over local history. Nothing but an object's bytes can answer,
    but **one** object answers for all of them — a store is either sealed or
    plaintext throughout, because the gate below refuses every run that would
    mix the two. Reading the whole listing instead would make ``status`` and
    every plaintext sync download the entire store to learn what one object
    already says.
    """
    probe = next((obj for obj in listing if obj.key.partition("/")[0] in _ROOT_HEADS), None)
    if probe is None:
        return False
    return envelope.is_sealed(store.get_object(probe.key))


def resolve_cipher(
    store: ObjectStore,
    *,
    encrypted: bool,
    direction: SyncDirection = SyncDirection.BOTH,
    dry_run: bool = False,
) -> ResolvedCipher:
    """Check the store against this machine's setting and build the cipher.

    Creates the manifest when encryption is switched on for an empty store, but
    only for a run that writes to the store anyway. A ``dry_run`` preview and a
    :attr:`SyncDirection.PULL` run must not write to the store.
    """
    listing = store.list_objects("")
    has_manifest = manifest_in_listing(listing)

    if not encrypted:
        if has_manifest:
            raise EncryptedStoreError(ENCRYPTED_STORE_MISMATCH)
        if _holds_sealed_objects(store, listing):
            raise ManifestMissingError(MANIFEST_GONE)
        return ResolvedCipher(cipher=None, listing=listing)

    passphrase = resolve_passphrase()

    if has_manifest:
        return ResolvedCipher(
            cipher=open_manifest(load_manifest(store), passphrase), listing=listing
        )

    if holds_mirrored_objects(listing):
        if _holds_sealed_objects(store, listing):
            raise ManifestMissingError(MANIFEST_GONE)
        raise PlaintextStoreError(PLAINTEXT_STORE)

    manifest, cipher = new_manifest(passphrase)
    if not dry_run and direction is not SyncDirection.PULL:
        save_manifest(store, manifest)
    return ResolvedCipher(cipher=cipher, listing=listing)


__all__ = ["ResolvedCipher", "holds_mirrored_objects", "resolve_cipher"]
