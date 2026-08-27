"""Client-side encryption for remote sync: objects are sealed before upload.

**Re-exports nothing on purpose.** ``contracts`` carries the seal/unseal
protocol and nothing else, so the sync engine can depend on it while its
siblings pull in ``cryptography`` and the OS keyring. Callers import the
submodule they need, so an unencrypted process pays for none of it.
"""

from __future__ import annotations
