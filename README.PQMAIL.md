# PQ Mail YubiKey PIV adapter development

This branch starts the GnuPG side of the PQ Mail / Sequoia smart-card work.
**It does not yet implement or claim working YubiKey PQ signing/decryption.**
The initial change records the integration boundary, reusable backend and
validation requirements before changes to GnuPG's agent/card protocols.

- Branch: `development/yubikey6-piv`
- Upstream mirror: <https://github.com/gpg/gnupg>
- Pinned upstream commit: `b4a6152796619e7f0ab93eb8141de2938989ed95`
  (`scd:piv: Allow key import on all cards`, 2026-11-12).
- Primary upstream repository: <https://dev.gnupg.org/source/gnupg.git>
- Related implementations: [PQ Mail](https://github.com/ve7jtb/pq-mail) and
  [Sequoia adapter branch](https://github.com/ve7jtb/sequoia/tree/development/yubikey6-piv).

The GitHub upstream is a mirror. GnuPG asks contributors to use its mailing
lists or bug tracker rather than opening pull requests against that mirror.
See [upstream Git access](https://gnupg.org/download/git.html) and
[contribution information](https://www.gnupg.org/documentation/mailing-lists.html).

## What the pinned source already supports

The development source includes `--allow-9980`, v6 packet paths, and algorithm
identifiers for ML-DSA-65 + Ed25519, ML-DSA-87 + Ed448, ML-KEM-768 + X25519,
and ML-KEM-1024 + X448. This is source-level evidence, not a claim that a
released GnuPG or this branch has passed interoperability tests with PQ Mail.
Relevant locations are `common/openpgpdefs.h`, `g10/parse-packet.c`,
`g10/pubkey-enc.c`, `g10/sign.c`, and `agent/pkdecrypt.c`.

The current native PIV application in `scd/app-piv.c` supports conventional
RSA and NIST EC operations. It needs additional work for the required PQ and
Edwards component operations. The smart-card signing conversion in
`agent/pksign.c` does not yet accept an ML-DSA card result. The hybrid KEM path
in `agent/pkdecrypt.c` explicitly assumes its ML-KEM private component comes
from a local file; hardware decapsulation needs a separate path there.

## Integration boundary

GnuPG uses `gpg` → `gpg-agent` → `scdaemon` and the Assuan protocols. This is
different from Sequoia's in-process `Signer` and `Decryptor` interfaces.
Reuse of the PKCS#11 helper alone therefore does not make GnuPG support the
same certificates or composite operations.

The first prototype should expose an explicitly selected Assuan card backend
that delegates private component operations to the existing, short-lived
PKCS#11 helpers. It should support the required discovery and operation
subset (`SERIALNO`, `LEARN`, `READKEY`, `READCERT`, `SETDATA`, `PKSIGN`, and
the appropriate decryption/KEM command). Unsupported commands must fail
closed, especially key generation, deletion, import and policy changes.
The exact KEM command/result framing must be fixed after reviewing GnuPG's
existing agent KEM protocol; it must not masquerade as RSA decryption.

GnuPG's packet encoding, signature hashing, composite assembly and KEM
combiner should remain in its existing OpenPGP/agent code where possible.
The adapter supplies component results and must not silently introduce a
second, different OpenPGP implementation. ML-DSA external-μ handling must be
explicit to avoid hashing a precomputed μ again.

The native scdaemon must not retain an exclusive PC/SC or CCID connection
while a separate PKCS#11 process accesses the same key. An external adapter
daemon is the initial approach to evaluate; a direct upstream PIV extension
may ultimately be preferable. This decision needs a working prototype and
review before being presented as an upstream-ready patch.

See the upstream [agent protocol](https://www.gnupg.org/documentation/manuals/gnupg/Agent-Protocol.html)
and [scdaemon protocol](https://www.gnupg.org/documentation/manuals/gnupg/Scdaemon-Protocol.html).

## Reuse and restore

Reuse the existing PKCS#11 backend's single-process public-key check and
private operation. Keep one authorization per logical composite operation;
PINs travel only over local protected pipes and are cleared afterward.
Preserve the device's PIN and touch policies, including no automatic retry
after a failed private operation.

Restore reads the current compressed PQ Mail on-key certificate bundle,
validates its signatures and bounded framing, and compares every component
public key to the live card. The authenticated role/slot manifest selects a
known profile; a device serial alone is not authentication. Card data cannot
choose executable paths, modules or arbitrary commands.

Map the validated public keys to GnuPG keygrips and card references, and save
only public certificates and appropriate shadow-key metadata. Restoring an
identity must not automatically grant ownertrust or contact trust. Existing
certification, signing and encryption roles remain separate.

After native Level 3 hardware support, extend this mechanism to the documented
Level 5 layouts and encrypted software companions. Companion keys remain
operation-scoped in memory, with only authenticated ciphertext persisted.
The message algorithm category and private-key storage protection must be
reported separately, including host-memory/swap risks and classical-only
wrapping where applicable.

## Development milestones

1. Build this pinned development source and its required libraries in an
   isolated prefix. Use a separate temporary `GNUPGHOME`; do not change the
   system GnuPG installation, default agent or user's keyring.
2. Run software-only v6 certificate import, detached/embedded signature and
   encrypted-message interoperability tests against PQ Mail and Sequoia.
   Fix any wire incompatibility independently of card support.
3. Add fake-backend Assuan tests for role/keygrip mapping, serial changes,
   malformed requests, exact digest/μ handling, KEM component ordering,
   cancellation, process failures and secret cleanup.
4. Implement read-only bundle restore and public-key verification, then
   separately add Level 3 ML-DSA/Ed25519 signing and ML-KEM/X25519 decryption.
5. Test explicit, synthetic hardware operations on existing keys. Compare
   all public keys and PIN/touch policies before and after. Do not provision,
   reset, replace keys, send mail or change card data as part of adapter tests.
6. Add supported Level 5 and companion profiles only with the same negative
   tests and bidirectional interoperability evidence.

No hardware test or GnuPG build has been performed as part of this initial
branch setup. Follow upstream `README.GIT` for build prerequisites and
`./autogen.sh` instructions; this branch does not yet add a build wrapper or
an adapter executable.
