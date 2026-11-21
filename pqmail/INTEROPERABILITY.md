# GnuPG connector interoperability

This document describes the tested Level 3 integration, not every algorithm
accepted by upstream GnuPG. Public certificate version, signing security and
message-encryption format are separate choices. **V6 remains the default**;
v5 compatibility is explicit and never selected in response to a cryptographic
failure. Importing a certificate or verifying its signature does not grant trust.

## Format matrix

| Selected profile | Signing in the tested profile | Encryption | Compatibility boundary |
| --- | --- | --- | --- |
| IETF v6, default | ML-DSA-65 + Ed25519 hybrid | ML-KEM-768 + X25519, RFC 9980 algorithm 35 | Full hybrid signing needs the separate GnuPG core work; the Python connector alone is insufficient |
| IETF v4 compatibility | Classical Ed25519 | ML-KEM-768 + X25519, RFC 9980 algorithm 35 | Tested GnuPG 2.5.24 needs `--allow-9980`; the fixed sender is required for the tested v6-PKESK/v4-recipient output |
| GnuPG/LibrePGP v5, opt-in | Classical Ed25519 (algorithm 22) | ML-KEM-768 + X25519, LibrePGP algorithm 8 | Uses the LibrePGP combiner and v5 fingerprint semantics, not the RFC 9980 format; hardware receiver needs component hooks |

The v5 row describes certificates with a v5 primary and v5 hybrid subkey.
Stock GnuPG 2.5.24 ignores the explicit `Key-Version`/`Subkey-Version` batch
fields used by this test; with this batch it creates a **v4 primary plus v5
hybrid subkey** instead. That mixed-version certificate is outside the
demonstrated PQ Mail v5 coverage. The prepared core preserves the explicit
v5 versions; do not generalize this result to every default GnuPG certificate.

The v5 profile uses the dedicated classical Ed25519 signer in slot 88 and the
existing hybrid encryption components in slots 85 (X25519) and 9d (ML-KEM-768).
Public-key matching precedes private use. No key is moved or regenerated to
choose a different certificate encoding. GnuPG performs the protocol-specific
combiner on the host; the bridge returns the requested component operation.

The v5 signature is **not post-quantum**, regardless of the hybrid encryption
subkey. A client presenting this option should identify that signing limitation
rather than label the whole message post-quantum. The tested v4/v5 profiles do
not silently fall back to classical encryption after a hybrid failure.

## GnuPG policy flags

For the tested IETF hybrid format, `--allow-9980` enables the relevant algorithm
policy in GnuPG 2.5.24. It does not install missing core code, provide a secret
key, grant trust, or make a malformed packet valid. It is distinct from the
LibrePGP v5 profile and its algorithm-8 combiner.

In this GnuPG source, `--openpgp` selects the older **RFC 4880** compliance
preset; it is not a request to enable all newer IETF OpenPGP features. That
preset resets `allow_9980`. Consequently these orders are different:

```sh
gpg --allow-9980 --openpgp --decrypt message.pgp
gpg --openpgp --allow-9980 --decrypt message.pgp
```

The first disables the earlier algorithm opt-in. The second re-enables it but
retains the other RFC 4880 preset choices; it is not equivalent to a complete
RFC 9580 policy preset. The newer IETF v6 format used here is RFC 9580 with the
RFC 9980 post-quantum extensions. The integration harness uses an explicit
`allow-9980` setting without layering `--openpgp` over it. See the actual
[compliance-option handling](../g10/gpg.c) when applying additional presets.

Stock GnuPG 2.5.24 was also found to serialize a v4 fingerprint incorrectly in
the tested v6 PKESK sender path. That is independent of flag policy and remains
on the separate [fingerprint serialization fix branch](https://github.com/ve7jtb/gnupg/tree/fix/v6-pkesk-v4-fingerprint-length).
The v4 sender result must not be represented as a pass by the unmodified sender.
The tested stock v5 sender did not require that v4-recipient fix.

## Completed v5 hardware coverage — November 21, 2026

The GnuPG receiver used the prepared 2.5.24 development core with external
component hooks. The independent sender/verifier used stock GnuPG 2.5.24 and
libgcrypt 1.12.4. PQ Mail used a staged candidate jar containing the v5 codec;
its existing PKCS#11 native backend remained unchanged.

| Check | Observed result |
| --- | --- |
| Create a local v5 certificate from existing keygrips | Passed without hardware key generation or card certificate writes |
| GnuPG Ed25519/SHA-512 detached signature | Verified by PQ Mail and stock GnuPG |
| PQ Mail Ed25519/SHA-512 detached signature | Verified by stock GnuPG |
| PQ Mail to GnuPG hybrid decryption | SEIPD v1 integrity, `DECRYPTION_OKAY`, `GOODMDC`, and exact plaintext |
| Stock GnuPG to PQ Mail hybrid decryption | Tag-20 v1 AES-256/OCB authentication and exact plaintext |
| Reused certificate/signature provenance | Original public fixtures matched; both signatures reverified before decryption |
| Device and backend audit | All 24 slot snapshots and selected backend hashes matched before/after and the original baseline |

The card had ten occupied slots and fourteen empty slots. Snapshots covered
public keys, origin, PIN policy and touch policy. The successful decryption
resume reused the completed local certificate and signatures, with one hidden
PIN prompt per logical hybrid decryption. No email was sent. The ciphertexts
were unsigned fixtures; detached signatures were verified separately. This is
not evidence for inline signatures, live v5 PGP/MIME, other hardware layouts,
or v5 identity selection in a released PQ Mail interface.

## Reproduce the v5 hardware test

Use a prepared integration workspace as described in
[README.PQMAIL.md](../README.PQMAIL.md#reusable-five-operation-v4-hardware-harness).
It must contain the verified public-bundle restorer, matching PQ Mail candidate
app/native backend, patched Java runtime, and the separately built GnuPG core
with external-component support. This connector branch deliberately keeps
those core changes separate. The hardware harness currently assumes macOS
paths/Unix sockets; it is not a cross-platform installer.

Set the following environment variables to explicit local paths/values; none
is a PIN or password. `APP_DIR` may name a staged candidate's app directory or
an installed `Contents/app` directory, but it must contain the v5 codec. Keep
`HELPER_CLASSES` and each new result directory outside the app.

```sh
JAVA_HOME="$JAVA_HOME" "$PQ_MAIL_SOURCE/tests/hardware/build-v5-interop.sh" \
  "$APP_DIR" "$HELPER_CLASSES" --self-test

python3 -I -B pqmail/hardware_test.py --profile v5 \
  --root "$INTEGRATION_ROOT" --out "$NEW_PREFLIGHT_DIRECTORY" \
  --serial "$TEST_YUBIKEY_SERIAL" --email "$TEST_EMAIL" \
  --app-dir "$APP_DIR" --java "$JAVA_HOME/bin/java" \
  --helper-classes "$HELPER_CLASSES" --gpg-build "$GPG_BUILD" \
  --preflight-only
```

The driver self-test uses synthetic software fixtures and no card. The v5
hardware preflight restores and verifies public bundle metadata, matches live
public keys, and prepares the isolated shadow-key configuration. It requests
no PIN. It does **not** create the local v5 certificate or run the later v5
message checks: the certificate signatures require the private signer.

With a different fresh result directory, omit `--preflight-only` to run the
five logical operations: local certificate creation, GnuPG signing, PQ Mail
signing, GnuPG decryption and PQ Mail decryption. Each has one hidden Terminal
PIN prompt; existing device touch policies still apply. The v5 helper checks
the exported certificate and recipient binding before message private
operations. Neither bridge nor harness retries a failed operation. On failure,
inspect saved evidence before preparing a targeted resume; account-specific
resume launchers are not published.

The v5 `v5-backend-before.json`/`v5-backend-after.json` audit accompanies the
parent's `before.json`/`after.json` slot audit. Require matching audits and
`unchanged.txt`, not merely an operation PASS marker, before claiming an
unchanged-card successful run. Retain public GnuPG status output, exact-message
comparisons and the Java verification reports. Local results contain device
and certificate metadata and should not be committed to a public repository.

## Disposable software fixtures

[`tests/generate_v5_fixture.py`](tests/generate_v5_fixture.py) and PQ Mail's
`V5SoftwareFixture` helper generate fresh random software Ed25519, X25519 and
ML-KEM-768 keys with public SPKIs and a disposable PKCS#12. The password is the
public test string `synthetic-fixture-password`; never use these keys for real
mail. The generator invokes no PKCS#11 backend, card, account or mail transport.

The **prepared development GnuPG core is required for certificate creation and
signing**: it preserves explicit batch v5 packet versions and passes the raw
Ed25519 digest to the component bridge. Unmodified GnuPG 2.5.24 ignores those
batch version fields and prepends DigestInfo on its card-signing path. The
fixture generator does not modify GnuPG or the production bridge to work around
that behavior. A separate stock GnuPG executable independently verifies the
signature and creates the encrypted fixture.

After building the matching Java helpers, run:

```sh
python3 -I -B pqmail/tests/generate_v5_fixture.py --out "$NEW_FIXTURE_DIRECTORY" \
  --gpg "$GPG_BUILD/g10/gpg" --gpg-agent "$GPG_BUILD/agent/gpg-agent" \
  --gpg-connect-agent "$GPG_BUILD/tools/gpg-connect-agent" \
  --stock-gpg "$STOCK_GPG" --libgcrypt "$LIBGCRYPT_LIBRARY" \
  --java "$JAVA_HOME/bin/java" --helper-classes "$HELPER_CLASSES" \
  --app-dir "$APP_DIR"

"$JAVA_HOME/bin/java" -Djava.awt.headless=true -cp "$APP_DIR/*" \
  dev.hybridmail.LibreOpenPgpTest "$NEW_FIXTURE_DIRECTORY" \
  "$NEW_FIXTURE_DIRECTORY/identity.p12" "$NEW_CODEC_TEST_DIRECTORY"
```

The generated directory contains `identity.p12`, `keys.json`, a disposable-only
marker, `public-v5.pgp`, `detached.pgp`, `plain.txt`, `stock-encrypted.pgp`, public
GnuPG logs and a file-hash manifest. Its fresh GnuPG home is isolated and removed
after its agent is stopped. The fixed test password travels through stdin only.
The directory must not already exist; no user identity or keyring is overwritten.

Fresh generation with the prepared 2.5.24 core and stock GnuPG 2.5.24 passed,
followed by the PQ Mail codec regression: certificate/self-signature parsing,
stock ciphertext recovery, local signing/encryption, tamper/truncation rejection,
recipient binding before private operations, and compressed-v4 verification.
Keep generated private fixtures and local outputs out of the public repository;
only the generator and test sources are published.

## Private-operation diagnostics

The bridge normally discards arbitrary child stderr. An optional absolute
`diagnostic_file` path in its **trusted local** `bridge.json` enables a private
append-only diagnostic containing only fixed algorithm and failure categories,
for example `FAIL X25519 adapter public-key-check`. The file must be a regular,
owner-owned file with no group/other permissions; new files use mode `0600`.
Symlinks and nonregular targets are rejected. The path must never come from a
recipient certificate or incoming message.

Known provider PIN-error phrases become closed `pin-incorrect`, `pin-invalid`
or `pin-expired` categories. Unknown error text remains a generic category;
there are no raw provider messages, PINs, shared secrets or command arguments
in the diagnostic. This improves diagnosis without asserting that every
GnuPG `Not supported` error is a cryptographic incompatibility. Logging failure
never triggers a retry or replaces the original operation failure.

All 59 connector/harness software tests passed, including bounded subprocess
cleanup, diagnostic redaction, v5 sequencing, exact recipient selection and
integrity-status enforcement. Separate isolated end-to-end checks passed
byte-identical transport of synthetic six- and eight-character PINs through
GnuPG, the bridge and component to a fake PKCS#11 adapter for both hybrid
components; those checks used no real PIN or physical card.
