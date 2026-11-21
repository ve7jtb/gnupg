# PQ Mail GnuPG PIV connector

This development branch contains an Assuan component bridge to PQ Mail's
PKCS#11 helpers. The bridge maps verified public keys to component keygrips
and delegates existing-key signing and decapsulation. GnuPG retains OpenPGP
packet handling, signature digest selection and the hybrid KEM combiner.

- Branch: [`development/yubikey6-piv`](https://github.com/ve7jtb/gnupg/tree/development/yubikey6-piv)
- Related projects: [PQ Mail](https://github.com/ve7jtb/pq-mail) and
  [Sequoia PIV connector](https://github.com/ve7jtb/sequoia/tree/development/yubikey6-piv).
- Packet/composite-signature and PKCS#12 implementation work is maintained
  separately on `feature/rfc9980-software-p12`. This adapter branch does not
  include or replace those GnuPG core changes. In particular, installing the
  Python connector alone does not add full v6 hybrid signing to stock GnuPG.
- The unrelated upstream serialization fix remains on
  [`fix/v6-pkesk-v4-fingerprint-length`](https://github.com/ve7jtb/gnupg/tree/fix/v6-pkesk-v4-fingerprint-length).

## Integration boundary

`pqmail/bridge.py` implements a restricted Assuan server: discovery, keygrip
metadata, public-key reads, bounded `SETDATA`, component signing and component
decapsulation. It rejects provisioning and unsupported commands. It does not
hold a PC/SC connection, write certificates or change device policies.

`pqmail/component.py` routes the operation through PQ Mail's single-process
PKCS#11 wrappers. Trusted local configuration supplies executable/library paths,
device serial and reviewed SPKI-to-slot mappings. Card data, certificates and
incoming messages must never choose executable paths. The PKCS#11 backend
compares the complete public key with the selected live key before use.

A restore integration must first verify the compressed public bundle signature
and its live public-key matches, then construct local bridge metadata. Discovery
from cached metadata is not itself a fresh device-authentication check. Import
and successful signature verification do not grant ownertrust or contact trust.

Supported Level 3 component roles include ML-DSA-65, Ed25519, ML-KEM-768 and
X25519. Current hardware routing covers signing, certification and compatibility
slots. V6 is the preferred wire profile; the optional v5 metadata describes
classical Ed25519 signatures and LibrePGP hybrid encryption. A certificate
version does not itself establish post-quantum signature security. See the
[format and interoperability matrix](pqmail/INTEROPERABILITY.md).

## Review fixes, November 21, 2026

Three findings in this connector were addressed during the seven-issue
PQ Mail/frontend/connector review:

1. Classical Ed25519 accepts SHA-256 OpenPGP digests as well as SHA-384/SHA-512.
   The shared PQ Mail Python adapter and native signing helper also require the
   corresponding update; older helpers still reject the 32-byte request.
   ML-DSA's external-mu and digest-profile restrictions are unchanged.
2. `pqmail/apply.py` checks all exact source anchors before changing a file,
   stages originals and replacements, and rolls back ordinary replacement
   failures. It is not power-loss atomic across multiple files; discard a
   staging tree interrupted by process termination or power loss.
3. Bridge and component processes share nonblocking pipe supervision. Input,
   both output streams and child completion share a deadline. Output limits
   apply while reading, and arbitrary child stderr is never echoed to the caller.
   No background I/O thread can retain a PIN/request after return.

The trusted outer bridge sets `PQMAIL_SUPERVISED_PROCESS_GROUP=1`; nested
component/adapters/native helpers remain in its isolated process group. The
component has a 110-second deadline inside the outer 120-second deadline.
Cleanup terminates the process group on success or failure, including a native
helper left behind by an exited wrapper. Update PQ Mail's shared adapters too:
older versions start native helpers in separate sessions and defeat this
end-to-end cleanup. Do not set the opt-in for an unsupervised invocation.

PINs travel through local pipes, never command arguments, environment values or
files. Mutable buffers are cleared where possible; Python/OS copies, swap and
crash dumps remain host-memory risks. A failed private operation is not retried.
The current bounded supervisor supports macOS/Linux and fails closed elsewhere.

## Tests and evidence

Run the software-only connector tests from this repository:

```sh
python3 -B -m unittest discover -s pqmail/tests -v
```

The connector and reusable harness now pass **59 software-only tests**. Coverage
includes SHA-256 compatibility, retained ML-DSA restrictions, patch rollback,
blocked stdin, output limits, nested process cleanup, selected installed-jar
paths, real GnuPG status lines, error stopping and final audits after failure.
The added v5 tests cover exact component selection, two signers and two
receivers, public preflight before message operations, required integrity
statuses and backend audits. Metadata tests cover the absence of a unique PIV
OpenPGP fingerprint hint; diagnostic tests reject arbitrary/oversized stderr
and unsafe log destinations.
The identical supervisor also passed seven executions on the separate software
branch. Patch anchors were checked against clean GnuPG 2.5.23 and 2.5.24 sources.
These automated checks use temporary fixtures and synthetic subprocesses;
they do not access accounts, ask for a PIN or contact hardware.

An authorized hardware rerun with the reviewed installed Mac backend and
fixed GnuPG sender passed all **five private operations**:

| Operation | Result |
| --- | --- |
| GnuPG v4 Ed25519/SHA-512 detached signing | Verified independently by stock GnuPG and installed PQ Mail |
| GnuPG decrypts PQ Mail's ML-KEM-768/X25519 message | Integrity passed; plaintext matched exactly |
| GnuPG decrypts the fixed GnuPG sender's ML-KEM-768/X25519 message | Integrity passed; plaintext matched exactly |
| GnuPG v4 Ed25519/SHA-256 detached signing | Verified independently by stock GnuPG and installed PQ Mail |
| Installed PQ Mail decrypts the fixed GnuPG sender's v6-PKESK/v4-recipient message | Integrity and exact plaintext passed; detached Ed25519 signature verified separately |

Both signatures are **classical Ed25519**; the three decryptions are hybrid.
The test ciphertexts contain no inline signature. The separate detached
signature check must not be described as an inline-signed encrypted message.
Stock GnuPG's isolated verifier may report unknown ownertrust: successful
cryptographic verification does not confer contact trust.

Before/after snapshots matched for all **24 ordinary PIV slots: 10 occupied
and 14 empty**, including public keys, origin, PIN policy and touch policy.
The installed backend hashes also matched. No hardware keys, token
certificates, touch policies or mail were changed by the tests. These counts
record the tested card's existing state; the harness does not require every
future card to have exactly ten occupied slots.

The fixed sender is explicitly distinguished from stock GnuPG: stock 2.5.24
emitted an incorrectly padded v4 fingerprint in a v6 PKESK. The generic fix
remains on the separate
[`fix/v6-pkesk-v4-fingerprint-length`](https://github.com/ve7jtb/gnupg/tree/fix/v6-pkesk-v4-fingerprint-length)
branch. Device-specific launchers, credentials, account certificates and local
hardware result files are not published.

## V5 signing and hybrid decryption — November 21, 2026

Existing-key hardware testing completed the optional **v5 compatibility**
profile with GnuPG 2.5.24, this connector and the staged PQ Mail v5 build:

| Operation | Result |
| --- | --- |
| Local v5 certificate creation from existing component keygrips | Passed; no hardware key generation or card certificate write |
| GnuPG Ed25519/SHA-512 detached signing | Verified by PQ Mail and stock GnuPG |
| PQ Mail Ed25519/SHA-512 detached signing | Verified by stock GnuPG |
| GnuPG decrypts PQ Mail's ML-KEM-768/X25519 ciphertext | `DECRYPTION_OKAY`, `GOODMDC` and exact plaintext |
| PQ Mail decrypts stock GnuPG's ML-KEM-768/X25519 ciphertext | Tag-20 OCB authentication and exact plaintext; detached signature verified separately |

The message signer uses the existing dedicated **Ed25519 slot 88**. Hybrid
decryption uses **ML-KEM-768 in 9d and X25519 in 85**, with combining performed
on the host. This v5 profile uses LibrePGP algorithm 8 and its combiner; it is
not the RFC 9980 algorithm-35 format used by the v4/v6 IETF profile. V5
signatures remain **classical**, even when the accompanying encryption is
hybrid. V6 remains the default; there is no automatic downgrade after failure.

The certificate and both signatures were retained and reverified when resuming
the two decryptions. The successful final run's before/after snapshots also
matched the original baseline across all **24 ordinary slots (10 occupied,
14 empty)**, including public keys, origin and PIN/touch policies. Selected
PQ Mail backend hashes matched throughout. No hardware keys, card certificates
or policies were changed, and no email was sent. These are detached-signature
and encrypted-fixture tests, not inline-signed messages or a live v5 mail-UI test.

The selected PQ Mail jar included the new v5 codec; this result does not assert
that every installed release or desktop identity selector supports v5. The
GnuPG receiver used the separately prepared development core with hardware
component hooks; the sender and independent verifier used stock GnuPG 2.5.24.
See [version boundaries and reproduction](pqmail/INTEROPERABILITY.md). This
coverage requires a v5 primary and v5 subkey; it does not establish support for
the mixed v4-primary/v5-subkey certificate created when stock GnuPG ignores
these explicit batch version fields.

A prior generic `Not supported` response did not establish an unsupported
algorithm. The connector now optionally records only a fixed failure stage and
algorithm in a local diagnostic file. It never records arbitrary child stderr,
PINs or shared secrets, and it never retries a failed private operation. See
[private-operation diagnostics](pqmail/INTEROPERABILITY.md#private-operation-diagnostics).

## Reusable five-operation v4 hardware harness

[`pqmail/review_v4_test.py`](pqmail/review_v4_test.py) runs the three-operation
connector test, then the SHA-256 and installed-PQ-Mail receive regressions.
Device selection and installed application/runtime paths are explicit local
arguments. The default development GnuPG build is
`work/gnupg-releases/gnupg-2.5.24` under `--root`, overridable with `--gpg-build`.
Stock GnuPG and ykman default to the Homebrew Mac paths shown by `--help` and
can also be overridden. This is a Mac integration harness, not an installer.

`--root` identifies a prepared multi-project integration workspace containing:

- Sequoia's built `work/sequoia/target/debug/piv-restore` and read-only snapshot
  module at `work/sequoia/piv-adapter/hardware/run.py`;
- a tested development GnuPG build with the connector core hooks and fixed
  v6-PKESK sender (`g10/gpg`, `agent/gpg-agent`, `tools/gpg-connect-agent`);
- PQ Mail's installed Mac app, patched Java runtime and the public Java test
  drivers compiled using the commands below.

The experimental GnuPG core is separate from this connector branch. Compiling
its unchanged upstream C sources alone does not add all hybrid operations.
The Python connector never silently changes the installed GnuPG or PQ Mail.

Build the public drivers from the matching
[PQ Mail hardware-test sources](https://github.com/ve7jtb/pq-mail/tree/feature/on-key-certificates/tests/hardware).
Set `PQ_MAIL_SOURCE`, `JAVA_HOME`, `APP_DIR` and `HELPER_CLASSES` to local paths;
`APP_DIR` names the chosen app's `Contents/app` directory. Keep helper classes
and result directories outside the application bundle.

```sh
JAVA_HOME="$JAVA_HOME" "$PQ_MAIL_SOURCE/tests/hardware/build-v4-interop.sh" \
  "$APP_DIR" "$HELPER_CLASSES" --self-test
```

The driver-only class directory and the selected installed app's jars are the
entire Java classpath. The helpers check that `OpenPgp.class` actually came
from that app's `hybrid-mail.jar`, rejecting a shadow copy. The self-test uses
disposable software fixtures and does not request a PIN or access a card.

First run the PIN-free public preflight with a new result directory:

```sh
python3 -I -B pqmail/review_v4_test.py --root "$INTEGRATION_ROOT" \
  --out "$NEW_RESULT_DIRECTORY" --serial "$TEST_YUBIKEY_SERIAL" \
  --app-dir "$APP_DIR" --java "$JAVA_HOME/bin/java" \
  --helper-classes "$HELPER_CLASSES" --gpg-build "$GPG_BUILD" \
  --preflight-only
```

The preflight restores and verifies the public bundle, matches its keys to the
live device, prepares both senders' synthetic ciphertexts and validates the
fixed sender's packet with the installed receiver. It requests no PIN. Use
another fresh result directory and omit `--preflight-only` for the explicitly
authorized five-operation run. Expect **five hidden Terminal PIN prompts**,
one per logical signature or hybrid decryption. Touch only when the existing
policy requires it. The harness never retries a failed private operation.

The wrapper records fresh backend hashes and all 24 slot snapshots before
starting and again after success or failure. A missing device, incomplete
snapshot or changed file prevents an unchanged-state success claim. It rejects
an existing result directory or a result path within the selected app bundle.
The result root contains `before.json`, `after.json`, `backend-before.json`,
`backend-after.json` and the overall result. `operations/` contains the public
restore, synthetic fixtures, separate GnuPG status logs, public Java
verification output, and the supplemental `sha256/` checks. Keep those local
results private: public certificate and serial metadata are not secrets, but
may identify the owner or device.

For a reproducible software-only codec regression, the
[disposable fixture generator](pqmail/INTEROPERABILITY.md#disposable-software-fixtures)
uses fresh Java test keys, the prepared core for certificate/signature creation,
and a separate stock GnuPG sender/verifier. Fresh generation and the PQ Mail
codec test passed; no generated PKCS#12, account data or device artifacts are
published.

The lower-level [`pqmail/hardware_test.py`](pqmail/hardware_test.py) remains
available for v4/v5/v6 integration work. For v4, supply the same `--app-dir`,
`--java` and `--helper-classes` arguments to use these current public drivers.
The v5 path now uses the matching public Java drivers from
`tests/hardware/build-v5-interop.sh`; its prepared candidate app must include the
v5 codec. V5 remains opt-in and requires `--email` for its locally generated
test certificate. See the [v5 reproduction commands](pqmail/INTEROPERABILITY.md#reproduce-the-v5-hardware-test).
The v6 experiment still uses its separate prepared fixture drivers. None of
these harnesses provisions hardware keys, changes token policy, writes token
certificates or sends mail.

## Upstream contributions

The upstream GitHub repository is a mirror. Use the GnuPG development mailing
list or bug tracker for reports and proposed patches, not mirror pull requests.
Keep generic protocol bugs separate from this experimental adapter integration.
See [GnuPG contribution channels](https://www.gnupg.org/documentation/mailing-lists.html).
