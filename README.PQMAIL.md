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
version does not itself establish post-quantum signature security.

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
   apply while reading, and diagnostics are never echoed to the caller.
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

The review update passed **24 tests**, including SHA-256 compatibility, retained
ML-DSA restrictions, patch-preflight/rollback failures, blocked stdin, output
floods and nested descendant cleanup. The identical supervisor passed seven
additional executions on the software branch. Patch anchors were checked
against clean GnuPG 2.5.23 and 2.5.24 sources; test fixtures use temporary files
and synthetic subprocesses, without hardware or account access.

Separate authorized hardware testing with the development GnuPG core and the
existing PKCS#11 backend verified:

- v4 Ed25519 signing, independently verified by stock GnuPG and PQ Mail;
- ML-KEM-768/X25519 decryption of PQ Mail and fixed-GnuPG ciphertexts, with
  byte-for-byte plaintext and integrity checks;
- identical before/after snapshots for all 24 ordinary PIV slots, including
  public keys, origin, PIN policy and touch policy.

The fixed GnuPG sender is explicitly distinguished from stock GnuPG: stock
2.5.24 emitted an incorrectly padded v4 fingerprint in a v6 PKESK packet.
The connector-review changes have software regression coverage; they have not
been followed by another hardware operation. Device-specific launchers,
credentials, public account certificates and local result directories are not
included in this source snapshot.

## Developer hardware harness

The generic `pqmail/hardware_test.py` harness is included, but its account and
serial selections are supplied locally through arguments. It uses the existing
multi-project integration workspace, rather than installing dependencies or
altering the user's system GnuPG. `--root` must identify that workspace, with:

- the tested development GnuPG build under `work/gnupg-releases/gnupg-2.5.24`;
- Sequoia's built `piv-restore`/`piv-test` tools and hardware snapshot module
  under `work/sequoia`;
- the PQ Mail app/backend under `outputs/pq-mail-desktop` and its compiled
  public-only Java interoperability fixtures (`PqMailInterop` and
  `V4HardwareInterop`) under `outputs/sequoia-piv-test` and
  `outputs/gnupg-v4-hardware` respectively;
- the matching PQ Mail jar/libraries and patched Java runtime, plus stock
  GnuPG and ykman at the Mac paths shown in the harness.

The required experimental GnuPG core build is separate from this connector
snapshot. It is not sufficient to compile the unchanged C sources on this
branch and assume full hybrid operation support. The harness retains the
paths used for the measured Mac integration; it is not a cross-platform
installer.

For an already prepared workspace, first run the PIN-free preflight:

```sh
python3 -I -B pqmail/hardware_test.py --root "$INTEGRATION_ROOT" \
  --out "$NEW_RESULT_DIRECTORY" --serial "$TEST_YUBIKEY_SERIAL" \
  --profile v4 --preflight-only
```

Use a fresh result directory and omit `--preflight-only` for the authorized
three-operation test. Supply `--email "$TEST_EMAIL"` for an explicit v5 local
certificate test. PINs are entered only in hidden Terminal prompts. No test
provisions hardware keys, changes touch policy, writes token certificates or
sends mail. The v5 flow creates a local certificate from existing keygrips.

## Upstream contributions

The upstream GitHub repository is a mirror. Use the GnuPG development mailing
list or bug tracker for reports and proposed patches, not mirror pull requests.
Keep generic protocol bugs separate from this experimental adapter integration.
See [GnuPG contribution channels](https://www.gnupg.org/documentation/mailing-lists.html).
