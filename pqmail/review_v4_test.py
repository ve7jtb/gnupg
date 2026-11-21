#!/usr/bin/env python3
"""Five opt-in, existing-key v4 interoperability operations on an installed Mac app.

The ordinary harness performs one Ed25519/SHA-512 signature and two hybrid
ML-KEM-768/X25519 decryptions. This runner adds Ed25519/SHA-256 signing and the
installed PQ Mail receiver's decryption of the fixed GnuPG sender's ciphertext.
There is no provisioning, token write, policy update, account or mail operation.
"""
import argparse
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


# Hash both installed jars and native/Python operation paths. Recording these
# immediately before and after this run avoids relying on a stale private
# preflight fixture or silently comparing different installed app versions.
BACKEND_FILES = (
    'hybrid-mail.jar', 'adapters/pkcs11-mu.py', 'adapters/pkcs11-kem.py',
    'adapters/ykman-mu.py', 'native/bin/openssl', 'native/bin/hybrid-mail-provision',
    'native/bin/pqmail-pkcs11-sign', 'native/bin/pqmail-pkcs11-kem',
    'native/lib/pkcs11.dylib', 'native/lib/libykcs11.dylib',
)
SLOTS = {'9a', '9c', '9d', '9e'} | {format(n, '02x') for n in range(0x82, 0x96)}


def arguments(argv=None):
    """Require caller-owned paths and device selection; never infer an account."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'out', 'app-dir', 'java', 'helper-classes'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--serial', required=True, help='Existing test YubiKey serial')
    parser.add_argument('--gpg-build', type=Path,
                        help='Development build containing the fixed v6-PKESK sender')
    parser.add_argument('--stock-gpg', type=Path, default=Path('/opt/homebrew/bin/gpg'))
    parser.add_argument('--ykman', type=Path, default=Path('/usr/local/bin/ykman'))
    parser.add_argument('--preflight-only', action='store_true',
                        help='Public restore/fixtures only; no PIN or private operation')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[1-9][0-9]{0,9}', args.serial):
        parser.error('--serial must be an explicit positive decimal YubiKey serial')
    for name in ('root', 'out', 'app_dir', 'java', 'helper_classes', 'stock_gpg', 'ykman'):
        setattr(args, name, getattr(args, name).resolve())
    args.gpg_build = (args.gpg_build or args.root/'work/gnupg-releases/gnupg-2.5.24').resolve()
    return args


def classpath(args):
    """Only test-driver classes may precede the selected app's jars."""
    return str(args.helper_classes)+os.pathsep+str(args.app_dir/'*')


def java_command(args, entry, *tail):
    return [str(args.java), '-Djava.awt.headless=true', '-cp', classpath(args), 'dev.hybridmail.'+entry,
            *map(str, tail)]


def installed_hashes(app):
    """Include every bundled jar so dependency replacement also fails the audit."""
    paths = set(BACKEND_FILES) | {p.name for p in app.glob('*.jar')}
    return {name: hashlib.sha256((app/name).read_bytes()).hexdigest()
            for name in sorted(paths)}


def preflight(args):
    """Check local dependencies before reading a card or asking for a PIN.

    Java's software-only self-test also checks OpenPgp.class's code source;
    a copied application class in the helper directory must not shadow the
    installed jar. No source-tree PQ Mail classes enter this classpath.
    """
    protected = [args.app_dir]
    if args.app_dir.name == 'app' and args.app_dir.parent.name == 'Contents' and args.app_dir.parent.parent.suffix == '.app':
        protected.append(args.app_dir.parent.parent)
    # A caller-selected result directory must not modify the signed application
    # bundle. File hashes cover backend identity, not arbitrary new app files.
    if any(args.out == base or base in args.out.parents for base in protected):
        raise ValueError('Result directory must be outside the selected app bundle')
    if args.out.exists():
        raise ValueError('Use a new result directory; existing evidence is never overwritten')
    required = [args.java, args.stock_gpg, args.ykman,
                args.gpg_build/'g10/gpg', args.gpg_build/'agent/gpg-agent',
                args.gpg_build/'tools/gpg-connect-agent',
                args.root/'work/sequoia/target/debug/piv-restore']
    for executable in required:
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError('Required executable is unavailable: '+str(executable))
    for filename in ('V4HardwareInterop.class', 'V4InstalledReceive.class'):
        if not (args.helper_classes/'dev/hybridmail'/filename).is_file():
            raise ValueError('Compile the published PQ Mail hardware helpers first')
    snapshot_module = args.root/'work/sequoia/piv-adapter/hardware/run.py'
    if not snapshot_module.is_file():
        raise ValueError('Sequoia public snapshot module is unavailable')
    installed_hashes(args.app_dir)  # Missing backend files fail before a device call.
    # This subprocess receives no token PIN or account credentials. Its output
    # is software-fixture diagnostics; suppress it on success for readable runs.
    checked(java_command(args, 'V4InstalledReceive', '--self-test', args.app_dir))


def checked(command, log=None, timeout=180):
    """Run a public-data command; a failure stops subsequent private operations."""
    result = subprocess.run(list(map(str, command)), capture_output=True, timeout=timeout)
    if log is not None:
        log.write_bytes(result.stdout+result.stderr)
    if result.returncode:
        raise RuntimeError('Test command failed; no retry'+(' (see '+str(log)+')' if log else ''))
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def snapshot_function(args):
    """Reuse the connector's explicit-empty-slot handling, not ad hoc probes."""
    spec = importlib.util.spec_from_file_location(
        'piv_review_snapshot', args.root/'work/sequoia/piv-adapter/hardware/run.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.snapshot


def full_snapshot(snapshot, device):
    value = snapshot(device)
    # Never report "all slots unchanged" from a partial or wrong-device read.
    if value.get('serial') != device.serial or set(value.get('slots', {})) != SLOTS:
        raise RuntimeError('Expected a complete 24-slot snapshot of the selected key')
    return value


def standard_command(args, operations):
    """Pass every chosen backend path to the three-operation harness unchanged."""
    cmd = [sys.executable, '-I', '-B', str(Path(__file__).with_name('hardware_test.py')),
           '--root', str(args.root), '--out', str(operations), '--serial', args.serial,
           '--profile', 'v4', '--app-dir', str(args.app_dir), '--java', str(args.java),
           '--helper-classes', str(args.helper_classes), '--gpg-build', str(args.gpg_build),
           '--stock-gpg', str(args.stock_gpg), '--ykman', str(args.ykman)]
    if args.preflight_only:
        cmd.append('--preflight-only')
    return cmd


def sha256_signature(args, operations):
    """One operation-scoped PIN exercises all SHA-256 signing gates together."""
    restored = operations/'restored'
    review = json.loads((restored/'identity.json').read_text())
    if (review.get('serial') != int(args.serial) or not review.get('liveKeysMatched')
            or not review.get('bundleSignatureVerified')):
        raise RuntimeError('Expected verified live-card restore before signing')
    fingerprint = review.get('compatibilityFingerprint', '')
    if not re.fullmatch(r'[0-9A-Fa-f]{40}', fingerprint):
        raise RuntimeError('Expected the full v4 Ed25519 primary fingerprint')
    home = Path((operations/'agent-home.txt').read_text().strip())
    extra = operations/'sha256'
    extra.mkdir(mode=0o700)
    (extra/'message.txt').write_bytes((operations/'message.txt').read_bytes())
    cert = restored/'openpgp-v4-hybrid.asc'
    command = [args.gpg_build/'g10/gpg', '--agent-program', args.gpg_build/'agent/gpg-agent',
               '--homedir', home, '--batch', '--yes', '--allow-9980', '--digest-algo', 'SHA256',
               '--status-fd', '1', '--pinentry-mode', 'loopback', '--passphrase-fd', '0',
               '--local-user', fingerprint+'!', '--output', extra/'v4-signature.pgp',
               '--detach-sign', extra/'message.txt']
    # getpass returns an immutable Python string that cannot be reliably erased;
    # clear the mutable operation buffers and make no stronger memory claim.
    # Never place this PIN in command arguments, files or the environment.
    pin = bytearray(getpass.getpass('YubiKey PIN (Ed25519 / SHA-256 signing; touch if flashing): ').encode('ascii'))
    request = bytearray()
    try:
        if not 6 <= len(pin) <= 8 or any(v < 32 or v > 126 for v in pin):
            raise ValueError('Invalid PIV PIN; no private request sent')
        request.extend(pin); request.append(10)
        result = subprocess.run(list(map(str, command)), input=request,
                                capture_output=True, timeout=180)
        (extra/'signing.log').write_bytes(result.stderr)
        (extra/'signing.status').write_bytes(result.stdout)
        # Match a real status line, not arbitrary diagnostics containing the
        # same text. 22 is legacy Ed25519, 8 is SHA-256, and D means detached.
        if result.returncode or not any(line.startswith(b'[GNUPG:] SIG_CREATED D 22 8 ')
                                        for line in result.stdout.splitlines()):
            raise RuntimeError('Ed25519/SHA-256 signing failed; no retry')
    finally:
        pin[:] = b'\0'*len(pin); request[:] = b'\0'*len(request)
        # Discard this isolated agent's cached PIN even if signing fails.
        checked([args.gpg_build/'tools/gpg-connect-agent', '--homedir', home,
                 'KILLAGENT', '/bye'], timeout=10)
    # Independent stock verification establishes cryptographic validity, not
    # ownertrust. This temporary verifier has public keys only and no scdaemon.
    with tempfile.TemporaryDirectory(prefix='pq-v4-verify-', dir='/private/tmp') as temporary:
        peer = Path(temporary)
        (peer/'gpg-agent.conf').write_text('disable-scdaemon\n')
        stock = [args.stock_gpg, '--homedir', peer, '--batch', '--yes', '--allow-9980']
        checked(stock+['--import', cert], extra/'stock-import.log')
        checked(stock+['--verify', extra/'v4-signature.pgp', extra/'message.txt'], extra/'stock-verify.log')
        checked(java_command(args, 'V4HardwareInterop', 'verify', cert, extra, args.app_dir),
                extra/'pqmail-verify.log')
    print('PASS Ed25519/SHA-256 signature verified by stock GnuPG and installed PQ Mail', flush=True)


def receive(args, operations):
    """The fifth PIN belongs to Java's one hybrid receive operation.

    Inherit the local Terminal so Console.readPassword hides input. Do not
    capture stdin, inject a PIN, or retain a UI credential in this wrapper.
    The helper checks decryption/integrity and the independent detached
    signature separately; the sender's ciphertext contains no inline signature.
    """
    # Do not put an outer timeout around user-paced PIN entry: terminating
    # only Java could orphan a native child that began near that deadline.
    # The installed backend separately bounds each actual private operation.
    subprocess.run(java_command(args, 'V4InstalledReceive', '--decrypt',
                               operations/'restored', operations, args.app_dir, args.serial),
                   check=True)


def audit(args, snapshot, device, before, hashes):
    """Attempt both final audits even if one fails; never infer unchanged state."""
    failures = []
    try:
        after = full_snapshot(snapshot, device)
        write_json(args.out/'after.json', after)
        if after != before:
            raise RuntimeError('Key/public-key/origin/PIN/touch snapshot changed')
        (args.out/'unchanged.txt').write_text('PASS all 24 slot/public-key/origin/PIN/touch snapshots unchanged\n')
    except Exception as error:
        failures.append(str(error))
    try:
        after_hashes = installed_hashes(args.app_dir)
        write_json(args.out/'backend-after.json', after_hashes)
        if after_hashes != hashes:
            raise RuntimeError('Installed backend changed during the test')
        (args.out/'backend-unchanged.txt').write_text('PASS selected installed backend files unchanged\n')
    except Exception as error:
        failures.append(str(error))
    if failures:
        (args.out/'audit-failure.txt').write_text('\n'.join(failures)+'\n')
        raise RuntimeError('Final audit incomplete or changed; inspect saved results')


def execute(args):
    preflight(args)
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    snapshot = snapshot_function(args)
    device = argparse.Namespace(ykman=str(args.ykman), serial=args.serial)
    hashes = installed_hashes(args.app_dir)
    write_json(args.out/'backend-before.json', hashes)
    before = full_snapshot(snapshot, device)
    write_json(args.out/'before.json', before)
    operations = args.out/'operations'
    completed = False
    try:
        # Inherit the terminal for exactly the standard three hidden PIN
        # prompts. Any failure stops both supplemental private operations.
        subprocess.run(standard_command(args, operations), check=True)
        if not args.preflight_only:
            sha256_signature(args, operations)  # Fourth PIN, then two public verifiers.
            receive(args, operations)           # Fifth PIN, one hybrid decryption.
        completed = True
    finally:
        # Covers failures in the standard harness and both supplemental steps.
        # A disconnected device cannot yield an "unchanged" success report.
        audit(args, snapshot, device, before, hashes)
        print('Results: '+str(args.out), flush=True)
    if completed:
        result = ('PASS public preflight; no private operations\n' if args.preflight_only else
                  'PASS five private operations: two classical Ed25519 signatures (SHA-512/SHA-256) '
                  'and three ML-KEM-768/X25519 decryptions; detached signature verified separately; '
                  'ciphertexts contain no inline signature\n')
        (args.out/'result.txt').write_text(result)
        print(result.strip(), flush=True)


if __name__ == '__main__':
    execute(arguments())
