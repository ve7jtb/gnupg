"""Opt-in v5 hardware interoperability; existing keys and local certificates only.

The v5 signing algorithm is classical Ed25519. Its hybrid encryption uses the
LibrePGP algorithm-8 wire format, not the RFC 9980 algorithm-35 combiner. This
harness keeps the two formats distinct and never provisions a card key.
"""
import getpass
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile


def load(name, path):
    """Load reviewed sibling code, never a path supplied by a certificate."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fingerprints(listing):
    """Select one v5 Ed25519 primary and its algorithm-8 encryption subkey.

    A restored v6 certificate can have the same email. Neither email matching
    nor GnuPG's automatic recipient choice may silently substitute that key.
    The Java public preflight independently validates exported packet versions,
    self-signatures and exact component public keys before message operations.
    """
    primary = hybrid = None
    current = None
    wanted = None
    for line in listing.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            current = None
            wanted = 'primary' if fields[3] == '22' else None
        elif fields[0] == 'sub':
            wanted = 'hybrid' if current and fields[3] == '8' else None
        elif fields[0] == 'fpr' and wanted:
            value = fields[9]
            if len(value) != 64 or any(c not in '0123456789ABCDEF' for c in value):
                raise ValueError('Expected a complete v5 fingerprint')
            if wanted == 'primary':
                if primary is not None:
                    raise ValueError('Ambiguous v5 primary key')
                primary = current = value
            else:
                if hybrid is not None:
                    raise ValueError('Ambiguous v5 hybrid subkey')
                hybrid = value
            wanted = None
    if primary is None or hybrid is None:
        raise ValueError('Expected v5 Ed25519 and LibrePGP algorithm-8 keys')
    return primary, hybrid


def require_status(label, status):
    """Require actual GnuPG status lines instead of matching diagnostic prose."""
    lines = status.splitlines()
    if label == 'v5-signing':
        valid = any(line.startswith(b'[GNUPG:] SIG_CREATED D 22 10 ') for line in lines)
    elif label == 'v5-certificate':
        valid = any(line.startswith(b'[GNUPG:] KEY_CREATED ') for line in lines)
    elif label == 'pqmail-v5-decryption':
        # The public fixture deliberately uses SEIPD v1, so GOODMDC is required
        # as well as success and the exact recovered synthetic bytes.
        valid = all(line in lines for line in (b'[GNUPG:] DECRYPTION_OKAY', b'[GNUPG:] GOODMDC'))
    else:
        raise ValueError('Unknown private operation status')
    if not valid:
        raise RuntimeError('Missing expected '+label+' status; no retry')


def java_command(config, entry, *tail):
    """Only the public test drivers may precede the selected app's own jars."""
    cp = str(Path(config['test_classes']))+os.pathsep+str(Path(config['backend_app'])/'*')
    return [Path(config['test_java']), '-Djava.awt.headless=true', '-cp', cp,
            'dev.hybridmail.'+entry, *tail]


def private_java(config, mode, restored, out):
    """Let Java own one hidden Terminal PIN prompt and operation-scoped PIN.

    Human PIN entry is not placed under an outer subprocess timeout: killing
    only Java near that deadline could leave a native child running during the
    final snapshot. The installed component helpers enforce their own limits.
    No PIN appears in argv, environment values or this wrapper's log files.
    """
    subprocess.run(list(map(str, java_command(config, 'V5InstalledReceive', mode,
                       restored, out, config['backend_app'], config['device_serial']))), check=True)


def test(root, out, home, build, config, run):
    """Five logical PIN operations using signer 88 and hybrid keys 85/9d.

    The parent hardware harness owns complete before/after card snapshots.
    This child additionally records the selected installed-backend hashes so
    software replacement cannot be mistaken for one continuous test run.
    """
    source = Path(__file__).parent
    bridge = load('v5_bridge', source/'bridge.py')
    profiles = load('v5_profiles', source/'profiles.py')
    audit = load('v5_backend_audit', source/'review_v4_test.py')
    before = audit.installed_hashes(Path(config['backend_app']))
    (out/'v5-backend-before.json').write_text(json.dumps(before, indent=2, sort_keys=True)+'\n')
    try:
        _operations(out, home, build, config, run, bridge, profiles)
    finally:
        # Runs after successful operations or any failure. If a dependency is
        # absent or different, fail rather than claiming unchanged software.
        after = audit.installed_hashes(Path(config['backend_app']))
        (out/'v5-backend-after.json').write_text(json.dumps(after, indent=2, sort_keys=True)+'\n')
        if before != after:
            raise RuntimeError('Selected installed backend changed during v5 test')
        (out/'v5-backend-unchanged.txt').write_text('PASS selected app/backend hashes unchanged\n')
    # Publish this operation result only after the backend audit succeeds.
    # The parent still must produce its independent unchanged-card snapshot.
    (out/'result.txt').write_text((out/'v5-operations.txt').read_text())


def _operations(out, home, build, config, run, bridge, profiles):
    """Separate the operation sequence from snapshot/audit cleanup for tests."""
    keys = bridge.Bridge(config, io.BytesIO(), io.BytesIO()).keys
    grips = {}
    for reference, algorithm in (('PIV.88','Ed25519'), ('PIV.85','X25519'), ('PIV.9D','ML-KEM-768')):
        matches = [(grip, key) for grip, key in keys.items() if key['reference'] == reference]
        if len(matches) != 1 or matches[0][1]['algorithm'] != algorithm:
            raise ValueError('Required existing component is not uniquely mapped: '+reference)
        grips[reference] = matches[0][0]
    # Key-Grip/Subkey-Grip make GnuPG construct certificate packets around
    # existing keys. The component bridge exposes no key generation command.
    # Never borrow the Ed25519 component of the v6 hybrid signer in slot 84.
    batch = profiles.v5_parameters(config['email'], grips['PIV.88'],
                                    grips['PIV.85'], grips['PIV.9D'])
    (out/'v5-existing-keys.batch').write_text(batch)
    gpg = [build/'g10/gpg', '--agent-program', build/'agent/gpg-agent', '--homedir', home,
           '--batch', '--yes', '--digest-algo', 'SHA512', '--cert-digest-algo', 'SHA512']

    def authorized(label, args):
        # GnuPG may use this one supplied PIN for several local certificate
        # signatures. Each private operation keeps the card's existing policy.
        # Python's immutable getpass string cannot be reliably erased; wipe
        # mutable copies and make no stronger host-memory protection claim.
        pin = bytearray(getpass.getpass('YubiKey PIN ('+label+'; touch if flashing): ').encode('ascii'))
        request = bytearray()
        try:
            if not 6 <= len(pin) <= 8 or any(x < 32 or x > 126 for x in pin):
                raise ValueError('Invalid PIN format; no token operation')
            request.extend(pin); request.append(10)
            status = run(gpg+['--status-fd','1','--pinentry-mode','loopback','--passphrase-fd','0']+args,
                         label, request)
            # Keep these non-secret status lines even when a caller's generic
            # logging callback only stores stderr for certificate/signing work.
            (out/(label+'.status')).write_bytes(status)
            require_status(label, status)
            return status
        finally:
            pin[:] = b'\0'*len(pin); request[:] = b'\0'*len(request)
            subprocess.run([str(build/'tools/gpg-connect-agent'),'--homedir',str(home),'KILLAGENT','/bye'],
                           capture_output=True,timeout=10,check=True)

    print('V5 compatibility: classical Ed25519 signing and LibrePGP hybrid encryption.', flush=True)
    print('Creating a LOCAL certificate from existing keys; no token certificate write.', flush=True)
    authorized('v5-certificate', ['--generate-key', out/'v5-existing-keys.batch'])
    listing = run(gpg+['--with-colons','--list-keys'], 'v5-list').decode()
    primary, hybrid = fingerprints(listing)
    cert = out/'openpgp-v5.pgp'
    run(gpg+['--output',cert,'--export',primary], 'v5-export')
    (out/'v5-fingerprint.txt').write_text(primary+'\n')

    # The public Java driver chooses the same exact synthetic message bytes
    # for every implementation and prepares an unsigned encrypted fixture.
    # Detached signatures are verified separately, not described as inline.
    run(java_command(config, 'V5HardwareInterop', 'prepare', cert, out, config['backend_app']),
        'pqmail-v5-prepare')
    message = (out/'v5-message.txt').read_bytes()
    restored = out/'restored'
    with tempfile.TemporaryDirectory(prefix='pqv5-peer-', dir='/private/tmp') as temporary:
        peer = Path(temporary)
        (peer/'gpg-agent.conf').write_text('disable-scdaemon\n')
        stock = [config['stock_gpg'],'--homedir',peer,'--batch','--yes']
        run(stock+['--import',cert], 'stock-v5-import')
        # Force only the full hybrid subkey fingerprint. Keep GnuPG's normal
        # payload selection so AEAD-capable v5 certificates exercise LibrePGP
        # tag-20 encryption. The obsolete --force-mdc flag has no effect.
        run(stock+['--trust-model','always','--recipient',hybrid+'!',
                   '--output',out/'stock-v5-encrypted.pgp','--encrypt',out/'v5-message.txt'],
            'stock-v5-encrypt')
        checked = run(java_command(config, 'V5InstalledReceive', '--preflight', restored, out,
                                   config['backend_app'], config['device_serial']), 'pqmail-v5-receive-preflight')
        # Retain public framing/binding diagnostics even if the generic caller
        # logs only stderr for names that do not end in prepare or verify.
        (out/'pqmail-v5-receive-preflight.stdout').write_bytes(checked)
        authorized('v5-signing', ['--local-user',primary+'!','--output',out/'v5-signature.pgp',
                                 '--detach-sign',out/'v5-message.txt'])
        run(stock+['--verify',out/'v5-signature.pgp',out/'v5-message.txt'], 'stock-v5-verify')
        run(java_command(config,'V5HardwareInterop','verify',cert,out,config['backend_app']),
            'pqmail-v5-verify')
        private_java(config, '--sign', restored, out)
        run(stock+['--verify',out/'pqmail-v5-signature.pgp',out/'v5-message.txt'],
            'stock-pqmail-v5-verify')
        authorized('pqmail-v5-decryption', ['--output',out/'pqmail-v5-plain.txt',
                                            '--decrypt',out/'pqmail-v5-encrypted.pgp'])
        if (out/'pqmail-v5-plain.txt').read_bytes() != message:
            raise RuntimeError('PQ Mail-to-GnuPG v5 plaintext mismatch')
        private_java(config, '--decrypt', restored, out)
    # The Java receive driver independently checks its exact plaintext and
    # integrity. This is the operation-only result: overall success additionally
    # requires the backend audit above and the parent's final card snapshot.
    (out/'v5-operations.txt').write_text('PASS v5 cryptographic operations (require parent unchanged-card audit); local existing-key certificate; GnuPG and PQ Mail classical Ed25519 signatures independently verified; LibrePGP ML-KEM-768/X25519 encryption/decryption both ways; ciphertexts unsigned with detached signatures checked separately\n')
    print('PASS v5 signing and hybrid encryption/decryption in both directions', flush=True)
