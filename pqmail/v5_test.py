"""Explicit v5 hardware test: local certificates only; no key generation."""
import getpass
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile


def load(name, path):
    """Load reviewed application code, never a path supplied by a certificate."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test(root, out, home, build, config, run):
    """Exercise existing slot 88 signing and 85/9d hybrid encryption keys."""
    source = Path(__file__).parent
    bridge = load('v5_bridge', source/'bridge.py')
    profiles = load('v5_profiles', source/'profiles.py')
    keys = bridge.Bridge(config, io.BytesIO(), io.BytesIO()).keys
    grips = {key['reference']: grip for grip, key in keys.items()}
    # The separate classical signing key is mandatory: do not borrow the
    # Ed25519 component of the existing v6 hybrid signing key in slot 84.
    batch = profiles.v5_parameters(config['email'], grips['PIV.88'],
                                    grips['PIV.85'], grips['PIV.9D'])
    (out/'v5-existing-keys.batch').write_text(batch)
    gpg = [build/'g10/gpg', '--agent-program', build/'agent/gpg-agent', '--homedir', home,
           '--batch', '--yes', '--digest-algo', 'SHA512', '--cert-digest-algo', 'SHA512']
    def authorized(label, args):
        # Scope a single supplied PIN to the requested operation. GnuPG may
        # use it for several certificate signatures; each keeps its touch policy.
        pin = bytearray(getpass.getpass('YubiKey PIN ('+label+'; touch when flashing): ').encode('ascii'))
        try:
            if not 6 <= len(pin) <= 8 or any(x < 32 or x > 126 for x in pin):
                raise ValueError('Invalid PIN format; no token operation')
            return run(gpg+['--pinentry-mode','loopback','--passphrase-fd','0']+args, label, pin+b'\n')
        finally:
            pin[:] = b'\0'*len(pin)
            subprocess.run([str(build/'tools/gpg-connect-agent'),'--homedir',str(home),'KILLAGENT','/bye'],
                           capture_output=True,timeout=10)
    print('V5 compatibility: classical Ed25519 signing, hybrid LibrePGP encryption.', flush=True)
    print('Creating only a LOCAL certificate from existing keys; touch for each certification.', flush=True)
    authorized('v5-certificate', ['--generate-key', out/'v5-existing-keys.batch'])
    # Select by version and primary algorithm, not by email alone: the restored
    # v6 certificate has the same email and must never be signed accidentally.
    listing = run(gpg+['--with-colons','--list-keys'], 'v5-list').decode()
    fingerprint = None
    wanted = False
    for line in listing.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            wanted = fields[3] == '22'
        elif wanted and fields[0] == 'fpr':
            if fingerprint is not None:
                raise ValueError('Ambiguous v5 primary key')
            fingerprint = fields[9]
            wanted = False
    if fingerprint is None or len(fingerprint) != 64:
        raise ValueError('Expected a v5 Ed25519 primary fingerprint')
    run(gpg+['--output',out/'openpgp-v5.pgp','--export',fingerprint], 'v5-export')
    (out/'v5-fingerprint.txt').write_text(fingerprint+'\n')
    message = b'Synthetic GnuPG v5 YubiKey compatibility test.\r\n'
    (out/'v5-message.txt').write_bytes(message)
    authorized('v5-signing', ['--local-user',fingerprint,'--output',out/'v5-signature.pgp',
                               '--detach-sign',out/'v5-message.txt'])
    # An unmodified GnuPG installation independently validates our certificate
    # and signature, then constructs its own LibrePGP hybrid ciphertext.
    stockhome = Path(tempfile.mkdtemp(prefix='pqv5-peer-', dir='/private/tmp'))
    (out/'stock-home.txt').write_text(str(stockhome)+'\n')
    stock = ['/opt/homebrew/bin/gpg','--homedir',stockhome,'--batch','--yes']
    run(stock+['--import',out/'openpgp-v5.pgp'], 'stock-v5-import')
    run(stock+['--verify',out/'v5-signature.pgp',out/'v5-message.txt'], 'stock-v5-verify')
    run(stock+['--trust-model','always','--recipient',fingerprint,'--output',out/'stock-v5-encrypted.pgp',
               '--encrypt',out/'v5-message.txt'], 'stock-v5-encrypt')
    authorized('v5-decryption', ['--output',out/'v5-plain.txt','--decrypt',out/'stock-v5-encrypted.pgp'])
    if (out/'v5-plain.txt').read_bytes() != message:
        raise RuntimeError('V5 plaintext mismatch')
    (out/'result.txt').write_text('PASS local v5 certificate; slot 88 Ed25519 signature verified by unmodified GnuPG; stock LibrePGP ML-KEM-768/X25519 ciphertext decrypted using slots 9d/85\n')
    print('PASS v5 certificate, independent signature verification and hybrid decryption', flush=True)
