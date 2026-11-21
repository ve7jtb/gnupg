"""Existing v4 certificate / RFC 9980 hardware interoperability, without writes."""
import getpass
from pathlib import Path
import subprocess
import tempfile


def test(root, out, home, build, config, run, preflight=False):
    """Sign in slot 88; decrypt using ML-KEM-768/X25519 in 9d/85."""
    cert = out/'restored/openpgp-v4-hybrid.asc'
    gpg = [build/'g10/gpg','--agent-program',build/'agent/gpg-agent','--homedir',home,
           '--batch','--yes','--allow-9980','--digest-algo','SHA512']
    run(gpg+['--import',cert], 'v4-import')
    listing = run(gpg+['--with-colons','--list-keys'], 'v4-keys').decode()
    primary = hybrid = None
    kind = None
    current_primary = None
    for line in listing.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            current_primary = None
            kind = 'primary' if fields[3] == '22' else None
        elif fields[0] == 'sub':
            kind = 'hybrid' if fields[3] == '35' and current_primary else None
        elif fields[0] == 'fpr' and kind:
            if kind == 'primary':
                if primary is not None: raise ValueError('Ambiguous v4 primary')
                primary = current_primary = fields[9]
            else:
                if hybrid is not None: raise ValueError('Ambiguous v4 hybrid subkey')
                hybrid = fields[9]
            kind = None
    if not primary or not hybrid or len(primary) != 40 or len(hybrid) != 40:
        raise ValueError('Expected v4 primary and hybrid subkey fingerprints')
    java = root/'work/hybrid-mail/tools/zulu25.38.201-ca-jdk25.0.5.1-macosx_aarch64/Contents/Home/bin/java'
    cp = str(root/'outputs/gnupg-v4-hardware/classes')+':'+str(root/'outputs/hybrid-mail-source/build/hybrid-mail.jar')+':'+str(root/'outputs/hybrid-mail-source/lib/*')
    java = [java,'-cp',cp,'dev.hybridmail.V4HardwareInterop']
    run(java+['prepare',cert,out], 'pqmail-v4-prepare')
    # Stock GnuPG has only public keys in its own short-lived test home.
    stockhome = Path(tempfile.mkdtemp(prefix='pqv4-peer-',dir='/private/tmp'))
    (stockhome/'gpg-agent.conf').write_text('disable-scdaemon\n')
    stock = ['/opt/homebrew/bin/gpg','--homedir',stockhome,'--batch','--yes','--allow-9980']
    run(stock+['--import',cert], 'stock-v4-import')
    # The ! pins the hybrid subkey, excluding the certificate's optional
    # classical encryption subkey and any automatic recipient substitution.
    # Stock 2.5.24 writes 32 fingerprint bytes while declaring 20 for a
    # v4 recipient in a v6 PKESK. Use our fixed sender, still with the
    # public-only peer home; stock remains the independent signature verifier.
    sender = [build/'g10/gpg','--homedir',stockhome,'--batch','--yes','--allow-9980']
    run(sender+['--trust-model','always','--recipient',hybrid+'!','--output',out/'fixed-gpg-v4-encrypted.pgp',
               '--encrypt',out/'message.txt'], 'fixed-gpg-v4-encrypt')
    if preflight:
        (out/'preflight.txt').write_text('PASS restored v4 bindings/live keys, shadow mappings and PQ Mail/fixed GnuPG hybrid ciphertext preparation; no private operations\n')
        print('PASS v4 read-only preflight',flush=True)
        return
    # Ed25519 compatibility signing is classical even though both ciphertexts
    # below use a hybrid KEM. Keeping those checks separate avoids reporting
    # a PQ signature based only on successful hybrid decryption.
    operations = [('v4-signing',['--local-user',primary+'!','--output',out/'v4-signature.pgp','--detach-sign',out/'message.txt']),
                  ('pqmail-v4-decryption',['--output',out/'pqmail-v4-plain.txt','--decrypt',out/'pqmail-v4-encrypted.pgp']),
                  ('fixed-gpg-v4-decryption',['--output',out/'fixed-gpg-v4-plain.txt','--decrypt',out/'fixed-gpg-v4-encrypted.pgp'])]
    for label,args in operations:
        # GnuPG's loopback PIN is scoped to this operation, including both
        # decryption components. Never persist it or retry a rejected PIN.
        pin = bytearray(getpass.getpass('YubiKey PIN ('+label+'; touch if flashing): ').encode('ascii'))
        try:
            if not 6 <= len(pin) <= 8 or any(x < 32 or x > 126 for x in pin):
                raise ValueError('Invalid PIN format; no private operation')
            run(gpg+['--status-fd','1','--pinentry-mode','loopback','--passphrase-fd','0']+args,label,pin+b'\n')
        finally:
            pin[:] = b'\0'*len(pin)
            subprocess.run([str(build/'tools/gpg-connect-agent'),'--homedir',str(home),'KILLAGENT','/bye'],capture_output=True,timeout=10)
        if label == 'v4-signing':
            run(stock+['--verify',out/'v4-signature.pgp',out/'message.txt'],'stock-v4-verify')
            run(java+['verify',cert,out],'pqmail-v4-verify')
        else:
            plain = out/label.replace('-decryption','-plain.txt')
            if plain.read_bytes() != (out/'message.txt').read_bytes():
                raise RuntimeError('Decrypted plaintext mismatch')
        print('PASS '+label,flush=True)
    (out/'result.txt').write_text('PASS existing v4 Ed25519 slot 88 signature verified by stock GnuPG and PQ Mail; PQ Mail and fixed GnuPG RFC 9980 hybrid ciphertexts decrypted byte-for-byte using slots 9d/85\n')
