#!/usr/bin/env python3
"""Local-only GnuPG/PIV integration test; never generates or changes keys."""
import argparse
import base64
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--serial', required=True, help='Explicit serial of the existing test key')
    p.add_argument('--email', help='Email for a local v5 test certificate; required only for --profile v5')
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--app-dir', type=Path, help='Installed PQ Mail Contents/app directory')
    p.add_argument('--java', type=Path, help='Java executable for public interoperability helpers')
    p.add_argument('--helper-classes', type=Path, help='Compiled public interoperability helpers matching the selected profile')
    p.add_argument('--gpg-build', type=Path, help='Tested development GnuPG build directory')
    p.add_argument('--stock-gpg', default='/opt/homebrew/bin/gpg')
    p.add_argument('--ykman', default='/usr/local/bin/ykman')
    p.add_argument('--preflight-only', action='store_true')
    p.add_argument('--profile', choices=('v6','v5','v4'), default='v6')
    a = p.parse_args()
    root = a.root.resolve()
    out = a.out.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    app = (a.app_dir or root/'outputs/pq-mail-desktop/PQ Mail.app/Contents/app').resolve()
    source = Path(__file__).resolve().parent
    build = (a.gpg_build or root/'work/gnupg-releases/gnupg-2.5.24').resolve()
    # Device/account selection belongs to the local launcher, never public
    # source defaults. Validate before taking snapshots or prompting for a PIN.
    serial = a.serial
    if not serial.isdecimal():
        raise ValueError('Explicit numeric YubiKey serial required')
    if a.profile == 'v5' and not a.email:
        raise ValueError('--email is required for the local v5 certificate')
    # Reuse the proven read-only snapshot routine, which distinguishes empty
    # slots from transport errors and includes public keys and touch policies.
    spec = importlib.util.spec_from_file_location('piv_snapshot', root/'work/sequoia/piv-adapter/hardware/run.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    device = argparse.Namespace(ykman=a.ykman, serial=serial)
    # Capture the full public state before restoring or asking for a PIN. A
    # final snapshot failure is not evidence of unchanged state and must fail
    # the run even if individual cryptographic operations already succeeded.
    before = mod.snapshot(device)
    (out/'before.json').write_text(json.dumps(before, indent=2))
    # macOS Unix-domain sockets require a short path; only public shadow
    # stubs and configuration persist here, never exported private keys.
    home = Path(tempfile.mkdtemp(prefix='pqg-', dir='/private/tmp'))
    (out/'agent-home.txt').write_text(str(home)+'\n')
    def run(args, name, secret=None):
        # Only fixed synthetic messages, public metadata and GPG status go to
        # logs. The PIN is passed exclusively through the child's stdin pipe.
        result = subprocess.run([str(x) for x in args], input=secret,
                                capture_output=True, timeout=180)
        (out/(name+'.log')).write_bytes(result.stderr)
        if name.endswith(('-prepare', '-verify')):
            # Public-only fixture/verification drivers print useful PASS
            # evidence on stdout. Preserve it separately from stderr; this
            # branch is never used for a secret-bearing backend response.
            (out/(name+'.stdout')).write_bytes(result.stdout)
        if name.endswith('-decryption') or name == 'v4-signing':
            # These GPG invocations use --status-fd 1 and a separate output
            # file: retain public status codes, never PIN or plaintext pipes.
            (out/(name+'.status')).write_bytes(result.stdout)
        if result.returncode or (name == 'learn' and b'ERR ' in result.stdout):
            raise RuntimeError(name+' failed; no retry. See '+str(out/(name+'.log')))
        return result.stdout
    gpg = [build/'g10/gpg', '--agent-program', build/'agent/gpg-agent', '--homedir', home,
           '--batch', '--yes', '--digest-algo', 'SHA384']
    try:
        # The restorer verifies bundle signatures and matches every public
        # component against the live card before writing this local manifest.
        run([root/'work/sequoia/target/debug/piv-restore',
             app/'native/bin/hybrid-mail-provision', serial, out/'restored'], 'restore')
        restored = out/'restored'
        review = json.loads((restored/'identity.json').read_text())
        if review['serial'] != int(serial) or not review['bundleSignatureVerified'] or not review['liveKeysMatched']:
            raise RuntimeError('Unverified restore')
        # Bind each private-operation reference to the complete restored SPKI.
        # OpenPGP fingerprints select certificates; these hashes additionally
        # prevent silently routing the same algorithm to another device key.
        keys = []
        for slots, usage in [(review['slots']['signing'], 's'),
                             (review['slots']['certification'], 's'),
                             (review['slots']['decryption'], 'e'),
                             (review['slots']['classical'], None)]:
            for i, slot in enumerate(slots):
                der = (restored/('slot-'+slot+'-public.der')).read_bytes()
                if hashlib.sha256(der).hexdigest() != review['publicKeySha256'][slot]:
                    raise RuntimeError('Restored public key hash mismatch')
                keys.append(dict(spki=base64.b64encode(der).decode(), reference='PIV.'+slot.upper(),
                                 usage=usage or ('s' if i == 0 else 'e')))
        # Public test paths are explicitly supplied by the caller. In v4 and v5,
        # encryption, signing and verification select this same reviewed app
        # jar; helper classes must match the selected wire profile.
        test_java = (a.java or root/'work/hybrid-mail/tools/zulu25.38.201-ca-jdk25.0.5.1-macosx_aarch64/Contents/Home/bin/java').resolve()
        test_classes = (a.helper_classes or root/'outputs/gnupg-v4-hardware/classes').resolve()
        config = dict(test_java=str(test_java), test_classes=str(test_classes), stock_gpg=a.stock_gpg,
                      wire_profile=a.profile, email=a.email, serial='D27600012401'+format(int(serial), '08X'), device_serial=serial,
                      libgcrypt='/opt/homebrew/lib/libgcrypt.dylib', keys=keys,
                      backend_app=str(app), prompt='YubiKey PIN (not a password)',
                      component_command=['/usr/bin/python3', '-I', '-B', str(source/'component.py'), str(home/'bridge.json')])
        (home/'bridge.json').write_text(json.dumps(config, indent=2))
        wrapper = home/'component-bridge'
        wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 -I -B '+shlex.quote(str(source/'bridge.py'))+' '+shlex.quote(str(home/'bridge.json'))+' "$@"\n')
        wrapper.chmod(0o700)
        (home/'gpg-agent.conf').write_text('scdaemon-program '+str(wrapper)+'\nallow-loopback-pinentry\ndisable-check-own-socket\n')
        (home/'gpg.conf').write_text('allow-9980\n')
        run(gpg+['--import', restored/'openpgp-v6.asc'], 'import')
        run([build/'tools/gpg-connect-agent','--homedir',home,'LEARN --force','/bye'], 'learn')
        if a.profile == 'v4':
            spec = importlib.util.spec_from_file_location('v4_test', source/'v4_test.py')
            v4 = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(v4)
            v4.test(root, out, home, build, config, run, a.preflight_only)
            return

        if a.profile == 'v5':
            # Keep v5 opt-in and leave the restored v6 identity untouched.
            spec = importlib.util.spec_from_file_location('v5_test', source/'v5_test.py')
            v5 = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(v5)
            if a.preflight_only:
                v5.profiles = v5.load('profiles', source/'profiles.py')
                print('PASS v5 public restore and shadow-key setup; no private operations', flush=True)
                return
            v5.test(root, out, home, build, config, run)
            return

        # Public-key encryption requires no PIN and prepares two independent
        # senders' ciphertexts for the same restored recipient certificate.
        java = root/'work/hybrid-mail/tools/zulu25.38.201-ca-jdk25.0.5.1-macosx_aarch64/Contents/Home/bin/java'
        cp = str(root/'outputs/sequoia-piv-test/classes')+':'+str(root/'outputs/hybrid-mail-source/build/hybrid-mail.jar')+':'+str(root/'outputs/hybrid-mail-source/lib/*')
        run([java,'-cp',cp,'dev.hybridmail.PqMailInterop','prepare',restored/'openpgp-v6.asc',out], 'pqmail-prepare')
        message = (b'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n'
                   b'Synthetic Sequoia YubiKey Level 3 interoperability test.\r\n')
        (out/'message.mime').write_bytes(message)
        sq = [root/'outputs/gws-sequoia-chat/bin/sq','--home=none','--cert-store=none','--key-store=none']
        # The fixture tool selects exactly the hybrid recipient. sq encrypt
        # selects every eligible subkey, including the classical fallback.
        run([root/'work/sequoia/target/debug/piv-test', 'encrypt',
             restored/'openpgp-v6.asc', out], 'sequoia-encrypt')
        if a.preflight_only:
            (out/'preflight.txt').write_text('PASS restore, live-key match, GnuPG import/LEARN and independent encrypted fixtures; no private operations\n')
            print('PASS read-only preflight', flush=True)
            return
        for label, args in [('signing', ['--local-user',review['fingerprint'],'--output',out/'signature.pgp','--detach-sign',out/'message.mime']),
                            ('pqmail-decryption',['--output',out/'pqmail-plain.mime','--decrypt',out/'pqmail-encrypted.pgp']),
                            ('sequoia-decryption',['--output',out/'sequoia-plain.mime','--decrypt',out/'sequoia-encrypted.pgp'])]:
            # One prompt per logical operation; both composite components use
            # the supplied loopback PIN. Kill the isolated agent afterward.
            pin = bytearray(getpass.getpass('YubiKey PIN ('+label+'; touch if flashing): ').encode('ascii'))
            try:
                if not 6 <= len(pin) <= 8 or any(x < 32 or x > 126 for x in pin):
                    raise ValueError('Invalid PIV PIN format; no token request')
                run(gpg+['--pinentry-mode','loopback','--passphrase-fd','0']+args, label, pin+b'\n')
            finally:
                pin[:] = b'\0'*len(pin)
                subprocess.run([str(build/'tools/gpg-connect-agent'),'--homedir',str(home),'KILLAGENT','/bye'],capture_output=True,timeout=10)
            if label == 'signing':
                run(sq+['verify','--signer-file',restored/'openpgp-v6.asc','--signature-file',out/'signature.pgp',out/'message.mime'], 'sequoia-verify')
                run([java,'-cp',cp,'dev.hybridmail.PqMailInterop','verify',restored/'openpgp-v6.asc',out], 'pqmail-verify')
            else:
                if (out/label.replace('-decryption','-plain.mime')).read_bytes() != message:
                    raise RuntimeError('Plaintext mismatch')
            print('PASS '+label, flush=True)
        (out/'result.txt').write_text('PASS GnuPG v6 hardware signing independently verified by Sequoia and PQ Mail; both senders decrypted byte-for-byte\n')
    finally:
        # Even a failed operation gets a fresh snapshot; never infer unchanged
        # state when a disconnect prevents reading the card.
        after = mod.snapshot(device)
        (out/'after.json').write_text(json.dumps(after, indent=2))
        if before != after:
            raise RuntimeError('Key/policy snapshots differ; inspect before proceeding')
        (out/'unchanged.txt').write_text('PASS all 24 slot/public-key/origin/PIN/touch snapshots unchanged\n')
        print('Results: '+str(out), flush=True)


if __name__ == '__main__':
    main()
