#!/usr/bin/env python3
"""Create disposable v5 software fixtures with prepared GnuPG and a Java test helper.

This program has no YubiKey, PKCS#11, provisioning, account or mail path. The
PKCS#12 contains fresh random test keys under a PUBLIC, fixed test password;
never use the generated identity for real mail or copy a user identity here.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

PASSWORD = b'synthetic-fixture-password\n'
EMAIL = 'synthetic-v5@example.test'
HERE = Path(__file__).resolve().parents[1]


def load(name, path):
    """Load only repository-owned helpers, not paths supplied by a certificate."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def executable(value):
    """Require explicit local tools so another PATH entry cannot select a card helper."""
    path = value.resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('Expected an executable local tool: '+str(path))
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='New disposable fixture directory')
    parser.add_argument('--gpg', type=Path, required=True, help='Prepared development GnuPG with explicit v5 batch versions and component hooks')
    parser.add_argument('--stock-gpg', type=Path, required=True, help='Independent stock GnuPG sender/verifier with algorithm-8 support')
    parser.add_argument('--gpg-agent', type=Path, required=True)
    parser.add_argument('--gpg-connect-agent', type=Path, required=True)
    parser.add_argument('--libgcrypt', type=Path, required=True)
    parser.add_argument('--java', type=Path, required=True)
    parser.add_argument('--helper-classes', type=Path, required=True)
    parser.add_argument('--app-dir', type=Path, required=True, help='PQ Mail candidate app jars, no native backend used')
    args = parser.parse_args()
    if os.name != 'posix':
        raise ValueError('Fixture generator currently requires macOS or Linux')
    # A private umask is inherited by Java/GnuPG. The deliberately public test
    # password does not turn these disposable files into real user credentials.
    os.umask(0o077)
    out = args.out.resolve()
    if out.exists():
        raise ValueError('Fixture directory must not already exist')
    tools = {name: executable(getattr(args, name)) for name in
             ('gpg', 'stock_gpg', 'gpg_agent', 'gpg_connect_agent', 'java')}
    app = args.app_dir.resolve(strict=True)
    classes = args.helper_classes.resolve(strict=True)
    libgcrypt = args.libgcrypt.resolve(strict=True)
    if not libgcrypt.is_file() or not (app/'hybrid-mail.jar').is_file():
        raise ValueError('Expected libgcrypt and the selected candidate app jar')
    if not (classes/'dev/hybridmail/V5SoftwareFixture.class').is_file():
        raise ValueError('Compile build-v5-interop.sh test helpers first')
    if out == app or app in out.parents or out == classes or classes in out.parents:
        raise ValueError('Keep disposable fixtures outside the app and helper classes')
    java = [str(tools['java']), '-Djava.awt.headless=true', '-cp',
            str(classes)+os.pathsep+str(app/'*'), 'dev.hybridmail.V5SoftwareFixture']
    # --generate refuses an existing directory and creates only fresh software
    # Ed25519/X25519/ML-KEM-768 keys. No production component helper is selected.
    generated = subprocess.run(java+['--generate', str(out)], capture_output=True, timeout=90)
    if generated.returncode:
        raise RuntimeError('Disposable Java fixture generation failed')
    (out/'generate.log').write_bytes(generated.stdout+generated.stderr)

    def run(command, label, secret=None):
        # All retained output is public GnuPG status or synthetic fixture data.
        # The fixed disposable password travels exclusively through stdin.
        result = subprocess.run(list(map(str, command)), input=secret,
                                capture_output=True, timeout=120)
        (out/(label+'.log')).write_bytes(result.stderr)
        (out/(label+'.status')).write_bytes(result.stdout)
        if result.returncode:
            raise RuntimeError(label+' failed; inspect disposable fixture logs')
        return result.stdout

    bridge = load('fixture_bridge', HERE/'bridge.py')
    profiles = load('fixture_profiles', HERE/'profiles.py')
    v5 = load('fixture_v5', HERE/'v5_test.py')
    # Keep the Unix socket path short even when the user's checkout path is
    # long. This isolated home contains public certificates and shadow stubs;
    # the actual software keys stay in the disposable test PKCS#12.
    with tempfile.TemporaryDirectory(prefix='pqv5-', dir='/tmp') as temporary:
        home = Path(temporary).resolve()
        config = dict(wire_profile='v5', serial='D2760001240100000000',
                      libgcrypt=str(libgcrypt), keys=json.loads((out/'keys.json').read_text()),
                      prompt='Disposable test password',
                      component_command=java+['--component', str(out/'identity.p12')])
        keys = bridge.Bridge(config, io.BytesIO(), io.BytesIO()).keys
        grips = {}
        for reference, algorithm in (('PIV.84','Ed25519'), ('PIV.85','X25519'), ('PIV.9D','ML-KEM-768')):
            matches = [(g,k) for g,k in keys.items() if k['reference']==reference]
            if len(matches)!=1 or matches[0][1]['algorithm']!=algorithm:
                raise ValueError('Unexpected disposable component mapping')
            grips[reference] = matches[0][0]
        config_path = home/'bridge.json';config_path.write_text(json.dumps(config, indent=2)+'\n')
        wrapper = home/'component-bridge'
        wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(os.sys.executable)+' -I -B '
                           +shlex.quote(str(HERE/'bridge.py'))+' '+shlex.quote(str(config_path))+' "$@"\n')
        wrapper.chmod(0o700)
        (home/'gpg-agent.conf').write_text('scdaemon-program '+str(wrapper)+'\nallow-loopback-pinentry\ndisable-check-own-socket\n')
        gpg = [tools['gpg'], '--agent-program', tools['gpg_agent'], '--homedir', home,
               '--batch', '--yes', '--digest-algo', 'SHA512', '--cert-digest-algo', 'SHA512']
        try:
            # LEARN calls the repository's metadata-only bridge. Explicit
            # Key-Grip/Subkey-Grip parameters below forbid GnuPG key generation.
            learned = run([tools['gpg_connect_agent'], '--homedir', home,
                           '--agent-program', tools['gpg_agent'], 'LEARN --force', '/bye'], 'learn')
            if b'ERR ' in learned:
                raise RuntimeError('Stock GnuPG rejected disposable component metadata')
            batch = out/'v5.batch'
            batch.write_text(profiles.v5_parameters(EMAIL, grips['PIV.84'], grips['PIV.85'], grips['PIV.9D']))
            created = run(gpg+['--status-fd','1','--pinentry-mode','loopback','--passphrase-fd','0',
                              '--generate-key', batch], 'create', PASSWORD)
            v5.require_status('v5-certificate', created)
            listing = run(gpg+['--with-colons','--list-keys'], 'list').decode()
            primary, hybrid = v5.fingerprints(listing)
            run(gpg+['--output',out/'public-v5.pgp','--export',primary], 'export')
            # These arbitrary synthetic bytes are intentionally separate from
            # mail/MIME tests: the codec test checks exact recovery and detached
            # signatures, without claiming inline signed-message coverage.
            (out/'plain.txt').write_bytes(b'Synthetic stock GnuPG v5 compatibility fixture.\r\n')
            signed = run(gpg+['--status-fd','1','--pinentry-mode','loopback','--passphrase-fd','0',
                             '--local-user',primary+'!','--output',out/'detached.pgp',
                             '--detach-sign',out/'plain.txt'], 'sign', PASSWORD)
            v5.require_status('v5-signing', signed)
            # Stock GnuPG performs the independent public operations. The
            # prepared core above is needed only for explicit batch v5 packet
            # versions and the external-component signing convention.
            stock = [tools['stock_gpg'], '--homedir', home, '--batch', '--yes']
            run(stock+['--verify',out/'detached.pgp',out/'plain.txt'], 'verify')
            # Select the full hybrid fingerprint and retain stock GnuPG's
            # normal payload choice, exercising its tag-20 OCB output.
            run(stock+['--trust-model','always','--recipient',hybrid+'!',
                     '--output',out/'stock-encrypted.pgp','--encrypt',out/'plain.txt'], 'encrypt')
            metadata = {'synthetic_only':True, 'email':EMAIL,
                        'gpg_version':run([tools['gpg'],'--version'],'version').decode().splitlines()[0],
                        'stock_gpg_version':run([tools['stock_gpg'],'--version'],'stock-version').decode().splitlines()[0],
                        'files':{name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in
                                 ('identity.p12','keys.json','public-v5.pgp','plain.txt','detached.pgp','stock-encrypted.pgp')}}
            (out/'fixture.json').write_text(json.dumps(metadata,indent=2)+'\n')
        finally:
            # Stop only this disposable home; never a user's normal agent.
            subprocess.run([str(tools['gpg_connect_agent']), '--homedir', str(home),
                            '--agent-program', str(tools['gpg_agent']), 'KILLAGENT', '/bye'],
                           capture_output=True,timeout=10)
    print('PASS disposable v5 fixture created; prepared-core certificate/signing and stock-GnuPG encryption/verification: '+str(out))


if __name__=='__main__':
    main()
