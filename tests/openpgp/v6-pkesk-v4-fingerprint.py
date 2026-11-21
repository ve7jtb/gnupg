#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Standalone regression for the v6 PKESK fingerprint length.

Requires Python 3 and GnuPG with --allow-9980/ML-KEM-768 support. Only the
adjacent synthetic public certificate is imported. No private key, card,
PKCS#11 module, PQ Mail installation or network service is required.

Run: python3 v6-pkesk-v4-fingerprint.py --gpg /path/to/gpg
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def packet_body(data):
    """Return the first definite-length new-format PKESK, rejecting truncation."""
    if len(data) < 2 or data[0] != 0xc1:
        raise AssertionError('Expected a new-format public-key encrypted packet')
    first = data[1]
    if first < 192:
        offset, length = 2, first
    elif first < 224 and len(data) >= 3:
        offset, length = 3, ((first - 192) << 8) + data[2] + 192
    elif first == 255 and len(data) >= 6:
        offset, length = 6, int.from_bytes(data[2:6], 'big')
    else:
        raise AssertionError('Unexpected partial/truncated PKESK header')
    if len(data) < offset + length:
        raise AssertionError('Truncated PKESK')
    return data[offset:offset + length]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gpg', required=True)
    parser.add_argument('--gpgconf', default=shutil.which('gpgconf'))
    args = parser.parse_args()
    # Resolve relative executable paths before switching to the isolated home.
    gpg = str(Path(shutil.which(args.gpg) or args.gpg).resolve())
    fixture = Path(__file__).resolve().with_name('v4-mlkem768-public.asc')
    with tempfile.TemporaryDirectory(prefix='pkesk-test-') as directory:
        home = Path(directory)
        home.chmod(0o700)
        (home/'gpg-agent.conf').write_text('disable-scdaemon\n')
        env = dict(os.environ, GNUPGHOME=str(home))
        base = [gpg, '--no-options', '--homedir', str(home), '--batch',
                '--yes', '--allow-9980', '--no-auto-key-retrieve',
                '--auto-key-locate', 'clear', '--no-autostart']

        def run(arguments):
            """Keep diagnostics on failure without exposing any user keyring."""
            result = subprocess.run(base + arguments, env=env, cwd=home,
                                    capture_output=True, timeout=60)
            if result.returncode:
                raise RuntimeError(result.stderr.decode(errors='replace'))
            return result.stdout

        try:
            run(['--import', str(fixture)])
            listing = run(['--with-colons', '--list-keys']).decode()
            recipients, pending = [], False
            for line in listing.splitlines():
                fields = line.split(':')
                if fields[0] in ('pub', 'sub'):
                    pending = fields[0] == 'sub' and fields[3] == '35'
                elif fields[0] == 'fpr' and pending:
                    recipients.append(bytes.fromhex(fields[9]))
                    pending = False
            if len(recipients) != 1 or len(recipients[0]) != 20:
                raise AssertionError('Fixture must have exactly one v4 ML-KEM subkey')
            fingerprint = recipients[0]
            (home/'message.txt').write_bytes(b'Synthetic PKESK regression test.\n')
            failures = []
            for anonymous in (False, True):
                label = 'anonymous' if anonymous else 'v4-fingerprint'
                # Pin the hybrid subkey: no substitution by the optional
                # classical subkey, and no recipient trust interaction.
                options = ['--throw-keyids'] if anonymous else []
                run(options + ['--trust-model', 'always', '--recipient',
                               fingerprint.hex() + '!', '--output', 'message.pgp',
                               '--encrypt', 'message.txt'])
                body = packet_body((home/'message.pgp').read_bytes())
                # A v6 PKESK may address a v4 key: these two version fields
                # describe different things. Anonymous recipients omit both
                # the key version and fingerprint, but keep the algorithm.
                prefix = bytes([6, 0]) if anonymous else bytes([6, 21, 4]) + fingerprint
                expected_length = len(prefix) + 1 + 32 + 1088 + 1 + 40
                correct = (body.startswith(prefix) and len(body) == expected_length
                           and body[len(prefix)] == 35 and body[-41] == 40)
                print(('PASS ' if correct else 'FAIL ') + label +
                      ': algorithm=%d, body length=%d (expected %d)' %
                      (body[len(prefix)], len(body), expected_length))
                if not correct:
                    failures.append(label)
            if failures:
                raise SystemExit('Invalid PKESK serialization: ' + ', '.join(failures))
        finally:
            # Kill only agents associated with this disposable test home.
            # gpgconf is optional because public encryption can run without it.
            if args.gpgconf:
                subprocess.run([args.gpgconf, '--homedir', str(home), '--kill', 'all'],
                               env=env, capture_output=True, timeout=15)


if __name__ == '__main__':
    main()
