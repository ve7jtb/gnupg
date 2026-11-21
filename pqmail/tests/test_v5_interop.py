"""Software-only v5 harness sequencing tests; no card, app or GnuPG is launched."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('v5_interop_harness', SOURCE/'v5_test.py')
V5 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V5)
PROFILES = V5.load('v5_test_profiles', SOURCE/'profiles.py')
PRIMARY = 'A'*64
HYBRID = 'B'*64
MESSAGE = b'Synthetic GnuPG v5 YubiKey compatibility test.\r\n'


def listing(primary=PRIMARY, hybrid=HYBRID):
    """Minimal colon records model only public fingerprint/algorithm fields."""
    return ('pub::255:22::::::\nfpr:::::::::'+primary+':\n'
            'sub::768:8::::::\nfpr:::::::::'+hybrid+':\n')


class V5InteropTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='v5-harness-unit-')
        self.root = Path(self.temporary.name)
        self.out = self.root/'out'; self.out.mkdir()
        self.home = self.root/'home'; self.home.mkdir()
        self.build = self.root/'gpg-build'
        self.config = dict(email='interop@example.test', test_java=str(self.root/'java'),
                           test_classes=str(self.root/'drivers'), backend_app=str(self.root/'app'),
                           device_serial='123', stock_gpg=str(self.root/'stock-gpg'))
        keys = {'C'*40:dict(reference='PIV.88',algorithm='Ed25519'),
                'D'*40:dict(reference='PIV.85',algorithm='X25519'),
                'E'*40:dict(reference='PIV.9D',algorithm='ML-KEM-768')}
        self.bridge = types.SimpleNamespace(Bridge=lambda *args: types.SimpleNamespace(keys=keys))
        self.events = []

    def tearDown(self):
        self.temporary.cleanup()

    def run_public(self, command, name, secret=None):
        # This fake driver returns fixed public status and writes only dummy
        # synthetic fixtures. A future unmocked executable would be a bug.
        self.events.append((name,list(map(str,command))))
        if name == 'v5-certificate':
            self.assertEqual(secret, bytearray(b'123456\n'))
            return b'[GNUPG:] KEY_CREATED B '+PRIMARY.encode()+b'\n'
        if name == 'v5-list': return listing().encode()
        if name == 'v5-export': (self.out/'openpgp-v5.pgp').write_bytes(b'public-fixture')
        if name == 'pqmail-v5-prepare':
            (self.out/'v5-message.txt').write_bytes(MESSAGE)
            (self.out/'pqmail-v5-encrypted.pgp').write_bytes(b'pq-ciphertext')
        if name == 'stock-v5-encrypt': (self.out/'stock-v5-encrypted.pgp').write_bytes(b'gpg-ciphertext')
        if name == 'v5-signing':
            (self.out/'v5-signature.pgp').write_bytes(b'gpg-signature')
            return b'[GNUPG:] SIG_CREATED D 22 10 00 0 '+PRIMARY.encode()+b'\n'
        if name == 'pqmail-v5-decryption':
            (self.out/'pqmail-v5-plain.txt').write_bytes(MESSAGE)
            return b'[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n'
        return b''

    def fake_private(self, config, mode, restored, out):
        self.events.append((mode,[]))
        if mode == '--sign': (out/'pqmail-v5-signature.pgp').write_bytes(b'pq-signature')
        elif mode == '--decrypt': (out/'pqmail-v5-receive.txt').write_text('PASS synthetic receive\n')
        else: self.fail('Unknown private Java mode')

    def operate(self, run=None):
        with patch.object(V5.getpass,'getpass',return_value='123456') as prompt, \
             patch.object(V5.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as process, \
             patch.object(V5,'private_java',side_effect=self.fake_private):
            V5._operations(self.out,self.home,self.build,self.config,run or self.run_public,
                           self.bridge,PROFILES)
        return prompt,process

    def test_full_sequence_has_two_signers_and_two_receivers(self):
        prompt, process = self.operate()
        self.assertEqual(prompt.call_count,3)  # Other two prompts belong to Java.
        self.assertEqual(process.call_count,3) # Kill only the isolated test agent.
        names = [name for name,_ in self.events]
        self.assertLess(names.index('pqmail-v5-receive-preflight'),names.index('v5-signing'))
        self.assertLess(names.index('v5-signing'),names.index('--sign'))
        self.assertLess(names.index('--sign'),names.index('pqmail-v5-decryption'))
        self.assertLess(names.index('pqmail-v5-decryption'),names.index('--decrypt'))
        self.assertIn('pqmail-v5-verify',names)
        self.assertIn('stock-v5-verify',names)
        self.assertIn('stock-pqmail-v5-verify',names)
        stock_encrypt = dict(self.events)['stock-v5-encrypt']
        self.assertEqual(stock_encrypt[0],self.config['stock_gpg'])
        self.assertIn(HYBRID+'!',stock_encrypt)
        self.assertNotIn('123456',stock_encrypt)
        self.assertIn('ciphertexts unsigned', (self.out/'v5-operations.txt').read_text())
        self.assertTrue((self.out/'v5-signing.status').is_file())

    def test_certificate_batch_references_only_existing_components(self):
        self.operate()
        batch = (self.out/'v5-existing-keys.batch').read_text()
        self.assertIn('Key-Grip: '+('C'*40),batch)
        self.assertIn('Subkey-Grip: '+('D'*40)+','+('E'*40),batch)
        self.assertIn('Key-Version: 5',batch)
        self.assertIn('Subkey-Type: 8',batch)
        self.assertNotIn('Key-Length:',batch)

    def test_preflight_failure_stops_before_message_private_operations(self):
        def failed(command,name,secret=None):
            if name == 'pqmail-v5-receive-preflight': raise RuntimeError('Bad public packet')
            return self.run_public(command,name,secret)
        with self.assertRaisesRegex(RuntimeError,'Bad public packet'):
            self.operate(failed)
        names = [name for name,_ in self.events]
        self.assertIn('v5-certificate',names)
        self.assertNotIn('v5-signing',names)
        self.assertNotIn('--sign',names)
        self.assertFalse((self.out/'result.txt').exists())

    def test_integrity_failure_stops_before_second_decryption(self):
        def failed(command,name,secret=None):
            value=self.run_public(command,name,secret)
            return b'[GNUPG:] DECRYPTION_OKAY\n' if name=='pqmail-v5-decryption' else value
        with self.assertRaisesRegex(RuntimeError,'Missing expected'):
            self.operate(failed)
        self.assertNotIn('--decrypt',[name for name,_ in self.events])
        self.assertFalse((self.out/'result.txt').exists())

    def test_wrong_component_role_fails_before_prompt(self):
        self.bridge=types.SimpleNamespace(Bridge=lambda *args:types.SimpleNamespace(keys={}))
        with patch.object(V5.getpass,'getpass') as prompt:
            with self.assertRaisesRegex(ValueError,'not uniquely mapped'):
                V5._operations(self.out,self.home,self.build,self.config,self.run_public,self.bridge,PROFILES)
            prompt.assert_not_called()

    def test_pin_never_becomes_a_command_argument(self):
        self.operate()
        for name,command in self.events:
            self.assertNotIn('123456',command)
        self.assertEqual((self.out/'v5-existing-keys.batch').read_text().count('interop@example.test'),1)

    def test_private_java_uses_terminal_and_selected_app(self):
        with patch.object(V5.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as run:
            V5.private_java(self.config,'--decrypt',self.out/'restored',self.out)
        command=run.call_args.args[0]
        self.assertIn('-Djava.awt.headless=true',command)
        self.assertIn(self.config['backend_app'],command)
        self.assertEqual(command[-1],'123')
        for option in ('input','timeout','capture_output','stdin'):
            self.assertNotIn(option,run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs,dict(check=True))

    def test_full_fingerprints_and_algo8_are_required(self):
        self.assertEqual(V5.fingerprints(listing()),(PRIMARY,HYBRID))
        for bad in (listing(hybrid='B'*40),listing().replace('sub::768:8:','sub::768:35:'),
                    listing()+listing()):
            with self.assertRaises(ValueError): V5.fingerprints(bad)

    def test_status_cannot_be_satisfied_by_diagnostic_prose(self):
        for label,status in (('v5-signing',b'fake [GNUPG:] SIG_CREATED D 22 10'),
                             ('v5-certificate',b'KEY_CREATED'),
                             ('pqmail-v5-decryption',b'DECRYPTION_OKAY GOODMDC')):
            with self.assertRaises(RuntimeError): V5.require_status(label,status)

    def test_backend_audit_runs_after_operation_failure(self):
        audit=types.SimpleNamespace(installed_hashes=lambda app:{'jar':'same'})
        def loader(name,path):
            return audit if name=='v5_backend_audit' else object()
        with patch.object(V5,'load',side_effect=loader), \
             patch.object(V5,'_operations',side_effect=RuntimeError('synthetic failure')):
            with self.assertRaisesRegex(RuntimeError,'synthetic failure'):
                V5.test(self.root,self.out,self.home,self.build,self.config,self.run_public)
        self.assertEqual(json.loads((self.out/'v5-backend-before.json').read_text()),
                         json.loads((self.out/'v5-backend-after.json').read_text()))
        self.assertTrue((self.out/'v5-backend-unchanged.txt').is_file())

    def test_changed_backend_prevents_unchanged_claim(self):
        values=iter([{'jar':'before'},{'jar':'after'}])
        audit=types.SimpleNamespace(installed_hashes=lambda app:next(values))
        with patch.object(V5,'load',side_effect=lambda name,path:audit if name=='v5_backend_audit' else object()), \
             patch.object(V5,'_operations'):
            with self.assertRaisesRegex(RuntimeError,'backend changed'):
                V5.test(self.root,self.out,self.home,self.build,self.config,self.run_public)
        self.assertFalse((self.out/'v5-backend-unchanged.txt').exists())


if __name__ == '__main__': unittest.main()
