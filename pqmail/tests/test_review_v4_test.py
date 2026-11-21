"""Software-only orchestration regressions; never invoke a card, PIN UI or GPG."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[1]/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load('review_v4_test', 'review_v4_test.py')
v4 = load('review_existing_v4', 'v4_test.py')


class ReviewHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        # Spaces exercise argument-vector preservation; these are disposable
        # paths and a synthetic serial, not a developer's private workspace.
        self.args = argparse.Namespace(root=root, out=root/'new results',
            app_dir=root/'Selected App', java=root/'JDK/bin/java',
            helper_classes=root/'helper classes', serial='12345678',
            gpg_build=root/'GPG build', stock_gpg=root/'stock/gpg',
            ykman=root/'tools/ykman', preflight_only=False)
        for name in runner.BACKEND_FILES:
            path = self.args.app_dir/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic backend')
        (self.args.app_dir/'dependency.jar').write_bytes(b'synthetic dependency')
        self.before = {'serial': self.args.serial,
                       'slots': {slot: {'empty': True} for slot in runner.SLOTS}}

    def execute(self, child=None, sign=None, receive=None, snapshots=None):
        # All operation providers are replaced, while production audit/file
        # logic still runs against the disposable files and mock snapshots.
        with patch.object(runner, 'preflight'), \
             patch.object(runner, 'snapshot_function', return_value=(snapshots or (lambda _: self.before))), \
             patch.object(runner.subprocess, 'run', side_effect=child or (lambda *a, **k: None)) as standard, \
             patch.object(runner, 'sha256_signature', side_effect=sign) as signer, \
             patch.object(runner, 'receive', side_effect=receive) as receiver, \
             contextlib.redirect_stdout(io.StringIO()):
            runner.execute(self.args)
            return standard, signer, receiver

    def test_all_operations_order_and_installed_paths(self):
        sequence = []
        child = lambda *a, **k: sequence.append('standard three')
        standard, signer, receiver = self.execute(child, lambda *a: sequence.append('SHA256'),
                                                lambda *a: sequence.append('PQ Mail receive'))
        self.assertEqual(sequence, ['standard three', 'SHA256', 'PQ Mail receive'])
        command = standard.call_args.args[0]
        for option, value in [('--app-dir', self.args.app_dir), ('--java', self.args.java),
                              ('--helper-classes', self.args.helper_classes),
                              ('--serial', self.args.serial), ('--stock-gpg', self.args.stock_gpg)]:
            self.assertEqual(command[command.index(option)+1], str(value))
        self.assertIn('five private operations', (self.args.out/'result.txt').read_text())
        self.assertEqual(json.loads((self.args.out/'before.json').read_text()), self.before)
        self.assertEqual((self.args.out/'backend-before.json').read_bytes(),
                         (self.args.out/'backend-after.json').read_bytes())

    def test_failures_stop_later_operations_but_preserve_final_audits(self):
        for failing in ('standard', 'sign', 'receive'):
            with self.subTest(failing=failing):
                self.args.out = self.args.root/failing
                calls = []
                def step(name):
                    def call(*args, **kwargs):
                        calls.append(name)
                        if name == failing:
                            raise RuntimeError('synthetic operation failure')
                    return call
                with self.assertRaisesRegex(RuntimeError, 'synthetic operation'):
                    self.execute(step('standard'), step('sign'), step('receive'))
                self.assertEqual(calls, ['standard', 'sign', 'receive'][:['standard', 'sign', 'receive'].index(failing)+1])
                self.assertTrue((self.args.out/'after.json').is_file())
                self.assertTrue((self.args.out/'backend-after.json').is_file())
                self.assertFalse((self.args.out/'result.txt').exists())

    def test_preflight_only_has_no_supplemental_private_operations(self):
        self.args.preflight_only = True
        standard, signer, receiver = self.execute()
        self.assertIn('--preflight-only', standard.call_args.args[0])
        signer.assert_not_called(); receiver.assert_not_called()
        self.assertIn('no private operations', (self.args.out/'result.txt').read_text())

    def test_final_snapshot_error_still_hashes_backend_and_cannot_pass(self):
        calls = []
        def snapshot(device):
            calls.append(device)
            if len(calls) > 1:
                raise RuntimeError('synthetic disconnected key')
            return self.before
        with self.assertRaisesRegex(RuntimeError, 'Final audit'):
            self.execute(snapshots=snapshot)
        self.assertTrue((self.args.out/'backend-after.json').is_file())
        self.assertFalse((self.args.out/'unchanged.txt').exists())
        self.assertFalse((self.args.out/'result.txt').exists())

    def test_backend_change_cannot_pass_even_if_all_operations_succeed(self):
        def changed(*args, **kwargs):
            (self.args.app_dir/'dependency.jar').write_bytes(b'replaced')
        with self.assertRaisesRegex(RuntimeError, 'Final audit'):
            self.execute(receive=changed)
        self.assertTrue((self.args.out/'after.json').is_file())
        self.assertFalse((self.args.out/'backend-unchanged.txt').exists())
        self.assertFalse((self.args.out/'result.txt').exists())

    def test_partial_or_wrong_device_snapshot_rejected(self):
        for invalid in ({'serial': self.args.serial, 'slots': {}},
                        {'serial': '87654321', 'slots': self.before['slots']}):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(RuntimeError, 'complete 24-slot'):
                runner.full_snapshot(lambda _: invalid, self.args)

    def test_existing_output_rejected_before_command_or_card(self):
        self.args.out.mkdir()
        with patch.object(runner, 'checked') as child, self.assertRaisesRegex(ValueError, 'new result'):
            runner.preflight(self.args)
        child.assert_not_called()

    def test_results_cannot_be_written_into_selected_app_bundle(self):
        app = self.args.root/'PQ Mail.app'
        self.args.app_dir = app/'Contents/app'
        for target in (self.args.app_dir/'results', app/'other-results'):
            self.args.out = target
            with self.subTest(target=target), patch.object(runner, 'checked') as child, self.assertRaisesRegex(ValueError, 'outside'):
                runner.preflight(self.args)
            child.assert_not_called()

    def test_dependency_preflight_and_jar_origin_selftest(self):
        executables = [self.args.java, self.args.stock_gpg, self.args.ykman,
                       self.args.gpg_build/'g10/gpg', self.args.gpg_build/'agent/gpg-agent',
                       self.args.gpg_build/'tools/gpg-connect-agent',
                       self.args.root/'work/sequoia/target/debug/piv-restore']
        for path in executables:
            path.parent.mkdir(parents=True, exist_ok=True); path.write_text('synthetic executable'); path.chmod(0o700)
        for name in ('V4HardwareInterop.class', 'V4InstalledReceive.class'):
            path = self.args.helper_classes/'dev/hybridmail'/name
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'synthetic class')
        path = self.args.root/'work/sequoia/piv-adapter/hardware/run.py'
        path.parent.mkdir(parents=True); path.write_text('# synthetic module')
        with patch.object(runner, 'checked') as child:
            runner.preflight(self.args)
        self.assertEqual(child.call_args.args[0][-2:], ['--self-test', str(self.args.app_dir)])
        cp = child.call_args.args[0][3]
        self.assertEqual(cp, str(self.args.helper_classes)+runner.os.pathsep+str(self.args.app_dir/'*'))
        executables[0].unlink()
        with patch.object(runner, 'checked') as child, self.assertRaisesRegex(ValueError, 'executable'):
            runner.preflight(self.args)
        child.assert_not_called()

    def test_serial_must_be_explicit_positive_decimal(self):
        args = ['--root', str(self.args.root), '--out', str(self.args.out),
                '--app-dir', str(self.args.app_dir), '--java', str(self.args.java),
                '--helper-classes', str(self.args.helper_classes)]
        for suffix in ([], ['--serial', '0'], ['--serial', '12;bad']):
            with self.subTest(suffix=suffix), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runner.arguments(args+suffix)

    def signing_files(self):
        operations = self.args.root/'operations'; restored = operations/'restored'
        restored.mkdir(parents=True)
        (restored/'identity.json').write_text(json.dumps({'serial': int(self.args.serial),
            'liveKeysMatched': True, 'bundleSignatureVerified': True,
            'compatibilityFingerprint': 'A'*40}))
        (operations/'message.txt').write_bytes(b'synthetic message')
        (operations/'agent-home.txt').write_text(str(self.args.root/'short-home'))
        return operations

    def test_sha256_status_stdin_boundary_and_independent_verifiers(self):
        operations = self.signing_files(); captured = {}
        def sign(command, **kwargs):
            captured['command'] = command; captured['request'] = bytes(kwargs['input'])
            captured['buffer'] = kwargs['input']
            return subprocess.CompletedProcess(command, 0, b'[GNUPG:] SIG_CREATED D 22 8 00 1 ABC\n', b'')
        with patch.object(runner.getpass, 'getpass', return_value='123456'), \
             patch.object(runner.subprocess, 'run', side_effect=sign), \
             patch.object(runner, 'checked') as public, contextlib.redirect_stdout(io.StringIO()):
            runner.sha256_signature(self.args, operations)
        self.assertEqual(captured['request'], b'123456\n')
        self.assertEqual(captured['buffer'], b'\0'*7)
        self.assertNotIn('123456', captured['command'])
        self.assertEqual(public.call_count, 4)  # Agent cleanup, import, stock verification, PQ Mail verification.
        self.assertEqual(public.call_args.args[0][-1], str(self.args.app_dir))
        self.assertEqual(public.call_args.args[0][4], 'dev.hybridmail.V4HardwareInterop')

    def test_invalid_signature_status_stops_verification(self):
        operations = self.signing_files()
        # A diagnostic substring is not the GnuPG status protocol.
        result = subprocess.CompletedProcess([], 0, b'noise SIG_CREATED D 22 8 abc\n', b'')
        with patch.object(runner.getpass, 'getpass', return_value='123456'), \
             patch.object(runner.subprocess, 'run', return_value=result), \
             patch.object(runner, 'checked') as public, self.assertRaisesRegex(RuntimeError, 'signing failed'):
            runner.sha256_signature(self.args, operations)
        self.assertEqual(public.call_count, 1)  # Only isolated-agent cleanup.

    def test_receive_uses_terminal_not_pin_arguments(self):
        operations = self.args.root/'operations'
        with patch.object(runner.subprocess, 'run') as child:
            runner.receive(self.args, operations)
        command = child.call_args.args[0]
        self.assertEqual(command[-5:], ['--decrypt', str(operations/'restored'), str(operations),
                                       str(self.args.app_dir), self.args.serial])
        self.assertNotIn('input', child.call_args.kwargs)
        self.assertNotIn('capture_output', child.call_args.kwargs)
        self.assertNotIn('timeout', child.call_args.kwargs)

    def test_standard_signature_and_integrity_require_real_status_lines(self):
        v4.require_status('v4-signing', b'[GNUPG:] SIG_CREATED D 22 10 00 1 ABC\n')
        v4.require_status('pqmail-v4-decryption', b'[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n')
        for label, output in [('v4-signing', b'[GNUPG:] SIG_CREATED D 22 8 00 1 ABC\n'),
                              ('pqmail-v4-decryption', b'[GNUPG:] DECRYPTION_OKAY\n'),
                              ('fixed-gpg-v4-decryption', b'noise DECRYPTION_OKAY GOODMDC')]:
            with self.subTest(label=label), self.assertRaisesRegex(RuntimeError, 'expected'):
                v4.require_status(label, output)

    def test_standard_v4_preparation_uses_selected_installed_jar(self):
        out = self.args.root/'standard'; out.mkdir()
        calls = []
        def public(command, label, *secret):
            self.assertFalse(secret)  # Preflight must never pass a PIN.
            calls.append((list(map(str, command)), label))
            if label == 'v4-keys':
                return ('pub:-:0:22:::::::s:\nfpr:::::::::'+'A'*40+':\n'
                        'sub:-:0:35:::::::e:\nfpr:::::::::'+'B'*40+':\n').encode()
            return b''
        config = {'test_java': str(self.args.java), 'test_classes': str(self.args.helper_classes),
                  'backend_app': str(self.args.app_dir), 'stock_gpg': str(self.args.stock_gpg),
                  'device_serial': self.args.serial}
        with contextlib.redirect_stdout(io.StringIO()):
            v4.test(self.args.root, out, self.args.root/'home', self.args.gpg_build,
                    config, public, preflight=True)
        command = next(command for command, label in calls if label == 'pqmail-v4-prepare')
        self.assertEqual(command[-1], str(self.args.app_dir))
        self.assertEqual(command[3], runner.classpath(self.args))
        self.assertIn('-Djava.awt.headless=true', command)
        preflight = next(command for command, label in calls if label == 'pqmail-v4-receive-preflight')
        self.assertEqual(preflight[-2:], [str(self.args.app_dir), self.args.serial])


if __name__ == '__main__':
    unittest.main()
