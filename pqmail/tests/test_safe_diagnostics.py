"""Only synthetic stderr and local journals: no hardware, accounts or real PINs."""
import importlib.util
from pathlib import Path
import os
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('diagnostic_bridge', Path(__file__).parents[1]/'bridge.py')
BRIDGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BRIDGE)


class DiagnosticTests(unittest.TestCase):
    def test_split_marker_is_classified_without_retaining_stderr(self):
        scanner = BRIDGE.SafeDiagnostics()
        for fragment in (b'arbitrary secret data\nPQMAIL_COMPONENT_', b'ERROR adapter public-key-check\n'):
            scanner.feed(fragment)
        self.assertEqual(scanner.value, 'adapter public-key-check')
        self.assertEqual(scanner.pending, bytearray())

    def test_native_pin_error_wins_over_generic_private_stage(self):
        scanner = BRIDGE.SafeDiagnostics()
        scanner.feed(b'PQ Mail: Single-process PKCS#11 X25519 failed at private key check; no retry; PQMAIL_ERROR 408000A0 The specified PIN is incorrect\n')
        scanner.feed(b'PQMAIL_COMPONENT_ERROR adapter recover\n')
        self.assertEqual(scanner.value, 'pin-incorrect')

    def test_unknown_and_oversized_lines_do_not_become_diagnostics(self):
        scanner = BRIDGE.SafeDiagnostics()
        scanner.feed(b'PQMAIL_COMPONENT_ERROR adapter secret-PIN-value\n')
        scanner.feed(b'x'*2049+b'PQMAIL_COMPONENT_ERROR adapter recover\n')
        self.assertIsNone(scanner.value)
        scanner.feed(b'PQMAIL_COMPONENT_ERROR result\n')
        self.assertEqual(scanner.value, 'result')

    def test_journal_contains_only_algorithm_and_allowlisted_category(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'diagnostic.log'
            bridge = BRIDGE.Bridge.__new__(BRIDGE.Bridge)
            bridge.config = {'diagnostic_file':str(path)}
            bridge.record_failure('X25519','adapter pin-incorrect')
            bridge.record_failure('untrusted input','untrusted exception containing a secret')
            self.assertEqual(path.read_text(), 'FAIL X25519 adapter pin-incorrect\nFAIL unknown private-operation\n')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_journal_does_not_block_on_fifo(self):
        with tempfile.TemporaryDirectory() as folder:
            fifo = Path(folder)/'fifo';os.mkfifo(fifo,0o600)
            bridge = BRIDGE.Bridge.__new__(BRIDGE.Bridge)
            bridge.config = {'diagnostic_file':str(fifo)}
            bridge.record_failure('X25519','adapter')

    def test_journal_rejects_symlinks_and_nonprivate_files(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'target';path.write_text('unchanged');path.chmod(0o644)
            link = Path(folder)/'link';link.symlink_to(path)
            bridge = BRIDGE.Bridge.__new__(BRIDGE.Bridge)
            for selected in (link,path):
                bridge.config = {'diagnostic_file':str(selected)}
                bridge.record_failure('X25519','adapter')
            self.assertEqual(path.read_text(),'unchanged')


if __name__=='__main__':unittest.main()
