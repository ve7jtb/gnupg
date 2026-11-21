"""Bounded bridge child tests; generated subprocesses never access a card."""
import importlib.util
import os
from pathlib import Path
import sys
import time
import unittest

spec = importlib.util.spec_from_file_location('bounded_bridge', Path(__file__).parents[1]/'bridge.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeProcessTests(unittest.TestCase):
    def run_child(self, code, request=b'test request\n', timeout=3, limit=12000):
        # Do not forward application/provider configuration into synthetic children.
        return bridge.bounded_run([sys.executable, '-I', '-c', code], request,
                                  {'PATH': os.environ.get('PATH', '')}, timeout, limit)

    def test_exact_output_limit_is_allowed(self):
        code = 'import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b"x"*12000)'
        self.assertEqual(self.run_child(code), b'x'*12000)

    def test_stdout_overflow_rejected_while_child_is_still_running(self):
        code = 'import sys,time;sys.stdin.buffer.read();sys.stdout.buffer.write(b"x"*12001);sys.stdout.flush();time.sleep(20)'
        start = time.monotonic()
        with self.assertRaises(ValueError):
            self.run_child(code)
        self.assertLess(time.monotonic()-start, 2)

    def test_stderr_overflow_rejected_without_echoing_diagnostics(self):
        code = 'import sys,time;sys.stdin.buffer.read();sys.stderr.buffer.write(b"s"*12001);sys.stderr.flush();time.sleep(20)'
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, '^Private component failed; no retry$'):
            self.run_child(code)
        self.assertLess(time.monotonic()-start, 2)

    def test_both_streams_are_drained_concurrently(self):
        code = 'import sys;sys.stdin.buffer.read();sys.stderr.buffer.write(b"s"*12000);sys.stderr.flush();sys.stdout.buffer.write(b"reply")'
        self.assertEqual(self.run_child(code), b'reply')

    def test_nonzero_exit_is_rejected(self):
        with self.assertRaises(ValueError):
            self.run_child('import sys;sys.stdin.buffer.read();sys.exit(7)')

    def test_nonreading_child_cannot_block_stdin_past_deadline(self):
        start = time.monotonic()
        with self.assertRaises(ValueError):
            self.run_child('import time;time.sleep(20)', b'x'*(1024*1024), timeout=.2)
        self.assertLess(time.monotonic()-start, 2)

    @unittest.skipUnless(os.name == 'posix', 'POSIX process-group cleanup')
    def test_descendant_retaining_pipes_is_stopped_at_deadline(self):
        code = 'import subprocess,sys;sys.stdin.buffer.read();subprocess.Popen([sys.executable,"-c","import time;time.sleep(20)"])'
        start = time.monotonic()
        with self.assertRaises(ValueError):
            self.run_child(code, timeout=.3)
        self.assertLess(time.monotonic()-start, 2)


if __name__ == '__main__':
    unittest.main()
