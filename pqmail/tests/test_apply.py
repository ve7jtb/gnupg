"""Patch application regressions use temporary source fixtures only."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('adapter_apply', Path(__file__).parents[1]/'apply.py')
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Construct the exact supported anchors without depending on a local
        # checkout or modifying real GnuPG build sources.
        self.original = {}
        for name, old, new in patcher.EDITS:
            self.original[name] = self.original.get(name, '') + old + '\n'
        for name, text in self.original.items():
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            path.chmod(0o640)

    def assert_original(self):
        for name, text in self.original.items():
            self.assertEqual((self.root/name).read_text(), text)
        self.assertEqual(list(self.root.rglob('.pqmail-patch-*')), [])

    def test_late_missing_anchor_does_not_write_any_file(self):
        self.original['agent/call-scd.c'] = 'changed upstream source\n'
        (self.root/'agent/call-scd.c').write_text(self.original['agent/call-scd.c'])
        with self.assertRaises(ValueError):
            patcher.apply(self.root)
        self.assert_original()

    def test_ambiguous_anchor_is_rejected_without_writes(self):
        name, old, _ = patcher.EDITS[0]
        self.original[name] += old
        (self.root/name).write_text(self.original[name])
        with self.assertRaises(ValueError):
            patcher.apply(self.root)
        self.assert_original()

    def test_second_rename_failure_restores_first_file(self):
        replace = patcher.os.replace
        count = 0
        def fail_second(src, dst):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('synthetic rename failure')
            replace(src, dst)
        with mock.patch.object(patcher.os, 'replace', side_effect=fail_second):
            with self.assertRaises(OSError):
                patcher.apply(self.root)
        self.assert_original()

    def test_stage_failure_leaves_originals(self):
        stage = patcher.stage
        count = 0
        def fail_late(path, content):
            nonlocal count
            count += 1
            if count == 3:
                raise OSError('synthetic storage failure')
            return stage(path, content)
        with mock.patch.object(patcher, 'stage', side_effect=fail_late):
            with self.assertRaises(OSError):
                patcher.apply(self.root)
        self.assert_original()

    def test_success_and_reapplication_preserve_complete_state(self):
        patcher.apply(self.root)
        expected = dict(self.original)
        for name, old, new in patcher.EDITS:
            expected[name] = expected[name].replace(old, new, 1)
        for name, text in expected.items():
            self.assertEqual((self.root/name).read_text(), text)
            self.assertEqual((self.root/name).stat().st_mode & 0o777, 0o640)
        with self.assertRaises(ValueError):
            patcher.apply(self.root)
        for name, text in expected.items():
            self.assertEqual((self.root/name).read_text(), text)
        self.assertEqual(list(self.root.rglob('.pqmail-patch-*')), [])


if __name__ == '__main__':
    unittest.main()
