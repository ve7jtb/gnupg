"""Exercise the actual nested component supervisor without hardware helpers."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).parents[1]

def load(name):
    spec=importlib.util.spec_from_file_location('review_'+name, ROOT/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

component=load('component')
bridge=load('bridge')


class ComponentProcessTests(unittest.TestCase):
    def test_standalone_deadline_includes_blocked_stdin(self):
        start=time.monotonic()
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            component.bounded_run([sys.executable,'-I','-c','import time;time.sleep(20)'],
                                  b'x'*(1024*1024), {}, timeout=.2)
        self.assertLess(time.monotonic()-start,2)

    def test_component_overflow_does_not_wait_for_child_exit(self):
        code='import sys,time;sys.stdin.buffer.read();sys.stderr.write("x"*16385);sys.stderr.flush();time.sleep(20)'
        start=time.monotonic()
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            component.bounded_run([sys.executable,'-I','-c',code],b'request',{},timeout=3)
        self.assertLess(time.monotonic()-start,2)

    def test_nested_component_remains_in_outer_group_and_cleans_descendants(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker=Path(tmp)/'descendant-survived'
            # An intermediate backend exits while its synthetic native child
            # keeps the pipes. The native child would write a marker if leaked.
            native='import time,pathlib;time.sleep(1);pathlib.Path('+repr(str(marker))+').write_text("alive")'
            backend='import subprocess,sys;sys.stdin.buffer.read();subprocess.Popen([sys.executable,"-I","-c",'+repr(native)+'])'
            wrapper=('import importlib.util,sys,os;'
                     's=importlib.util.spec_from_file_location("component",'+repr(str(ROOT/'component.py'))+');'
                     'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
                     'm.bounded_run([sys.executable,"-I","-c",'+repr(backend)+'],b"test",{},timeout=.2)')
            env={'PATH':os.environ.get('PATH',''),'PQMAIL_SUPERVISED_PROCESS_GROUP':'1'}
            with self.assertRaises(ValueError):
                bridge.bounded_run([sys.executable,'-I','-c',wrapper],b'',env,timeout=.5)
            time.sleep(1.1)
            self.assertFalse(marker.exists(),'native descendant escaped the outer group')

    def test_nested_backend_receives_outer_group_opt_in(self):
        code='import os,sys;sys.stdin.buffer.read();sys.stdout.write(os.environ["PQMAIL_SUPERVISED_PROCESS_GROUP"])'
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(component.bounded_run([sys.executable,'-I','-c',code],b'test',{}),b'1')


if __name__=='__main__':
    unittest.main()
