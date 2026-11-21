"""Public metadata-only Assuan tests; no library, card or private key access."""
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock

SPEC=importlib.util.spec_from_file_location('metadata_bridge',Path(__file__).resolve().parents[1]/'bridge.py')
BRIDGE=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BRIDGE)


class BridgeMetadataTests(unittest.TestCase):
    def exchange(self,commands):
        # Bypass libgcrypt initialization: these public protocol responses need
        # only a serial string and empty component collection, never a key.
        bridge=BRIDGE.Bridge.__new__(BRIDGE.Bridge)
        bridge.config={};bridge.keys={};bridge.serial='D2760001240100000001'
        bridge.data=bytearray();bridge.inp=io.BytesIO(commands);bridge.out=io.BytesIO()
        bridge.operate=Mock(side_effect=AssertionError('Private operation forbidden'))
        bridge.run()
        bridge.operate.assert_not_called()
        return bridge.out.getvalue().splitlines()

    def test_piv_has_no_single_openpgp_card_fingerprint_hint(self):
        # Successful absence leaves certificate selection to GnuPG's keyring.
        # An ERR here marks an otherwise successful default-key sign as failed.
        response=self.exchange(b'GETATTR KEY-FPR\nBYE\n')
        self.assertEqual(response,[b'OK PQ Mail component bridge',b'OK',b'OK'])
        self.assertFalse(any(b'KEY-FPR ' in line for line in response))

    def test_empty_hint_does_not_claim_an_openpgp_applet(self):
        response=self.exchange(b'GETATTR APPTYPE\nGETATTR KEY-FPR\nBYE\n')
        self.assertIn(b'S APPTYPE PIV',response)
        self.assertFalse(any(b'ERR ' in line for line in response))

    def test_unrecognized_attribute_or_extra_argument_is_rejected(self):
        # Scope the compatibility allowance narrowly; arbitrary card commands
        # must not become successes merely because one optional hint is absent.
        response=self.exchange(b'GETATTR KEY-FPR arbitrary\nGETATTR UNKNOWN\nBYE\n')
        self.assertEqual(sum(line.startswith(b'ERR ') for line in response),2)


if __name__=='__main__':unittest.main()
