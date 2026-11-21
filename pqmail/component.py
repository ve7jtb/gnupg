#!/usr/bin/env python3
"""Private-component adapter to PQ Mail's existing PKCS#11 helpers.

Input is four bounded lines: algorithm, public SPKI, message/ciphertext, PIN.
The trusted local configuration maps exact public keys to a device and slot.
No provision, reset, certificate write, or touch-policy operation is exposed.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import importlib.util


def payload(algorithm, public, incoming):
    """Translate GnuPG primitives, keeping OpenPGP hashing/combining in GnuPG."""
    if algorithm == 'ML-DSA-65':
        prefix = bytes.fromhex('308207b2300b0609608648016503040312038207a100')
        if not public.startswith(prefix) or len(public) != len(prefix) + 1952:
            raise ValueError('Invalid ML-DSA-65 public key')
        if len(incoming) not in (48, 64):
            raise ValueError('Use SHA384 or SHA512 for this hardware profile')
        # FIPS 204 external mu for pure ML-DSA with an empty context. The
        # incoming value is already the OpenPGP digest; this is not HashML-DSA.
        # FIPS 204 message framing is 0x00 || context_length || context || M.
        # With an empty context the two zero octets are mandatory domain
        # separation, even though M here is the OpenPGP signature digest.
        tr = hashlib.shake_256(public[len(prefix):]).digest(64)
        return hashlib.shake_256(tr + b'\0\0' + incoming).digest(64)
    # Classical Ed25519 permits a SHA-256 OpenPGP digest too. Do not copy
    # the ML-DSA-65 profile's SHA-384/SHA-512 restriction to this component.
    if algorithm == 'Ed25519' and len(incoming) in (32, 48, 64):
        return incoming
    if algorithm == 'X25519' and len(incoming) == 32:
        # The existing PKCS#11 adapter accepts the peer as a complete SPKI.
        return bytes.fromhex('302a300506032b656e032100') + incoming
    if algorithm == 'ML-KEM-768' and len(incoming) == 1088:
        return incoming
    raise ValueError('Unsupported algorithm or input length')


def bounded_run(command, request, env, timeout=110, limit=16384):
    """Use the same nonblocking supervisor as the outer Assuan bridge.

    The reviewed sibling module contains protocol code only; importing it does
    not load a configuration, contact a card, or execute its main function.
    Explicit loading also works with Python -I, which excludes the script
    directory from ordinary module search paths.
    """
    path = Path(__file__).with_name('bridge.py')
    spec = importlib.util.spec_from_file_location('pqmail_bounded_bridge', path)
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    # If launched by the bridge, remain in its fresh group so its timeout and
    # success cleanup also reach descendants. A standalone component creates
    # its own group. Its adapter/native children always inherit that group.
    inherited_group = os.environ.get('PQMAIL_SUPERVISED_PROCESS_GROUP') == '1'
    child_env = dict(env, PQMAIL_SUPERVISED_PROCESS_GROUP='1')
    return bridge.bounded_run(command, request, child_env, timeout, limit,
                              own_group=not inherited_group)


class ComponentError(ValueError):
    """Carry only an allowlisted public failure stage across the child pipe."""
    def __init__(self, stage, detail=None):
        allowed = ('arguments', 'input', 'pin-callback-setup', 'providers',
                   'public-key-check', 'pin-input', 'private-key-check', 'recover',
                   'output', 'pin-incorrect', 'pin-invalid', 'pin-expired')
        self.diagnostic = stage + (' '+detail if stage=='adapter' and detail in allowed else '')
        super().__init__('GnuPG PIV component failed; no retry')


def main():
    """Only locally configured paths/slots may route a private operation."""
    config = json.loads(Path(sys.argv[1]).read_text())
    # The wire protocol is exactly algorithm/SPKI/input/PIN, one line each.
    # Base64 keeps arbitrary public bytes out of the newline delimiters; the
    # PIN is validated as printable ASCII before any hardware child starts.
    fields = [sys.stdin.buffer.readline(8193) for _ in range(4)]
    pin = bytearray(fields.pop().rstrip(b'\n'))
    request = bytearray()
    stage = 'request'
    try:
        if any(len(x) > 8192 or not x.endswith(b'\n') for x in fields):
            raise ValueError('Malformed component input')
        stage = 'pin-format'
        if not 6 <= len(pin) <= 8 or any(x < 32 or x > 126 for x in pin):
            raise ValueError('Invalid PIV PIN format')
        stage = 'request'
        algorithm = fields[0].strip().decode('ascii')
        public, incoming = [base64.b64decode(x.strip(), validate=True) for x in fields[1:]]
        # Match the full SPKI, not just an algorithm or a caller-supplied slot.
        stage = 'identity-binding'
        matches = [k for k in config['keys'] if base64.b64decode(k['spki'], validate=True) == public]
        if len(matches) != 1:
            raise ValueError('Key is not uniquely mapped in this identity')
        stage = 'slot-mapping'
        slot = matches[0]['reference'].split('.')[-1].lower()
        # These are the currently implemented Level 3 hardware roles, not an
        # unrestricted PIV slot selector. A future manifest layout must extend
        # this policy explicitly rather than forwarding arbitrary references.
        permitted = {'ML-DSA-65': ('9c', '86'), 'Ed25519': ('84', '87', '88'),
                     'ML-KEM-768': ('9d',), 'X25519': ('85', '89')}
        if slot not in permitted.get(algorithm, ()):
            raise ValueError('Unsupported algorithm/slot mapping')
        app = Path(config['backend_app'])
        if not app.is_absolute() or not str(config['device_serial']).isdecimal():
            raise ValueError('Explicit backend and device serial required')
        signing = algorithm in ('Ed25519', 'ML-DSA-65')
        script = app / 'adapters' / ('pkcs11-mu.py' if signing else 'pkcs11-kem.py')
        # Drop inherited slot overrides and provider settings; these values
        # come only from the reviewed local restore configuration.
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'TMPDIR', 'SystemRoot')}
        env.update(OPENSSL_BIN=str(app/'native/bin/openssl'),
                   PKCS11_PROVIDER=str(app/'native/lib/pkcs11.dylib'),
                   PKCS11_MODULE=str(app/'native/lib/libykcs11.dylib'),
                   PKCS11_SERIAL=str(config['device_serial']), HYBRID_MAIL_PIN_STDIN='1',
                   PKCS11_TRADITIONAL_SLOT=slot, PKCS11_KEM_SLOT=slot, PKCS11_ECDH_SLOT=slot)
        # Certification and compatibility slots are opt-in exceptions in the
        # shared PKCS#11 wrappers. Set the exception only for this request so
        # a prior invocation cannot change a later operation's slot policy.
        if slot in ('86', '87'):
            env['PQMAIL_CERTIFICATION_SLOTS'] = '86,87'
        if slot in ('88', '89'):
            env['PQMAIL_COMPATIBILITY_SLOT'] = slot
        stage = 'payload'
        converted = payload(algorithm, public, incoming)
        request.extend(algorithm.encode() + b'\n' + base64.b64encode(public) + b'\n')
        request.extend(base64.b64encode(converted) + b'\n' + pin + b'\n')
        stage = 'adapter'
        reply = bounded_run(['/usr/bin/python3', '-I', '-B', str(script)], request, env)
        # Signing helpers return base64; KEM helpers return raw shared secrets.
        stage = 'result'
        raw = base64.b64decode(reply.strip(), validate=True) if signing else reply
        expected = {'ML-DSA-65': 3309, 'Ed25519': 64, 'ML-KEM-768': 32, 'X25519': 32}[algorithm]
        if len(raw) != expected:
            raise ValueError('Wrong private-operation result length')
        sys.stdout.buffer.write(base64.b64encode(raw) + b'\n')
    except Exception as error:
        raise ComponentError(stage, getattr(error, 'diagnostic', None)) from None
    finally:
        # Clear buffers under our control; immutable Python/subprocess copies
        # can outlive this overwrite, so the helper process is also short-lived.
        pin[:] = b'\0' * len(pin)
        request[:] = b'\0' * len(request)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Only a closed stage/category crosses stderr. Never include exception
        # messages, input values, raw child stderr, PINs or shared secrets.
        category = error.diagnostic if isinstance(error, ComponentError) else 'request'
        print('PQMAIL_COMPONENT_ERROR '+category, file=sys.stderr)
        sys.exit(1)
