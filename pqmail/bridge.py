#!/usr/bin/env python3
"""Bounded Assuan component bridge for password-protected PKCS#12 identities.

No OpenPGP packet or trust policy is implemented here. GnuPG owns the digest,
combiner and packet layers. Public component metadata is local configuration;
private data is passed only to a short-lived process through anonymous pipes.
Hardware adapters may reuse this protocol without becoming dependencies of the
software branch. No generation, key import, deletion or card APDU is exposed.
"""
import base64, ctypes, hashlib, json, os, re, signal, subprocess, sys, selectors, time
from pathlib import Path
# This is the aggregate decoded SETDATA bound, separate from Assuan's
# per-line limit. ML-KEM ciphertexts arrive over several hex-encoded lines.
MAX=8192

def atom(x):
    # Canonical S-expression lengths count octets, not Unicode characters.
    # Binary curve points/signatures must remain opaque to the Assuan framing.
    if isinstance(x,str): x=x.encode('ascii')
    return str(len(x)).encode()+b':'+x

def sexp(*items):
    return b'('+b''.join(items)+b')'

def unescape(s):
    """Decode Assuan octets; malformed escapes fail, never partially decode."""
    if re.search(rb'%(?![0-9A-Fa-f]{2})',s): raise ValueError('Bad escape')
    return re.sub(rb'%([0-9A-Fa-f]{2})',lambda m:bytes([int(m[1],16)]),s)

def escape(s):
    return s.replace(b'%',b'%25').replace(b'\r',b'%0D').replace(b'\n',b'%0A')

def public_key(der, legacy=False):
    """Accept exact SPKI encodings; a role cannot smuggle a different algorithm."""
    formats=[('Ed25519','302a300506032b6570032100',32),
             ('X25519','302a300506032b656e032100',32),
             ('ML-DSA-65','308207b2300b0609608648016503040312038207a100',1952),
             ('ML-KEM-768','308204b2300b0609608648016503040402038204a100',1184)]
    for alg,prefix,n in formats:
        pre=bytes.fromhex(prefix)
        if der.startswith(pre) and len(der)==len(pre)+n:
            raw=der[len(pre):]
            if alg=='Ed25519': key=sexp(atom('ecc'),sexp(atom('curve'),atom('Ed25519')),sexp(atom('flags'),atom('eddsa')),sexp(atom('q'),atom(raw)))
            elif alg=='X25519':
                # LibrePGP uses the curve OID and 0x40 point prefix; IETF v6
                # uses the fixed-width algorithm-25 component encoding.
                if legacy:
                    key=sexp(atom('ecc'),sexp(atom('curve'),atom('Curve25519')),sexp(atom('flags'),atom('djb-tweak')),sexp(atom('q'),atom(b'\x40'+raw)))
                else:
                    key=sexp(atom('ecc'),sexp(atom('curve'),atom('ietf25')),sexp(atom('q'),atom(raw)))
            else:key=sexp(atom('dilithium3' if alg=='ML-DSA-65' else 'kyber768'),sexp(atom('p'),atom(raw)))
            return alg,raw,sexp(atom('public-key'),key)
    raise ValueError('Unsupported SPKI')

def bounded_run(command, request, env, timeout=120, limit=12000, own_group=True):
    """Drive all three pipes under one deadline without secret-owning threads.

    Top-level callers own a fresh process group. A nested supervised component
    stays in that group, so the outer supervisor can kill the whole helper
    chain even if an intermediate wrapper has already exited.
    """
    if os.name != 'posix':
        raise ValueError('Bounded connector subprocesses require macOS or Linux')
    deadline = time.monotonic() + timeout
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=env, start_new_session=own_group)
    output = bytearray()
    seen = {'stdout': 0, 'stderr': 0}
    sent = 0
    selector = selectors.DefaultSelector()
    pipes = (child.stdin, child.stdout, child.stderr)

    def close(stream):
        try:
            selector.unregister(stream)
        except KeyError:
            pass
        stream.close()

    def stop():
        try:
            if own_group:
                # Own only the group created by this call; a nested component
                # must not kill its own parent/siblings while returning status.
                os.killpg(child.pid, signal.SIGKILL)
            elif child.poll() is None:
                child.kill()
        except ProcessLookupError:
            pass

    try:
        for pipe in pipes:
            os.set_blocking(pipe.fileno(), False)
        selector.register(child.stdout, selectors.EVENT_READ, 'stdout')
        selector.register(child.stderr, selectors.EVENT_READ, 'stderr')
        if request:
            selector.register(child.stdin, selectors.EVENT_WRITE, 'stdin')
        else:
            child.stdin.close()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Private component failed; no retry')
            # OS-level writes avoid BufferedWriter retaining another request
            # copy or blocking while flushing after the explicit deadline.
            for key, events in selector.select(min(.05, remaining)):
                stream, role = key.fileobj, key.data
                try:
                    if role == 'stdin':
                        sent += os.write(stream.fileno(), memoryview(request)[sent:])
                        if sent == len(request):
                            close(stream)
                    else:
                        chunk = os.read(stream.fileno(), min(4096, limit+1-seen[role]))
                        if not chunk:
                            close(stream)
                            continue
                        seen[role] += len(chunk)
                        if seen[role] > limit:
                            raise ValueError('Private component failed; no retry')
                        if role == 'stdout':
                            output.extend(chunk)
                        # Stderr is drained and counted, never retained or
                        # reported: helpers can accidentally print secrets.
                except BlockingIOError:
                    continue
                except InterruptedError:
                    continue
            status = child.poll()
            if status is not None and not selector.get_map():
                if status or sent != len(request):
                    raise ValueError('Private component failed; no retry')
                return bytes(output)
    except (OSError, subprocess.SubprocessError):
        raise ValueError('Private component failed; no retry') from None
    finally:
        # The outer group covers native descendants too. A component's earlier
        # timeout (110s vs 120s) lets it report failure; outer cleanup still runs
        # if it cannot. No background thread keeps a PIN/request after return.
        stop()
        selector.close()
        for pipe in pipes:
            if not pipe.closed:
                pipe.close()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            # SIGKILL can be delayed by an OS-level uninterruptible operation;
            # do not retain the secret in a waiter thread or retry the request.
            pass
        output[:] = b'\0'*len(output)


class Bridge:
    def __init__(self, config, inp, out):
        self.config=config;self.inp=inp;self.out=out;self.data=bytearray();self.keys={}
        # This is an explicit local library path, never read from a bundle.
        lib=ctypes.CDLL(config['libgcrypt']);lib.gcry_check_version(None)
        lib.gcry_sexp_new.argtypes=[ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
        lib.gcry_pk_get_keygrip.argtypes=[ctypes.c_void_p,ctypes.c_void_p];lib.gcry_pk_get_keygrip.restype=ctypes.c_void_p
        lib.gcry_sexp_release.argtypes=[ctypes.c_void_p]
        # A keygrip identifies libgcrypt's component representation, not the
        # OpenPGP certificate fingerprint. V4/v6 certificates may share grips;
        # LibrePGP's X25519 representation deliberately uses different inputs.
        for k in config['keys']:
            der=base64.b64decode(k['spki'],validate=True);alg,raw,public=public_key(der, config.get('wire_profile', 'v6') == 'v5')
            obj=ctypes.c_void_p();buf=ctypes.create_string_buffer(public);grip=ctypes.create_string_buffer(20)
            if lib.gcry_sexp_new(ctypes.byref(obj),buf,len(public),1):raise ValueError('Invalid public key')
            try:
                if not lib.gcry_pk_get_keygrip(obj,grip):raise ValueError('Unsupported keygrip')
            finally:lib.gcry_sexp_release(obj)
            item=dict(k,algorithm=alg,raw=raw,public=public,grip=grip.raw.hex().upper())
            if item['grip'] in self.keys:raise ValueError('Duplicate keygrip')
            self.keys[item['grip']]=item
        self.serial=config['serial']
        if not re.fullmatch('[0-9A-F]{8,40}',self.serial):raise ValueError('Invalid bridge serial')
    def line(self,s):
        self.out.write(s+b'\n');self.out.flush()
    def send(self,data):
        # Splitting precedes escaping: even a chunk of only escaped octets
        # remains below the line limit (250 * 3 plus the 'D ' prefix).
        for i in range(0,len(data),250):self.line(b'D '+escape(data[i:i+250]))
    def read(self):
        b=self.inp.readline(1001)
        if len(b)>1000 or (b and not b.endswith(b'\n')):raise ValueError('Overlong Assuan line')
        return b.rstrip(b'\r\n')
    def key(self,text):
        text=text.upper()
        matches=[v for g,v in self.keys.items() if text in (g,v['reference'].upper())]
        if len(matches)!=1:raise ValueError('Unknown key')
        return matches[0]
    def password(self):
        self.line(b'INQUIRE NEEDPIN ||'+self.config.get('prompt','PKCS#12 identity password').encode())
        data=bytearray()
        try:
            while True:
                line=self.read()
                if line==b'END':break
                if not line.startswith(b'D '):raise ValueError('Cancelled password request')
                data.extend(unescape(line[2:]))
                if len(data)>256:raise ValueError('Oversized password')
            # NEEDPIN is an agent inquiry, not an independently trusted UI: the
            # caller controls whether a real pinentry or loopback source supplies
            # the value. Never interpret it as permission to retry a failed PIN.
            # gpg-agent pads NEEDPIN responses to its fixed buffer size.
            p=data.find(0)
            if p>=0:del data[p:]
            if not data or b'\n' in data or b'\r' in data:raise ValueError('Invalid password')
            return data
        except BaseException:
            data[:]=b'\0'*len(data);raise
    def operate(self,key,operation):
        # The caller supplies an OpenPGP digest or a raw KEM component input.
        # The bridge must not hash the digest again or implement its own
        # RFC/LibrePGP combiner; those protocol choices belong to GnuPG.
        alg=key['algorithm'];data=bytes(self.data)
        if operation=='PKSIGN':
            if alg not in ('Ed25519','ML-DSA-65') or len(data) not in (32,48,64):raise ValueError('Unsupported signing request')
        else:
            if (alg,len(data)) not in [('X25519',32),('ML-KEM-768',1088)]:raise ValueError('Invalid KEM input')
        password=self.password()
        request=bytearray()
        try:
            request.extend(alg.encode()+b'\n'+key['spki'].encode()+b'\n'+base64.b64encode(data)+b'\n');request.extend(password);request.extend(b'\n')
            # No shell, inherited crypto overrides or secrets in arguments.
            env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','TMPDIR','SystemRoot')}
            # The fresh outer process group owns cleanup for every nested
            # helper. This is set here, never inherited from external input.
            env['PQMAIL_SUPERVISED_PROCESS_GROUP']='1'
            # Enforce caps while collecting both pipes, before a noisy helper
            # can allocate unbounded memory. Failure never triggers a retry.
            result=bounded_run(self.config['component_command'], request, env)
            reply=base64.b64decode(result.strip(),validate=True)
            expect={'Ed25519':64,'ML-DSA-65':3309,'X25519':32,'ML-KEM-768':32}[alg]
            if len(reply)!=expect or (alg=='X25519' and not any(reply)):raise ValueError('Invalid component result')
            self.send(reply)
        finally:
            # Best-effort clearing covers these mutable buffers only. Python
            # and subprocess may have made immutable copies; this is not a
            # guarantee that all secret-bearing process memory is overwritten.
            password[:]=b'\0'*len(password);request[:]=b'\0'*len(request);self.data[:]=b'\0'*len(self.data);self.data.clear()
    def run(self):
        self.line(b'OK PQ Mail component bridge')
        while True:
            line=self.read()
            if not line:return
            try:
                words=line.decode('ascii').split();cmd=words[0];args=words[1:]

                if cmd=='BYE':self.line(b'OK');return
                if cmd in ('RESET','RESTART'):
                    self.data[:]=b'\0'*len(self.data);self.data.clear()
                elif cmd=='OPTION':
                    if not args or args[0].split('=')[0] not in ('event-signal','app'):raise ValueError('Unsupported option')
                elif cmd=='GETINFO' and args==['version']:self.send(b'1.0')
                elif cmd=='GETINFO' and args==['socket_name']:raise ValueError('Pipe-only bridge')
                elif cmd=='GETINFO' and args==['pid']:self.send(str(os.getpid()).encode())
                elif cmd=='SERIALNO':
                    for arg in args:
                        if arg.startswith('--demand=') and arg[9:]!=self.serial:raise ValueError('Wrong identity')
                    self.line(b'S SERIALNO '+self.serial.encode()+b' 0')
                elif cmd=='GETATTR' and args==['$DISPSERIALNO']:self.line(b'S $DISPSERIALNO '+self.serial.encode())
                elif cmd=='GETATTR' and args==['APPTYPE']:self.line(b'S APPTYPE PIV')
                # LEARN advertises verified restore metadata; it performs no
                # live card read. Device/slot/SPKI matching is repeated by the
                # private-operation backend before it uses a key.
                elif cmd=='LEARN':
                    self.line(b'S SERIALNO '+self.serial.encode()+b' 0');self.line(b'S APPTYPE PIV')
                    for k in self.keys.values():self.line(('S KEYPAIRINFO '+k['grip']+' '+k['reference']+' '+k['usage']).encode())
                elif cmd=='KEYINFO':
                    if args[0].startswith('--list'):
                        usage={'--list=sign':'s','--list=encr':'e','--list=auth':'a'}.get(args[0])
                        keys=[k for k in self.keys.values() if usage is None or usage in k['usage']]
                    else:keys=[self.key(args[0])]
                    for k in keys:self.line(('S KEYINFO '+k['grip']+' T '+self.serial+' '+k['reference']+' '+k['usage']).encode())
                elif cmd=='READKEY':
                    k=self.key(args[-1]);self.line(('S KEYPAIRINFO '+k['grip']+' '+k['reference']).encode());self.send(k['public'])
                elif cmd=='SETDATA':
                    append=args and args[0]=='--append';s=args[-1]
                    if not re.fullmatch('[0-9A-Fa-f]+',s) or len(s)%2:raise ValueError('Bad hex')
                    if not append:self.data.clear()
                    self.data.extend(bytes.fromhex(s))
                    if len(self.data)>MAX:raise ValueError('Input too large')
                elif cmd in ('PKSIGN','PKDECRYPT'):self.operate(self.key(args[-1]),cmd)
                else:raise ValueError('Unsupported command')
                self.line(b'OK')
            except (ValueError,IndexError,KeyError,subprocess.SubprocessError):
                self.data[:]=b'\0'*len(self.data);self.data.clear();self.line(b'ERR 67108924 Operation rejected')

def main():
    if len(sys.argv)<2:raise SystemExit('Usage: bridge.py CONFIG [--server]')
    # This file is a local execution policy: component_command and libgcrypt
    # are executable/library paths. The mode check rejects group/world writes;
    # it does not authenticate a downloaded manifest or validate its ancestry.
    path=Path(sys.argv[1]);st=path.stat()
    if st.st_mode&0o022:raise SystemExit('Configuration is writable by other users')
    config=json.loads(path.read_text());Bridge(config,sys.stdin.buffer,sys.stdout.buffer).run()
if __name__=='__main__':main()
