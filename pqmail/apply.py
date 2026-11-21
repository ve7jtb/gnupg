#!/usr/bin/env python3
"""Preflight and apply the Level 3 adapter patch to a fresh release tree.

Every anchor is checked before any source file is replaced. Ordinary write or
rename failures roll back replaced files. Like other multi-file source edits,
this cannot be atomic across process termination or power loss; discard such
an interrupted staging tree rather than building it.
"""
from pathlib import Path
import os
import stat
import sys
import tempfile

# Card signing receives the OpenPGP digest unchanged. In particular, the
# ML-DSA component must not receive an RSA-style ASN.1 DigestInfo wrapper.
EDITS = (
    ('agent/pksign.c', 'if (algo == GCRY_PK_RSA)\n        {', '''if (algo == GCRY_PK_MLDSA)
        {
          if (len != 3309) err = gpg_error (GPG_ERR_INV_DATA);
          else err = gcry_sexp_build (&s_sig, NULL, "(sig-val(dilithium3(s%b)))", (int)len, buf);
        }
      else if (algo == GCRY_PK_RSA)
        {'''),
    ('agent/pksign.c', 'err = divert_pksign (ctrl,', 'err = divert_pksign (ctrl,'),
    ('agent/call-scd.c', 'if (!mdalgo)\n    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);',
     '/* SETDATA already supports bounded multi-line raw messages. */'),
    ('agent/pksign.c', 'ctrl->digest.algo,\n\t\t\t       &buf, &len);',
     '(algo == GCRY_PK_MLDSA || algo == GCRY_PK_EDDSA)? 0 : ctrl->digest.algo,\n\t\t\t       &buf, &len);'),
)


def prepare(root):
    """Build the complete update in memory; mismatched anchors write nothing."""
    original, updated = {}, {}
    for name, old, new in EDITS:
        path = root/name
        if path not in original:
            original[path] = path.read_bytes()
            updated[path] = original[path].decode('utf-8')
        # Exact counts reject ambiguous newer upstream sources and reapplication.
        # This is an explicit error rather than assert, so python -O is safe.
        if updated[path].count(old) != 1:
            raise ValueError('Expected exactly one patch anchor in '+name)
        updated[path] = updated[path].replace(old, new, 1)
    return original, {path: text.encode('utf-8') for path, text in updated.items()}


def stage(path, content):
    """Write and sync a same-directory replacement with the original mode."""
    fd, name = tempfile.mkstemp(prefix='.pqmail-patch-', dir=path.parent)
    staged = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        staged.chmod(stat.S_IMODE(path.stat().st_mode))
        return staged
    except BaseException:
        staged.unlink(missing_ok=True)
        raise


def apply(root):
    """Prepare all originals/replacements before making the first mutation."""
    original, updated = prepare(root)
    staged, backups, replaced = {}, {}, []
    try:
        for path in updated:
            backups[path] = stage(path, original[path])
            staged[path] = stage(path, updated[path])
        # Avoid overwriting concurrent edits made since preflight. Callers must
        # still use an isolated source tree: this is not a general file lock.
        if any(path.read_bytes() != data for path, data in original.items()):
            raise RuntimeError('Source changed after preflight; no patch applied')
        try:
            for path, replacement in staged.items():
                os.replace(replacement, path)
                replaced.append(path)
        except BaseException:
            # Roll back every successful replacement before surfacing the
            # original failure. If rollback itself fails, retain its backups.
            rollback_failed = False
            for path in reversed(replaced):
                try:
                    os.replace(backups[path], path)
                except OSError:
                    rollback_failed = True
            if rollback_failed:
                backups.clear()  # Leave recovery files on disk intentionally.
                raise RuntimeError('Rollback incomplete; discard staging tree or recover .pqmail-patch backups')
            raise
    finally:
        for temporary in [*staged.values(), *backups.values()]:
            temporary.unlink(missing_ok=True)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('Usage: apply.py CLEAN_RELEASE_SOURCE')
    apply(Path(sys.argv[1]).resolve())


if __name__ == '__main__':
    main()
