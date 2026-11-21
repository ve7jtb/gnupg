#!/usr/bin/env python3
"""Explicit wire-format profiles; compatibility never replaces the v6 default."""
import re

DEFAULT_PROFILE = 'v6'
PROFILES = {
    'v6': {'label': 'IETF v6 hybrid', 'signing': 'ML-DSA-65 + Ed25519',
           'encryption': 'ML-KEM-768 + X25519 (RFC 9980)', 'pq_signature': True},
    'v5': {'label': 'GnuPG v5 compatibility', 'signing': 'Ed25519 (classical)',
           'encryption': 'ML-KEM-768 + X25519 (LibrePGP)', 'pq_signature': False},
}


def choose_profile(value=None):
    """Reject unknown versions instead of silently falling back to classical."""
    value = DEFAULT_PROFILE if value is None else value
    if value not in PROFILES:
        raise ValueError('Unsupported profile')
    return value


def v5_parameters(email, signing_grip, x25519_grip, mlkem_grip):
    """Build certificate-only GnuPG batch input referencing existing keys.

    The dedicated classical signer (slot 88) is used in hardware deployments.
    The encryption subkey reuses the existing hybrid component pair 85/9d.
    Key-Grip/Subkey-Grip prevent this operation from generating any keys.
    """
    if not re.fullmatch(r'[A-Za-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+', email):
        raise ValueError('Expected a single email address without control characters')
    grips = (signing_grip, x25519_grip, mlkem_grip)
    if any(not re.fullmatch('[0-9A-F]{40}', g) for g in grips) or len(set(grips)) != 3:
        raise ValueError('Expected three distinct full component keygrips')
    # Both key packets are v5. The legacy EdDSA algorithm identifier is 22;
    # LibrePGP's composite encryption identifier is 8, not RFC 9980's 35.
    return ('Key-Type: 22\nKey-Curve: Ed25519\nKey-Version: 5\n'
            'Key-Grip: '+signing_grip+'\nKey-Usage: cert sign\n'
            'Subkey-Type: 8\nSubkey-Version: 5\n'
            'Subkey-Grip: '+x25519_grip+','+mlkem_grip+'\nSubkey-Usage: encrypt\n'
            'Name-Email: '+email+'\nExpire-Date: 1y\n%commit\n')
