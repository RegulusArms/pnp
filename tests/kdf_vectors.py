#!/usr/bin/env python3
"""Prints the expected values in tests/test_kdf.c, computed with implementations independent of pnp's C code:
Python's hashlib (BLAKE2b), argon2-cffi (Argon2id: the reference C library) and cryptography (ChaCha20: OpenSSL).
Balloon has no common library, so it's written out here from the paper (Algorithm 1), separately from src/kdf.c.
Not run by `make test` (the CI containers have no Python): run it by hand after changing a vector, and paste.

    pip install argon2-cffi cryptography; python3 tests/kdf_vectors.py
"""
import hashlib

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def msg(n):  # the test message of n bytes: i*7+3
    return bytes((i * 7 + 3) & 255 for i in range(n))


def balloon(pw, salt, s, t):
    cnt = 0

    def h(*parts):
        nonlocal cnt
        x = hashlib.blake2b(cnt.to_bytes(8, "little"), digest_size=64)
        for p in parts:
            x.update(p)
        cnt += 1
        return x.digest()

    buf = [h(pw, salt)]
    for m in range(1, s):
        buf.append(h(buf[m - 1]))
    for r in range(t):
        for m in range(s):
            buf[m] = h(buf[(m - 1) % s], buf[m])
            for i in range(3):
                idx = h(salt, r.to_bytes(8, "little") + m.to_bytes(8, "little") + i.to_bytes(8, "little"))
                buf[m] = h(buf[m], buf[int.from_bytes(idx, "little") % s])
    return buf[s - 1]


def chacha(key, nonce, n):  # the library takes the 32-bit block counter (0) before the 12-byte nonce
    return Cipher(algorithms.ChaCha20(key, bytes(4) + nonce), None).encryptor().update(bytes(n))


print("/* BLAKE2b: {message length, output length, digest of msg(n)} */")
for n, ol in [(0, 64), (3, 64), (127, 32), (128, 64), (129, 1), (1000, 48)]:
    print(f'    {{{n}, {ol}, "{hashlib.blake2b(msg(n), digest_size=ol).hexdigest()}"}},')

print("/* Argon2id: {m KiB, passes, lanes, output length, tag of password \"password\", salt \"somesalt\"} */")
for m, t, p, ol in [(8, 1, 1, 4), (64, 2, 2, 64), (100, 3, 4, 65), (4096, 2, 3, 128), (65536, 2, 8, 32)]:
    tag = hash_secret_raw(b"password", b"somesalt", t, m, p, ol, Type.ID).hex()
    print(f'    {{{m}, {t}, {p}, {ol}, "{tag}"}},')

print("/* Balloon: {s_cost, t_cost, output for passphrase \"hunter2\", salt 0x00..0x0f} */")
for s, t in [(2, 1), (16, 3), (1000, 2)]:
    print(f'    {{{s}, {t}, "{balloon(b"hunter2", bytes(range(16)), s, t).hex()}"}},')

print("/* ChaCha20: key 0x00..0x1f, nonce 000000000000004a00000000: the first 200 keystream bytes */")
ks = chacha(bytes(range(32)), bytes(7) + bytes([0x4A]) + bytes(4), 200)
print(f'    "{ks.hex()}"')

# --protect's whole derivation (src/protect.c), passphrase "correct horse", salt 0x10..0x1f, 8 MiB, 4 lanes
salt = bytes(range(16, 32))
b = balloon(b"correct horse", salt, 8 * 256, 2)
a = hash_secret_raw(b, salt, 2, 8 * 1024, 4, 64, Type.ID)
print("/* --protect, 8 MiB, 4 lanes: wrapping key, check value, then share 3's first 64 keystream bytes */")
print(f'    "{a[:32].hex()}", "{a[32:48].hex()}",')
print(f'    "{chacha(a[:32], (3).to_bytes(4, "little") + bytes(8), 64).hex()}"')
