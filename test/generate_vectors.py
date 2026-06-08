#!/usr/bin/env python3
"""
CSAP DKSAP test-vector generator (dependency-free, offline).

Independent reference implementation — pure-Python secp256k1 + Keccak-256 + HKDF-SHA256,
deliberately NOT using @noble (TypeScript path) or k256 (Rust scanner) so that agreement
across the three is meaningful rather than circular.

Produces `test_vectors.json` next to this file. The values are the normative outputs that
the Rust scanner (`opaquecash/*/scanner`), the TypeScript SDK (`@opaquecash/opaque`), and
this script MUST all agree on. See spec/CSAP.md §2.2-§2.8.

Run:  python3 generate_vectors.py
"""

import hashlib
import hmac
import json
import os

# --- secp256k1 -------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def inv(x, m):
    return pow(x % m, m - 2, m)


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        m = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        m = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k, p):
    k %= N
    result = None
    addend = p
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def compress(pt):
    x, y = pt
    return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")


def uncompressed(pt):
    x, y = pt
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# --- Keccak-256 (Ethereum padding 0x01) ------------------------------------
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_MASK = (1 << 64) - 1


def _rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK


def _keccak_f(state):
    lanes = [[int.from_bytes(state[8 * (x + 5 * y):8 * (x + 5 * y) + 8], "little")
              for y in range(5)] for x in range(5)]
    for rnd in range(24):
        C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x][y] ^= D[x]
        x, y = 1, 0
        current = lanes[x][y]
        for t in range(24):
            x, y = y, (2 * x + 3 * y) % 5
            current, lanes[x][y] = lanes[x][y], _rol(current, ((t + 1) * (t + 2) // 2) % 64)
        for y in range(5):
            T = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5])
        lanes[0][0] ^= _RC[rnd]
    out = bytearray(200)
    for x in range(5):
        for y in range(5):
            out[8 * (x + 5 * y):8 * (x + 5 * y) + 8] = (lanes[x][y] & _MASK).to_bytes(8, "little")
    return out


def keccak256(msg: bytes) -> bytes:
    rate = 136
    state = bytearray(200)
    msg = bytearray(msg)
    msg.append(0x01)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] |= 0x80
    for off in range(0, len(msg), rate):
        for i in range(rate):
            state[i] ^= msg[off + i]
        state = _keccak_f(state)
    return bytes(state[:32])


# --- HKDF-SHA256 (RFC 5869; matches @noble salt=undefined -> 32 zero bytes) -
def hkdf_sha256(ikm: bytes, info: bytes, length: int) -> bytes:
    salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 0
    while len(okm) < length:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


DOMAIN = b"opaque-cash-v1"


def h(b: bytes) -> str:
    return "0x" + b.hex()


def dksap_vector(desc, v_hex, s_hex, r_hex):
    v = int(v_hex, 16)
    s = int(s_hex, 16)
    r = int(r_hex, 16)
    for name, k in (("viewing", v), ("spending", s), ("ephemeral", r)):
        assert 1 <= k < N, f"{name} key out of range"
    V = scalar_mul(v, G)
    S = scalar_mul(s, G)
    R = scalar_mul(r, G)
    meta = compress(V) + compress(S)               # V ‖ S  (CSAP §2.1)
    shared_pt = scalar_mul(r, V)                    # r·V  (== p_view·R)
    sec = compress(shared_pt)
    s_h = keccak256(sec)
    s_h_int = int.from_bytes(s_h, "big")
    assert s_h_int < N, "s_h >= n: Rust scanner would reject; choose another vector"
    view_tag = s_h[0]
    P_stealth = point_add(S, scalar_mul(s_h_int, G))
    stealth_addr = keccak256(uncompressed(P_stealth)[1:])[12:32]
    one_time = (s + s_h_int) % N
    # self-consistency: one_time·G must equal P_stealth (sender point == recipient key)
    assert scalar_mul(one_time, G) == P_stealth, "round-trip mismatch"
    return {
        "description": desc,
        "scheme_id": 1,
        "viewing_private_key": h(bytes.fromhex(v_hex)),
        "spending_private_key": h(bytes.fromhex(s_hex)),
        "ephemeral_private_key": h(bytes.fromhex(r_hex)),
        "viewing_public_key": h(compress(V)),
        "spending_public_key": h(compress(S)),
        "meta_address": h(meta),
        "ephemeral_public_key": h(compress(R)),
        "shared_secret": h(sec),
        "s_h": h(s_h),
        "view_tag": view_tag,
        "stealth_address": h(stealth_addr),
        "one_time_private_key": h(one_time.to_bytes(32, "big")),
    }


def derivation_vector(desc, sig: bytes):
    okm = hkdf_sha256(sig, DOMAIN, 64)
    v, s = okm[:32], okm[32:64]
    assert 1 <= int.from_bytes(v, "big") < N
    assert 1 <= int.from_bytes(s, "big") < N
    V = scalar_mul(int.from_bytes(v, "big"), G)
    S = scalar_mul(int.from_bytes(s, "big"), G)
    return {
        "description": desc,
        "hkdf": {"hash": "SHA-256", "salt": "<empty -> 32 zero bytes>", "info": DOMAIN.decode(), "length": 64},
        "signature": h(sig),
        "viewing_private_key": h(v),
        "spending_private_key": h(s),
        "meta_address": h(compress(V) + compress(S)),
    }


def main():
    # Sanity-check the primitives against a known answer before trusting outputs.
    assert keccak256(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak256 broken"
    assert compress(G) == bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), "secp256k1 G broken"

    aa, bb, cc = "aa" * 32, "bb" * 32, "cc" * 32
    dd = "dd" * 32
    out = {
        "_comment": "CSAP DKSAP test vectors. Generated by generate_vectors.py "
                    "(independent pure-Python secp256k1/Keccak/HKDF). Must agree with the "
                    "Rust scanner and the @noble TypeScript SDK. See spec/CSAP.md §2.2-§2.8.",
        "curve": "secp256k1",
        "hkdf_domain": DOMAIN.decode(),
        "derivation": [
            derivation_vector("HKDF-SHA256 signature -> (viewing, spending); CSAP §2.2",
                              bytes(range(1, 66))),  # 65-byte deterministic signature
        ],
        "dksap": [
            dksap_vector("scheme-1 secp256k1 DKSAP round trip (matches Rust scanner test inputs)",
                         aa, bb, cc),
            dksap_vector("same recipient, different ephemeral key", aa, bb, dd),
            dksap_vector("different recipient and ephemeral key",
                         "11" * 32, "22" * 32, "33" * 32),
        ],
    }
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_vectors.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print("wrote", path)
    for vec in out["dksap"]:
        print(f"  view_tag={vec['view_tag']:3d}  stealth={vec['stealth_address']}  ({vec['description']})")
    print("  derivation meta:", out["derivation"][0]["meta_address"][:20] + "…")


if __name__ == "__main__":
    main()
