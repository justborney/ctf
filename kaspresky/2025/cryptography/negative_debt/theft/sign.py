import os
from hashlib import sha3_256

from sage.all import *

# Fix elliptic curve ---------------------------------------------------
# NIST P-256:
## base field Fp
## p = 2^256 − 2^224 + 2^192 + 2^96 − 1
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
Fp = GF(p)

## elliptic curve params and itself
A = -3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
E = EllipticCurve([Fp(A), Fp(B)])

## order oа ellipic curve
q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
E.set_order(q)
Fq = GF(q)
q_byte_len = ceil(log(q, 2).n() / 8)

## generation point
Px = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Py = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P = E(Fp(Px), Fp(Py))
# ----------------------------------------------------------------------

# Fix hash function ----------------------------------------------------
# SHA3-256:
h = sha3_256
# ----------------------------------------------------------------------


def key_gen():
    d = randrange(1, q)
    Q = d * P

    return Fq(d), Q


def sign1_sign(d, m, id):
    e = h(m).digest()
    e = int.from_bytes(e, "little")
    e = Fq(e)

    d_id = d + id

    k = randrange(1, q)
    R = k * P
    r = R._coords[0]

    k = Fq(k)
    r = Fq(r)

    c = r + e

    if c == Fq(0):
        return None

    s = (k - c * d_id) / (d_id + 1)
    if s == Fq(0):
        return None

    signature = (c, s)
    return signature


def sign1_verify(Q, signature, m, id):
    Q_id = Q + int(id) * P

    c, s = signature
    if c == Fq(0) or s == Fq(0):
        return False

    e = h(m).digest()
    e = int.from_bytes(e, "little")
    e = Fq(e)

    R = int(s) * P + int(c + s) * Q_id
    Rx = R._coords[0]
    if Fq(Rx) != c - e:
        return False

    return True


def sign2_sign(d, m, id):
    Q = int(d) * P
    Qx, Qy = Q._coords[0], Q._coords[1]
    Qx_bytes = int(Qx).to_bytes(q_byte_len, "little")
    Qy_bytes = int(Qy).to_bytes(q_byte_len, "little")

    e = h(Qx_bytes + Qy_bytes + m).digest()
    e = int.from_bytes(e, "little")
    e = Fq(e)

    d_id = d + id

    k = randrange(1, q)
    R = k * P
    r = R._coords[0]

    k = Fq(k)
    r = Fq(r)

    c = r + e

    if c == Fq(0):
        return None

    s = (k - c * d_id) / (d_id + 1)
    if s == Fq(0):
        return None

    signature = (c, s)
    return signature


def sign2_verify(Q, signature, m, id):
    c, s = signature
    if c == Fq(0) or s == Fq(0):
        return False

    Qx, Qy = Q._coords[0], Q._coords[1]
    Qx_bytes = int(Qx).to_bytes(q_byte_len, "little")
    Qy_bytes = int(Qy).to_bytes(q_byte_len, "little")

    e = h(Qx_bytes + Qy_bytes + m).digest()
    e = int.from_bytes(e, "little")
    e = Fq(e)

    Q_id = Q + int(id) * P

    R = int(s) * P + int(c + s) * Q_id
    Rx = R._coords[0]
    if Fq(Rx) != c - e:
        return False

    return True


if __name__ == "__main__":
    id = Fq.random_element()
    print(f"id = {hex(int(id))}")
    m = b"Internal transfer: 500.00$ to customer number #971275923"
    d, Q = key_gen()

    signature = sign1_sign(d, m, id)
    print(f"c = 0x{int(signature[0]):064x}")
    print(f"s = 0x{int(signature[1]):064x}")

    assert sign1_verify(Q, signature, m, id)

    m2 = b"External transfer: 100,000.00$ to H$ck3r 1337 00 03 747 1481273"

    c2 = Fq(int(input("Enter c2 (hex): "), 16))
    s2 = Fq(int(input("Enter s2 (hex): "), 16))
    some_signature_we_dont_know = (c2, s2)
    flag = os.getenv("FLAG")
    assert flag.startswith("kaspersky{") and flag.endswith("}")
    id2 = int.from_bytes(flag.encode(), "little")

    assert sign2_verify(Q, some_signature_we_dont_know, m2, id2)
