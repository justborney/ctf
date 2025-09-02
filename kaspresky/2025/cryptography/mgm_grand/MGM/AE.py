import os

import AES
from sage.all import *

K2 = GF(2)["x"]
local_vars = {"x": K2.gen()}
modulus_pol = sage_eval("x^128 + x^7+ x^2 + x + 1", locals=local_vars)
assert modulus_pol.is_irreducible()
F2_128 = GF(2).extension(modulus_pol, name="x")


def pad_data(data):
    r = len(data) % AES.BLOCK_LEN
    padding = b"\x00" * (AES.BLOCK_LEN - r) if r else b""
    return data + padding


def incr_r(block):
    assert len(block) % 2 == 0

    half_block_len = len(block) // 2
    L, R = block[:half_block_len], block[half_block_len:]
    R_int = int.from_bytes(R, "big")
    R_int += 1
    R_int &= (1 << (8 * half_block_len)) - 1
    R = R_int.to_bytes(half_block_len, "big")

    return L + R


def incr_l(block):
    assert len(block) % 2 == 0

    half_block_len = len(block) // 2
    L, R = block[:half_block_len], block[half_block_len:]
    L_int = int.from_bytes(L, "big")
    L_int += 1
    L_int &= (1 << (8 * half_block_len)) - 1
    L = L_int.to_bytes(half_block_len, "big")

    return L + R


def make_gamma(key, nonce, q):
    Y_ = AES.encrypt(nonce, key)
    Y = Y_
    for _ in range(q - 1):
        Y_ = incr_r(Y_)
        Y += Y_

    return AES.encrypt(Y, key)


def make_mults(key, nonce, q):
    Z_ = AES.encrypt(nonce, key)
    Z = Z_
    for _ in range(q - 1):
        Z_ = incr_l(Z_)
        Z += Z_

    return AES.encrypt(Z, key)


def xor(b1: bytes, b2: bytes):
    return bytes(x ^ y for x, y in zip(list(b1), list(b2)))


def bytes_to_field_elems(data):
    assert len(data) % AES.BLOCK_LEN == 0

    res = []
    for i in range(0, len(data), AES.BLOCK_LEN):
        elem = data[i : i + AES.BLOCK_LEN]
        elem = int.from_bytes(elem, "big")
        res.append(F2_128.from_integer(elem))

    return res


def make_tag(cipher_text, mults, key):
    padded_cipher_text = pad_data(cipher_text)

    C = bytes_to_field_elems(padded_cipher_text)
    H = bytes_to_field_elems(mults)
    assert len(C) == len(H)

    tag = 0
    for c, h in zip(C, H):
        tag += c * h

    tag = tag.to_integer().to_bytes(AES.BLOCK_LEN, "big")
    tag = AES.encrypt(tag, key)

    return tag


def encrypt(plain_text, key, nonce):
    q = ceil(len(plain_text) / AES.BLOCK_LEN)

    gamma = make_gamma(key, nonce, q)
    cipher_text = xor(plain_text, gamma)

    mults = make_mults(key, nonce, q)
    tag = make_tag(cipher_text, mults, key)

    return cipher_text, tag


def decrypt(cipher_text, tag, key, nonce):
    q = ceil(len(cipher_text) / AES.BLOCK_LEN)

    mults = make_mults(key, nonce, q)
    tag_ = make_tag(cipher_text, mults, key)

    gamma = make_gamma(key, nonce, q)

    plain_text = xor(cipher_text, gamma) if tag_ == tag else None

    return plain_text


if __name__ == "__main__":
    key = bytes(randint(0, 255) for _ in range(AES.BLOCK_LEN))

    winner_id = bytes.fromhex("7B000F6DCE23C1F9842F219E35F9E388")
    plain_text = b"CTF2024 winner: " + winner_id

    nonce = bytes(randint(0, 255) for _ in range(AES.BLOCK_LEN))
    cipher_text, tag_2024 = encrypt(plain_text, key, nonce)
    plain_text_ = decrypt(cipher_text, tag_2024, key, nonce)
    assert plain_text == plain_text_

    print(f'ciphertext^24 = "{cipher_text.hex().upper()}"')
    print(f'tag^24 = "{tag_2024.hex().upper()}"')
    print(f'nonce^24 = "{nonce.hex().upper()}"')

    # ==================================================

    plain_text = bytes.fromhex("3E11257338119254228180CFA70F5EFB930AC3D57EEBC599BB2BA4BF4778C325")
    nonce = bytes(randint(0, 255) for _ in range(AES.BLOCK_LEN))
    cipher_text, tag = encrypt(plain_text, key, nonce)
    plain_text_ = decrypt(cipher_text, tag, key, nonce)
    assert plain_text == plain_text_

    print(f'ciphertext\' = "{cipher_text.hex().upper()}"')
    print(f'tag\' = "{tag.hex().upper()}"')
    print(f'nonce\' = "{nonce.hex().upper()}"')

    # ==================================================

    winner_id_2025 = b"..."  # 16 bytes
    plain_text = b"CTF2025 winner: " + winner_id_2025

    nonce = input().encode()
    assert len(nonce) == AES.BLOCK_LEN

    flag = (nonce + winner_id_2025).decode()
    assert flag == os.getenv("FLAG")

    cipher_text, tag_2025 = encrypt(plain_text, key, nonce)
    assert tag_2025 == tag_2024
    plain_text_ = decrypt(cipher_text, tag_2024, key, nonce)
    assert plain_text == plain_text_
