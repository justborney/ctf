from string import printable
import random

def tob(c: int):
    return c.to_bytes(1, "little")

def xortext(a, b):
    c = b""
    for ac, bc in zip(a, b):
        c += tob(ac ^ bc)
    return c

def divide_into_blocks(txt, blk_len=2):
    blocks = []
    i = 0
    while i < len(txt):
        blocks.append(txt[i:i+blk_len])
        i += blk_len
    return blocks

def pkcs7(text, blksize=16):
    ln = blksize - len(text)%blksize
    text += tob(ln)*ln
    return text

def pkcs7_unpad(text):
    padlen = text[-1]
    return text[:-padlen]

def CBC_enc(text, iv, key, encrypt_func):
    text = pkcs7(text)
    blks = divide_into_blocks(text, 16)
    cip = b''
    for blk in blks:
        bl = xortext(blk, iv)
        new_cip = encrypt_func(bl, key)
        iv = new_cip
        cip += new_cip
    return cip
    
def CBC_dec(cip, iv, key, decrypt_func):
    assert len(cip) % 16 == 0
    blks = divide_into_blocks(cip, 16)
    plain = b""
    for blk in blks:
        pl_pre = decrypt_func(blk, key)
        plain += xortext(pl_pre, iv)
        iv = blk
    return pkcs7_unpad(plain)
    
def randstr(ln=10):
    return b''.join([random.choice(printable).encode() for _ in range(ln)])


def encrypt_block(v, k):
    return b''.join([
        encrypt(a, b)
        for a, b 
        in zip(divide_into_blocks(v), divide_into_blocks(k))
    ])

def decrypt_block(v, k):
    return b''.join([
        decrypt(a, b)
        for a, b 
        in zip(divide_into_blocks(v), divide_into_blocks(k))
    ])


rounds = 32
def encrypt(v, k):
    v0, v1 = v[0], v[1]
    sum_val = 0
    delta = 0x9E3779B9
    
    for _ in range(rounds):
        sum_val = (sum_val + delta) & 0xFFFFFFFF
        
        term1 = (((v1 << 4) + k[0]) ^ (v1 + sum_val) ^ ((v1 >> 5) + k[1]))
        v0 = (v0 + term1) & 0xFF

        term2 = (((v0 << 4) ) ^ (v0 + sum_val) ^ ((v0 >> 5) ))
        v1 = (v1 + term2) & 0xFF
        
    return tob(v0)+tob(v1)


def decrypt(v, k):
    v0, v1 = v[0], v[1]
    delta = 0x9E3779B9
    sum_val = (delta * rounds) & 0xFFFFFFFF
    
    for _ in range(rounds):
        term2 = (((v0 << 4) ) ^ (v0 + sum_val) ^ ((v0 >> 5)))
        v1 = (v1 - term2) & 0xFF
        
        term1 = (((v1 << 4) + k[0]) ^ (v1 + sum_val) ^ ((v1 >> 5) + k[1]))
        v0 = (v0 - term1) & 0xFF
        sum_val = (sum_val - delta) & 0xFF
        
    return tob(v0)+tob(v1)



text4 = b"""
...

kaspersky{...}
""".strip()


key, iv = randstr(16), randstr(16)

c = CBC_enc(text4, iv, key, encrypt_block)

assert CBC_dec(c, iv, key, decrypt_block) == text4
len(c)

from base64 import b64encode

print(f"{b64encode(c)}")

# Output b'zTR8J8VwcgXuaa3x5G3NMl1RWgOnYkQV4ss7UJMo4DY7xkIGJPrDge2bOTn4xmTwnGteusGaMWOLP2CqeyK4FlPHIYg4OIOG1eNJ4pIn1Kuq6E8CbHa3x+jB6I5hr4R+gkbMBISbYjsdcuMKjzcVCODVSqW1A7e1b7EA0Y+S4HUSFNK95IKkaz6h4nghVYA2pMQjfGI87/CbCIYoiiYj8azwlriJ4pGA0jF830u57fTX6VT5iCtP5lul4GdOI/pak5JYYdJqTwPIJaPS6llW/uvLM7/7G7ESULUbHI3xZU8BiBkG8lH6mfFCUr4GDE9OQsG/LkKQO2hXftRsZOTutxcrCf1BvpLR/xCg/te+V2dJOXHqXpspqsa5i6zainKplJpahFyeKKdumjK0WwZ8d8HIQRRlCFmGuJ8GKkPTaz6KGKjFJfJTRUSNZ3Djp3qVCA65E/uwKA6fAwMad+YV2yUSJTPNzx8L8zQ7Y+4/v75srBwJPyxggigGWElEo5DuDeq2QP9WDejFAQYsV/lx//mLiUCrUYjYfVhqkewi77EUmO1b91Qy5FMEx5vG/U2eIGVuI4CKSZNyj4D+FVenu0rAvk30v1My/FiIw6ADqX+T5klDk6iVeOjhgMwwIQ+5EarrDYa1yAQwSu5xhVdMi+dQdn1gDGawsPC3aOviUK59PDnRKI7LTJjCQnQ0wZhTGhYfIHjbUTqcnW/TL0kG3nIij1fFRXAOLu1OgLXTOLdCnVfDjFzukN8xRffK9s/QYJv9ZHi22o7WrWNxI1lZ/L2jr3EyXTVrkNPI1fTia2uDks3EW3TocsHur3S4UmXbvBQ0ELni8S4P3qPSazzeKTQXRGyBN1OnFhs2EQqokYhh4blW/BgfglUwDsSxBeUVoC5X4kE+WRG4nKMBESynddfBLevpzimBP0i+PlyrjyR1Tezfv8pP4caxV0hIYkwU0gH3DEzoMfZJKHW9fYm1EzIsXodQlTe40ViH90AZ4X6F66TQjIR1os/WoLJ1i3yGKSrmuI/knYXvLq6uMMwJzBtr7H+SLnqq2hnE7kpu7TO0jGPf+kvaj3D/MZ5uDblmZGyN7n7r/GLXH+uoIh/GcAlTb2O6+uYoRMEsdICiEBVRc/L2p+4ZUWu1ITOkxRphChGAnRYXo0Re8Fub6an1ELCsgGvzJ1fpNcn03++qpT2qFPmsy8//SMu6HIxAn3KIDanIPTHEO04bQIBNIkGFJoW2WMhxUR4B1YK2WAvml07mFC+gES8tC3v98Ol9geZ1tLZepkcQMLCDjE6jSPYnxNTFqKHpzHyvAqJ60vDJMFl3F++l5vo6uHsMm1Pt6l79ephTNVoXDPlJP+voZl4bj2nI8meuFGChahwoV3uzaOxuIwqwYeLZUJpxyEej2ADef6nU+dRDCL25rNIIZHuhyMA9xl7ZHJXmROgrLojjX4M79uW0q2xhvg6C5I/xNQwOj/mCstdU/M5IxlkI8BGXo6oDdL++m8xaXjVeHM9u6X/OgPcs+O7qYmsnvMztHyMN6z/JajpRO9iN3PN614Pu/mJcFtdv8qHYHc41raJ93Ba6zTi4eE8cRy1S7KzBx1FL3R6T8KYL+AmtWXhzZn127949InlRcW+JMauPpXSCNUMu1+X9KAuCXLvojxmIgJuQXxRJ2ZrHE5mxjfSsT+4yaQ=='
