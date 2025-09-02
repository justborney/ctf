# Kaspersky{CTF} (https://lp.kaspersky.com/ctf/) - beta-test, 478 points by @tonysdx (https://t.me/tonysdx)

💡Idea:
We have an application where you can create storages with items inside. You can also edit the content inside items and delete them.
In storage we have an item counter, which when it reaches 0, frees the entire storage.
We also have feedback, which is allocated on the first call to the leave_feedback function. After it is allocated, we can only edit the content of its string, which is stored in a separate chunk on the heap.

👹 Vulnerability:
1. Use-after-free — when the storage is freed, its pointer remains in the storages_arr array.
2. Downcasting of the item description size — if we input a description of length 255, the program converts it to 0.
3. Off-by-one — if an item has a zero-length description, the program writes a zero byte just outside the buffer (size_of_buffer - 1). This is exactly where the storage index is stored in the item structure.
4. Uninitialized variable output — if we enter something incorrect in the menu, the program outputs an uninitialized variable from the stack.

💉 Exploitation:
1. Leak the stack address by entering an incorrect menu item — for example, something_wrong.
2. Create storage #0 sized like the feedback control chunk — 0x10 and an item with a description of the same size.
3. After creating the storage, if you enter an invalid menu item, you get a leak of the binary address.
4. Fill the 0x20 tcache bin by allocating 2 storages with storage description (size - 1 byte) and item description (size - 0x10 bytes). readstr2 will quickly fill the tcache because everything in the challenge uses calloc, which cannot reuse chunks from tcache and constantly takes new chunks.
5. Free item #0 — this will be the 7th chunk in the 0x20 tcache bin. Since the item counter in storage #0 becomes 0, it will also be freed, and its pointer will go to the fastbin.
6. Allocate the feedback structure — it should take the fastbin chunk for the control chunk, so now we have a pointer to it in storage_arr[0].
7. From this point, we can decrement the feedback pointer using the second and third vulnerabilities. Also, we get a read/write primitive at the address pointed to by the feedback control chunk. However, at this moment, we can only move backward, decreasing the pointer by one.
8. Start decrementing the pointer by allocating items with a description length of 255. After allocation, call update for these chunks, and since the item size is 0 (due to downcasting), a zero byte will be written before the buffer, specifically in the storage index field.
9. After deleting these updated zero-sized chunks, we decrement by one the first 8 bytes of the zero storage. This is the pointer to the string in the feedback's control chunk.
10. Our main goal is to decrement the feedback pointer so that it points to itself, allowing us to overwrite it to any other address.
11. At any moment, we can call the leave_feedback function, and it will output bytes from the current pointer, so along the way, we collect the mangled heap key.
12. To decode mangled addresses, we use my exploit function crack_mangle_addr.
13. Our task is to make it so that by updating an item, we can change the feedback string pointer. To do this, reaching the control chunk with our string pointer, we overwrite it with a pointer to the control chunk in the binary segment itself.
14. Allocate another storage of any size and 1 item smaller than 255. Calculate its address using the decoded heap address above and the offset from the segment start.
15. The item allocated in step 14 will be the chunk to control the feedback pointer. Overwrite the feedback control chunk address in the binary with our controlled chunk (don't forget to add the offset — the first 2 bytes of items are very hard to update). Now you can update the item from step 14, and it will overwrite the feedback string pointer. We got AR/AW!
16. Leak libc through the GOT-table, calculate the RSP address when returning from the AW exploit function, and place ROP on the stack.
17. cat flag.txt

