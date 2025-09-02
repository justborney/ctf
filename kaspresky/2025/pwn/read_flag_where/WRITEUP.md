# Kaspersky{CTF} (https://lp.kaspersky.com/ctf/) - flag-what-where, 50 points by @tonysdx (https://t.me/tonysdx)

💡 Idea:
The binary reads the flag onto the stack via the fgets function, then erases it using memset.  
After that, we have 3 attempts to read arbitrary bytes of memory at a given address, after which the program terminates.  

👹 Vulnerability:
The fgets function, like many other functions from glibc, uses buffers on the heap when reading a string from stdin.  
Therefore, part of the flag can be found in heap memory.  

Why only part, and not the whole flag?  
Because fgets frees the buffer after finishing, and the first N bytes are overwritten with service data.  

Also, the binary is compiled without PIE, so calculating the necessary offsets is not difficult.  

💉 Exploitation:
1. Put cyclic(128) into the file flag.txt, patch the binary to use the same libraries as in the docker container, and run it in gdb.  
2. Use the command search -t bytes "aaaa".  
3. Find the heap area where part of the flag lies and calculate the offset from the start of the heap segment.  
4. Get libc leak via the GOT-table, heap leak from main_arena, and read data at the offset calculated in step 3.  

📝 Notes:
At first, I thought I would have to look for the first part of the flag, which is erased, somewhere else. But the organizers anticipated this: the entire flag was available in the heap.  
I just subtracted 16 from the initially calculated offset and got the full flag.

