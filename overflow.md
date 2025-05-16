# Buffer Overflow Attack Lab (Set-UID Version)

_Moses Ng (mshn2)_

## Task 1: Getting Familiar with Shellcode

Both `a32.out` and `a64.out` open a shell under the current user when run, as can be verified with the `id` command.

## Task 2: Understanding the Vulnerable Program

done :)

## Task 3: Launching Attack on 32-bit Program (Level 1)

Output of `gdb`:

```
20	    strcpy(buffer, str);       
gdb-peda$ p $ebp
$1 = (void *) 0xffffca38
gdb-peda$ p &buffer
$2 = (char (*)[100]) 0xffffc9cc
```

The return address is located 4 bytes above the previous frame pointer (which `ebp` points to) so it is at address `0xffffca3c`. This means that it is located `0x70` bytes above the start of the buffer, and this is the offset at which we should place our crafted return address in the badfile.

As mentioned in the lab notes, the frame pointer value will be larger by some amount when running without using `gdb`. We use a NOP sled to work around this; we place our shellcode at a high offset in the badfile (for example `0x170`), with a NOP sled below it, and set our crafted return address to point directly to the shellcode based on the addresses from `gdb` (in this case `0xffffcb3c`). Then, when running the program without using `gdb`, the buffer will be located at a higher address in the stack, and `0xffffcb3c` will instead point somewhere into the NOP sled below the shellcode.

The last thing to change in `exploit.py` is the shellcode itself; we take the 32-bit shellcode from `shellcode/call_shellcode.c`.

Upon running `stack-L1`, we are presented with a shell prompt, and we can verify with the `id` command that it is indeed running with `euid=0(root)`.

## Task 4: Launching Attack without Knowing Buffer Size (Level 2)

The buffer size can be anywhere from 100 (`0x64`) to 200 (`0xc8`) bytes inclusive; the return address will be located somewhere above the top of the buffer, so to be safe, we can spray the crafted return address in the badfile from offset `0x64` to offset `0xe0`. This requires a small modification of `exploit.py`:

```py
ret_start = 0x64
ret_end = 0xe0
L = 4     # Use 4 for 32-bit address and 8 for 64-bit address

for offset in range(ret_start, ret_end, L):
  content[offset:offset + L] = (ret).to_bytes(L,byteorder='little')
```

Next, we have to decide on the value of the crafted return address and the offset of the shellcode in the badfile. To be safe, we can put the shellcode near the end of the file, at offset `0x1e0`. Then the return address should be calculated assuming the largest possible buffer size; we can alternatively assume that the return address in the badfile with the highest offset was hit, in this case `0xdc`. In this case, the previous frame pointer would be located `0xd8` above the start of the buffer; we once again use `gdb` to get its location:

```
gdb-peda$ p $ebp
$1 = (void *) 0xffffca38
```

Under the assumptions above, the start of the buffer would be at address `0xffffca38` - `0xd8` = `0xffffc960`, and the shellcode would be at address `0xffffc960` + `0x1e0` = `0xffffcb40`, which is what we use for our crafted return address.

We can safely assume the largest possible buffer size in our calculations, because both a smaller buffer size and the reduced stack size from running without `gdb` would result in a higher start address for the buffer, and thus the crafted return address would point into the NOP sled (which we have made as large as we can within the badfile) below the shellcode.

Upon running `stack-L2`, we are presented with a shell prompt, and we can verify with the `id` command that it is indeed running with `euid=0(root)`. Since we can in fact control the size of the buffer, we can set it to the minimum and maximum values in the given range, and verify that the exploit works in both of those cases too.

## Task 5: Launching Attack on 64-bit Program (Level 3)

We use `gdb` to find the offset of the frame pointer from the base of the buffer:

```
20	    strcpy(buffer, str);       
gdb-peda$ p $rbp
$1 = (void *) 0x7fffffffd870
gdb-peda$ p &buffer
$2 = (char (*)[200]) 0x7fffffffd7a0
```

We can see that it is located at offset `0xd0`; the saved return address is located 8 bytes above this at offset `0xd8`, which is where we put the crafted return address in the badfile.

Because `strcpy()` will not copy anything past the crafted return address, the shellcode must go before it in the badfile. We want to have sufficient room before the shellcode for the NOP sled, and sufficient room after the shellcode so that it does not overwrite itself when pushing the arguments for `execve()` onto the stack; we will put it at offset `0x80` in the badfile.

The crafted return address should point directly at the shellcode, so that a reduced stack size without `gdb` results in jumping into the NOP sled below the shellcode. Hence, the crafted return address will be `&buffer + 0x80 = 0x7fffffffd820`.

Finally, we must remember to use the 64-bit shellcode instead of the 32-bit one, and to write 8 bytes of the crafted return address to the badfile. Upon running `stack-L3`, we once again successfully obtain a root shell.

## Task 6: Launching Attack on 64-bit Program (Level 4)

Since we can no longer fit the shellcode in the buffer before the crafted return address, we try instead to jump to a copy of the shellcode in the `str[]` array in `main()`, which holds the entire badfile instead of stopping at a null terminator.

Using `gdb` to find all the relevant addresses (note that since `str` is passed to `bof` as a pointer, we want to print out the value of this pointer):

```
20	    strcpy(buffer, str);       
gdb-peda$ p $rbp
$1 = (void *) 0x7fffffffd870
gdb-peda$ p &buffer
$2 = (char (*)[10]) 0x7fffffffd866
gdb-peda$ p str
$3 = 0x7fffffffdca0 "hello\n\377\377"
```

The frame pointer is at offset `0x0a` in the buffer, and thus the saved return address is at offset `0x12`. After, this, we can put a NOP sled followed by our shellcode, say at offset `0x80`. Finally, the crafted return address should point at the shellcode in the `str[]` array, which is at address `str + 0x80 = 0x7fffffffdd20`.

We thus construct the badfile, and upon running `stack-L4`, we are successful in obtaining a root shell.

## Task 7: Defeating `dash`'s Countermeasure

...