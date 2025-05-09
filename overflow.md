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

As mentioned in the lab notes, the frame pointer value will be larger by some amount when running without using `gdb`. We use a NOP sled to work around this; we place our payload at a high offset in the badfile (for example `0x170`), with a NOP sled below it, and set our crafted return address to point directly to the payload based on the addresses from `gdb` (in this case `0xffffcb3c`). Then, when running the program without using `gdb`, the buffer will be located at a higher address in the stack, and `0xffffcb3c` will instead point somewhere into the NOP sled below the payload.

The last thing to change in `exploit.py` is the shellcode; we take the 32-bit shellcode from `shellcode/call_shellcode.c`.

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

Next, we have to decide on the value of the crafted return address and the offset of the payload in the badfile. To be safe, we can put the payload near the end of the file, at offset `0x1e0`. Then the return address should be calculated assuming the largest possible buffer size; we can alternatively assume that the return address in the badfile with the highest offset was hit, in this case `0xdc`. In this case, the previous frame pointer would be located `0xd8` above the start of the buffer; we once again use `gdb` to get its location:

```
gdb-peda$ p $ebp
$1 = (void *) 0xffffca38
```

Under the assumptions above, the start of the buffer would be at address `0xffffca38` - `0xd8` = `0xffffc960`, and the payload would be at address `0xffffc960` + `0x1e0` = `0xffffcb40`, which is what we use for our crafted return address.

We can safely assume the largest possible buffer size in our calculations, because both a smaller buffer size and the reduced stack size from running without `gdb` would result in a higher start address for the buffer, and thus the crafted return address would point into the NOP sled (which we have made as large as we can within the badfile) below the payload.

Upon running `stack-L2`, we are presented with a shell prompt, and we can verify with the `id` command that it is indeed running with `euid=0(root)`. Since we can in fact control the size of the buffer, we can set it to the minimum and maximum values in the given range, and verify that the exploit works in both of those cases too.