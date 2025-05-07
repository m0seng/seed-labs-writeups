# Environment Variable and `Set-UID` Program Lab

_Moses Ng (mshn2)_

## Task 1: Manipulating Environment Variables

done :)

## Task 2: Passing Environment Variables from Parent Process to Child Process

The parent and child processes have the same set of environment variables; `diff` returns no differences.

## Task 3: Environment Variables and `execve()`

The new program gets its environment variables exclusively from the `envp` argument passed to `execve()`; if we pass `NULL` then it has no pre-defined environment variables.

## Task 4: Environment Variables and `system()`

`system()` does indeed pass the environment variables of the calling process to the new program.

## Task 5: Environment Variable and `Set-UID` Programs

The `PATH` environment variable and my custom defined one get into the `Set-UID` child process, however the `LD_LIBRARY_PATH` environment variable does not. It is quite surprising that particular environment variables are filtered out from the `Set-UID` child process.

## Task 6: The PATH Environment Variable and Set-UID Programs

By placing a fake `ls` program into `/home/seed`, for example `/bin/sh`, I can get the `Set-UID` program to run it and thus give me a shell; however, it is not running with root privileges, as the `id` command within this shell still shows the `seed` user with no change to the effective user ID.

Doing this again but with `zsh` instead, which does not have a countermeasure in place for being executed in a `Set-UID` process, we see that the output of `id` now includes `euid=0(root)`.

## Task 7: The `LD_PRELOAD` Environment Variable and `Set-UID` Programs

+ Regular program, normal user: overridden
+ `Set-UID` root program, normal user: sleeps
+ `Set-UID` root program, `LD_PRELOAD` exported in root account: overridden
+ `Set-UID` user program, `LD_PRELOAD` in another user's account: sleeps

Here is a test program I wrote to show the value of `LD_PRELOAD` if it is present:

```c
#include <stdio.h>
#include <string.h>

extern char **environ;

int main()
{
  int i = 0;
  while (environ[i] != NULL) {
    if (strncmp(environ[i], "LD_PRELOAD", 10) == 0)
    {
      printf("%s\n", environ[i]);
    }
    i++;
  }
}
```

Building this program and running it under the same circumstances as above, I found that in the cases where `myprog` slept, `LD_PRELOAD` was absent, and in the cases where `sleep()` was overridden, `LD_PRELOAD` was present. It seems that the `LD_*` variables are dropped from the environment when a `Set-UID` program is run by a user other than its owner.

## Task 8: Invoking External Programs Using `system()` versus `execve()`

In the version of `catall` which uses `system()`, the argument to `catall` is completely unsanitised and simply appended as a string to `"/bin/cat "`. This means that, for example, Bob can use the `;` command separator followed by any command that he wishes to run as root (wrapping everything in quotes so it is treated as a single argument to `catall`).

In the version which uses `execve()`, the above attack is no longer effective. When running the command `./catall "lmao.txt; rm lmao.txt"`, which worked on the `system()` version, the `execve()` version instead prints `/bin/cat: 'lmao.txt; rm lmao.txt': No such file or directory`. This indicates that the argument in quotes has been passed as a single argument directly to `/bin/cat`.

## Task 9: Capability Leaking

When Bob runs `cap_leak` with no arguments, the resulting shell's `id` is `bob`, as expected. However, the shell process still has the file descriptor of `/etc/zzz` open, and data can be sent to it using file redirection in the shell, such as with the command `echo "wow" >&3`.