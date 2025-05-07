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

The `PATH` environment variable and my custom defined one get into the `Set-UID` child process, however the `LD_LIBRARY_PATH` environment variable does not. I am surprised that any of my user-defined environment variables make it in at all!

## Task 6: The PATH Environment Variable and Set-UID Programs

By placing a fake `ls` program into `/home/seed`, for example `/bin/sh`, I can get the `Set-UID` program to run it and thus give me a shell; however, it is not running with root privilege, as the `id` command within this shell still shows the `seed` user with no change to the effective user ID.

Doing this again but with `zsh` instead, which does not have a countermeasure in place for being executed in a `Set-UID` process, we see that the output of `id` now includes `euid=0(root)`.

