## Reversing

### revmem

**`strace`**

> strace is **a diagnostic, debugging and instructional userspace utility for Linux**. It is used to monitor and tamper with interactions between processes and the Linux kernel, which include system calls, signal deliveries, and changes of process state.

**`ltrace`**

> ltrace is **a library call tracer** and it is primarily used to trace calls made by programs to library functions. It can also trace system calls and signals, like strace.

#### A first approach

Reversing challenge, meaning that we have just the binary and no remote connection needed. We just need to find the correct output that will make our binary print the flag. In this case we can start launching the binary with some random input to check its behaviour:

```shell
$  ./revmem ciao
Wrong!
```

Ok, now lets `strace` it:

```sh
$ strace ./revmem ciao
execve("./revmem", ["./revmem", "ciao"], 0x7fffffffe338 /* 39 vars */) = 0
brk(NULL)                               = 0x555555559000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=95222, ...}) = 0
mmap(NULL, 95222, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7ffff7fe0000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\20\35\2\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=2030928, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffff7fde000
mmap(NULL, 4131552, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7ffff79e2000
mprotect(0x7ffff7bc9000, 2097152, PROT_NONE) = 0
mmap(0x7ffff7dc9000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7ffff7dc9000
mmap(0x7ffff7dcf000, 15072, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7ffff7dcf000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7ffff7fdf4c0) = 0
mprotect(0x7ffff7dc9000, 16384, PROT_READ) = 0
mprotect(0x555555557000, 4096, PROT_READ) = 0
mprotect(0x7ffff7ffc000, 4096, PROT_READ) = 0
munmap(0x7ffff7fe0000, 95222)           = 0
brk(NULL)                               = 0x555555559000
brk(0x55555557a000)                     = 0x55555557a000
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 5), ...}) = 0
write(1, "Wrong!\n", 7Wrong!
)                 = 7
exit_group(0)                           = ?
+++ exited with 0 +++
```

Not useful at all.

#### Actually is way easier than it looks like

Now lets try `ltrace` on it:

```sh
$ ltrace ./revmem ciao
malloc(30)                                                                                         0x555555559260
strncmp("flag{this_was_an_easy_reverse}", "ciao", 30)                                            
puts("Wrong!"Wrong!
)                                                                                   
+++ exited (status 0) +++
```

Well...

This is happening because of this line of code:

```c
cmp = strncmp(flag,*(char **)(param_2 + 8),0x1e);
```

From which we can see that the program is taking the flag which is hardcoded in memory.

```c
char * flag_extractor(void)

{
  char *flag;
  byte local_15;
  int i;

  flag = (char *)malloc(30);
  local_15 = 0;
  for (i = 0; i < 30; i = i + 1) {
    flag[i] = PTR_DAT_00104048[i] ^ local_15;
    local_15 = flag[i];
  }
  return flag;
}
```

From this snippet of code we can see that the flag is put in memory by a `malloc` after being obtained by XORing the encoded version of the flag. Because of the `strcmp` with the flag in memory and our input we can see the flag in clear with `ltrace`.

### revmemp

Very similar to revmem. Both `strace` and `ltrace` outputs are not very useful in this case. We can try to debug the application when the `strcmp` between the user input and the flag gets executed. From the disassembler:

```assembly
0010136d e8 be fc ff ff      CALL      <EXTERNAL>::strncmp
```

Which corresponds to:

```c
int strncmp(char * __s1, char **)(arg2+8),33);
```

If we try to put a breakpoint there and to debug it:

```shell
pwndbg> brva 0x136d
Breakpoint 2 at 0x55555555536d
pwndbg> c
Continuing.
plz don't!
[Inferior 1 (process 17406) exited with code 0377]
```

Turns out we can't debug it with gdb:

```c
void debugger_stopper(void)

{
  long lVar1;

  lVar1 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar1 == -1) {
    puts("plz don\'t!");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  return;
}
```

Rip. This is a special function called `INIT` function, which is called before the begin of the main, which means that they are kind of hidden. Good way to find them: looking at which text output they prints, and search for it into Ghidra, or run strings on the binary

Can we stop the binary from escaping that check? Yes, we just need to patch the binary: we could, for example, replace the `exit(-1)` with tops to avoid this check altogether.

Still, we have another problem. The following function gets called multiple time during execution:

```c
void wtf(void)

{
  char *aux;

  aux = (char *)entry;
  while( true ) {
    if (aux == (char *)0x101425) {
      return;
    }
    if (((*(uint *)aux & 0xf0) == 0xc0) && ((*(uint *)aux & 0xf) == 0xc)) break;
    aux = aux + 1;
  }
  puts("do not play with me!");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

It basicaly checks if the first and second symbols of entry are breakpoints (`0xcc`). It basically avoids the user from using them.

#### How to patch the binary (`xxd`, the hard way)

We'll be using vim. First of all open the binary: `vim ./revmemnp`. then input the following:

```shell
:%!xxd
```

this gives us hex dump of the binary. Then we need to search for the byte codes of the instruction we want to replace. To search in vim we use the forward slash command. So, we want to replace the exit in the debugger avoider function to be a bunch of nop. So we'll first search for its first opcode:

```
/e8
```

Then press enter, and keep pressing n until we find our function:

```
000012f0: 00e8 4afd ffff bfff ffff ffe8 80fd ffff  ..J.............
```

Then we can use I to enter intert mode, overwrite it with pops (note that it is made up of 5 opcodes, which means we need 5 nops), and pass `:%!xdd -r` and `:wq` to save and exit. Or you could just use a gui hex editor, it works either way.

#### The exploit

Basically we just need to overwrite both checks, the one which prevents us from setting a breakpoint, and the one that checks if we have gdb attached. Once the binary has been patched to remove the exit, we just start the binary with `gdb`, set a breakpoint in the `strcmp`, and then we can just see the flag in clear as argument of the `strcmp`:

```sh
 ► 0x55555555536d    call   strncmp@plt                <strncmp@plt>
        s1: 0x555555559670 ◂— 'flag{this_was_a_bit_more_complex}'
        s2: 0x7fffffffe57a ◂— 0x5f434c006f616963 /* 'ciao' */
        n: 0x21
```

---

### keycheck_baby

In this challenge we have to reverse engineer a key encryption algorithm divided in two steps. We have the key which is split in two and encrypted differently using two loops.

#### Pt.1

```c
      for (i = 0; (uint)i < 13; i = i + 1) {
        if ((char)(j[i] ^ "babuzz"[(ulong)(long)i % 6]) != magic0[i]) goto LAB_00101487;
      }
```

This first loop XORs the key with characters from the string `babuzz` % 6 (modulo), which is the length of the string itself. Easy reverse, since we have the result of the XOR, which is the `magic0` variable and we can just XOR the two to get past it (since the XOR is an invertible function):

```python
for i in range(0, 13):
   tmp.append(chr(magic0[i] ^ b'babuzz'[i % 6]))
flag = ''.join(tmp)
print(f'flag pt.1: {flag}, len: {len(flag)}')
```

#### Pt.2

As for the second one:

```c
      for (i = 0; (uint)i < 12; i = i + 1) {
        local_85 = local_85 + *j;
        j = j + 1;
                    /* if this check does not fail the program terminates. To avoid that, local_85
                       must be identical to magic1 */
        if (local_85 != magic1[i]) goto LAB_00101487;
      }
```

We have a **CBC encryption algorithm**:

> Cipher block chaining (CBC) is a mode of operation for a [block cipher](https://www.techtarget.com/searchsecurity/definition/block-cipher) -- one in which a sequence of bits are encrypted as a single unit, or block, with a [cipher](https://www.techtarget.com/searchsecurity/definition/cipher) key applied to the entire block. Cipher block chaining uses what is known as an initialization vector ([IV](https://whatis.techtarget.com/definition/initialization-vector-IV)) of a certain length.
>

Implemented as such:

```c
      for (i = 0; (uint)i < 12; i = i + 1) {
        local_85 = local_85 + *j;
        j = j + 1;
                    /* if this check does not fail the program terminates. To avoid that, local_85
                       must be identical to magic1 */
        if (local_85 != magic1[i]) goto LAB_00101487;
      }
```

**Note**: in both loops the label `LAB_00101487` take the instruction pointer to the end of the main, making the program exit. To reverse this we need an equation system as such:
$$
\left\{
    \begin{array}{ll}
p_{0} = c_{0} - IV \\
p_{1} = c_{1} - c_{0} \\
... \\
p_{n} = c_{n} - c_{n-1} \\
\end{array}
\right.
$$
Where $IV$ is the initialization vector. This can be implemented in python as follows:

```python
local_85 = -0x45    # IV
tmp.append(chr(magic1[0] - local_85 & 0xff))
for i in range(1, 12):
   tmp.append(chr(magic1[i] - magic1[i-1] & 0xff))
```

In the code above $p_{i}$ are characters of the flag, while $c_{i}$ are characters of `magic1`. 

### crackme

Another easy reversing challenge, in this case we have a XOR cypher:

```c
marker = true;
for (i = 0; enc_key[i] != '\0'; i = i + 1) {
  if ((char)(flag[i] ^ enc_key[i]) != (&cypertext)[i]) {
    marker = false;
  }
}
```

Solution:

```python
from binascii import hexlify, unhexlify

key = b'\x19\x83\x89\xD2\x6E\x1F\x84\x1C\x94\x11\x31\x82\xDE\x04\xE9\x9B\xF0\xC9\x18\xBB\x82\x51\xAA\xBA\x13\x9E\x44\xEC\x49\xE5\xAD\x49\x01\x86\xAB\x39\x6A\x00'
cypertext = b'\x7F\xEF\xE8\xB5\x15\x73\xB4\x6A\xA7\x7D\x48\xDD\xEA\x6A\x9D\xAA\x82\xFA\x6E\xE4\xF6\x23\x9B\xD9\x78\xAB\x1B\x9B\x16\x96\x9C\x2E\x6F\xB2\xC7\x0C\x17\x00'

tmp = []
for i in range(len(cypertext)):
    tmp.append(chr(cypertext[i] ^ key[i]))
flag = ''.join(tmp)

print(f'flag: {flag}')
```
