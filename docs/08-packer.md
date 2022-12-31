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
