+++
date = '2025-04-22T00:41:11+08:00'
draft = false
title = 'puctf25'
math = true
+++
## Introduction
In this competiton, I played with _SLS Team 1_ and we got 3rd place in the secondary division, 12th overall. This is also my first ctf which I enjoyed really well.

## Simple RSA

We are given the following code:
```python
from Crypto.Util.number import *
from sympy import *
p = getPrime(1024)
q = getPrime(1024)
n = p * q
phi_n = (p - 1) * (q - 1)

o = getPrime(11)
print(o)
while (o).bit_length() <= 256:
    o = nextprime(o**2-o*2+o//114514)
    
e = 65537
d = inverse(e, phi_n)
message = b'flag{n0t_a_flag}'#not a flag, please dont submit it.
m = bytes_to_long(message)
c = pow(m, e, n)
leak = p // o
print(f"{leak = }\n{e = }\n{n = }\n{c = }")
```

So, we are given $ N, e, c $, and $\textrm{leak} = \lfloor\dfrac{p}{o}\rfloor$, lets look at the function that generates $o$

```python
o = getPrime(11)
print(o)
while (o).bit_length() <= 256:
    o = nextprime(o**2-o*2+o//114514)
```
Notice that it always gives the same prime for the same $o$,
 and there is not much 11-bits prime, so we can compute a list of 'valid prime' (and also $p$ being 1024 bits remove quite a lot of candidate)

 As we have $ p = o*\mathrm{leak} + r$, where $0 \leq r < o$,
the high bits of $p$ is known (r is at most 512 bits), and by division we also know the high bits of $q$.

Thus, we recover $p, q$ by finding small roots of:
$$f(x) \equiv p_{0} + x \colon f(x) \mid N $$
Where $p_{0} = o \cdot \mathrm{leak}$ (high-bits).

And luckily, sagemath can do it for us.

### Solve Script

```python
from sympy import primerange, nextprime
import itertools
from sage.all import *
from Crypto.Util.number import long_to_bytes
leak = 229525247431466363396748275102452237017483263642522169261128751667989187920222008435622161668672680319265020826924898363797246088163131807007417337332041423382249493063935834785517141215433641671449250167739
e = 65537
N = 17025704278529140533197619058872107964603885171352958470782161585790646923613462427169605377962573690550003077944502986729950168203218576512437143589552349649890314114132388935297791479264474856372925671733285461978196754222965933817210721106702170295307603219397576847046759192020479770500017828804341172966533293934501006960910933984286076206122078711900394523398604314656667759888376961986467636693449867798201636673910015862849243971295148252698582382932750152690278887575775483163190714208620615229118952215929316581064268051206844316410022831489028834016890716903650147622453497156376010954937711580778837022469
c = 4311864582410592398515641714066873283092570704733020675963750579450257637396801223206341426893531099797594214045668072474903562439113832955200193436212644751996373439076678324763681163278101719366667984049870077881797884706037815176674610422261092056836443076281786595701983578205257329239382883147135302350155936540564053276147568707317016243971315327000403900352756697151928182279279493762662885952724394866309727689713017096764000001598640823401861386229340651593352706627537214109887503672810630361933303225654511778551426781731805269570319655873440569557336547739592527340843859243342095245931485340768963841785

l = list(primerange(1024, 2048))

def to_o(o):
    while (o).bit_length() <= 256:
        o = nextprime(o**2-o*2+o//114514)
    return o
l = list(map(to_o, l)) # get the o used in division

cdt = []
for i in l:
	(p_low, p_high) = i * leak, i * (leak + 1)
	if p_low.bit_length() == 1024 or p_high.bit_length() == 1024:
		cdt.append((p_low, p_high))

def partial_p_upper(p_upper: int, N = N) -> int:
    PR.<x> = Zmod(N)[]
    f = x + p_upper
    roots = f.small_roots(X=2^(floor((N.nbits() / 4) * 6/7)), beta=0.3)
    for x0 in roots:
        return x0 + p_upper
    return 1

for i in cdt:
	print(partial_p_upper(i[0])) # we recover p here
p = ...
q = N // p
assert p * q == N
phi = (p-1)*(q-1)
d = inverse_mod(e, phi)
print(long_to_bytes(power_mod(c, d, N)))
```
### Flag
```python
'PUCTF25{l1l_m3th0d_13fD150796a10AdEF455aAE59A155cFE}'
```

## Simple AES
As source code is not provided, we need to first make an educated guess of what the functions in the remote instance correspond to. We can carry out two types of operation in the remote instance, so let's see some example inputs

```
======================
      Simple AES
======================
**Please just learn and explain that what is AES in super long details**, no need talk about other things

By R1ckyH:
     I will only let u try 10 times!

Position to control (x): 0 # call this operation 1
Add a block <hex>(32) at place x: 00000000000000000000000000000000
c1043aaf7cf9d038be26437f2fbd628c7a3c85a832506f165c227cc3096f2fab79b92c6b294650202685bb353317fb992880a5955b359d74f7d996956198057f5fe4718d0fe95bfbdcf5c3a128ab2d85eb1ca35ac4fedde107fbda3dced2d4bc

You can encrypt sth: 00000000 # call this operation 2
27748b31cc77684d5d5f75b3246c017c

Position to control (x): 0
Add a block <hex>(32) at place x: 00000000000000000000000000000000
5fb5ae9c277f2388c2d389894edc99efaf8c13fcbc41183c0776a3a11e705a218e3eeb986563ac8541595dff849138ea6b7bce01cf9bfd5ffb26efcabacc7cb5ccae6da7e853c6979ee1d9239141f4f267e66d6d151a9f3a0884c719bd6ec52a

You can encrypt sth: 00000000000000000000000000000000
5fb5ae9c277f2388c2d389894edc99ef31e8c3a247f9fc45b1c37b828c5fd79e
Position to control (x):
```
When a 32-character hex is encrypted with operation 2, the remote instance returns 64-character hex, so we can assume there is some padding pre-encryption. Also, operation 1 returns a pretty long hex, so we may alos assume that flag lies in it.

from the third and fourth input, we can also see that the leading 32-character hex is the same, as there is no matching string for my first and second input, the matching string is not an intitial vector. Therefore, we can assume **AES_ECB** is used here, and the corresponding operations are:


- add a block of 32-character hex (choosen by us) after the n-th character of the hex of the flag (n is also choosen by us), the encrypted hex is returned

- encrypt a choosen plaintext, the encrypted hex is returned

With the information, an **oracle attack** can be implemented:

Suppose $ \mathrm{flag} = b_{1}b_{2}\cdots b_{n}$

1. to get $b_{k}$, we add a block of hex $B$ at $k$ (position to control)
2. we encrypt $b_{1}b_{2} \cdots b_{k-1} \cdot g \cdot B $, where $g$ is our guess
3. Compare $ E(b_{1}\cdots b_{k} B ) $ and $E(b_{1}\cdots b_{k-1}gB) $, if they are the same (over some leading bytes depending on $k$, as $\mathrm{len}\,B = 32 $), then $ g = b_{k} $
4. if the encrypted hex is not the same, repeat 1 - 4 with another $g$

### Solve Script
```python
from pwn import * 
r = remote('...',  port = ..., level = 'debug')
wordlist = b'PUCTF25{' # initial flag
charset = list(b"etoanihsrdlucgwyfmpbkvjxqz{}_01234567890ETOANIHSRDLUCGWYFMPBKVJXQZ")
slice = len(wordlist) // 16
high = slice * 32 + 32 
i = 0
try:
    while True:
        r = remote('chal.polyuctf.com',  port = 21337, level = 'debug')
        for _ in range(10): # reconnect after 10 tries
            r.recvuntil(b'Position to control (x): ')
            r.sendline(f'{len(wordlist) + 1}')
            r.recvuntil(b'Add a block <hex>(32) at place x: ')
            r.sendline('00000000000000000000000000000000')
            rev1 = r.recvline()[0:high]
            r.recvuntil(b'You can encrypt sth: ')
            r.sendline((wordlist.hex() + hex(charset[i])[2:]).ljust(high, '0'))
            rev2 = r.recvline()[0:high]
            if rev1 == rev2:
                break
            i = i + 1
        if rev1 == rev2:
            wordlist = wordlist + bytes(chr(charset[i]), 'utf-8')
            i = 0
        r.close
except:
    print(wordlist) # we can update the flag when the connection is terminated
```
### Flag
```python
'PUCTF25{Y0u_N0w_Kn0w_What_1s_AES_76b9b71d9e8bc25df53d96ad9a689671}'
```

## Zero Knowledge
We are given a zkp system based on factorization of semiprime:
```python
#!/usr/bin/env python3
import os
import random
import sys
from Crypto.Util.number import getPrime, getRandomRange

def main():
    k = 80 # security level
    l = 5 # number of iterations for the interactive protocol
    A = 2**(1024 - 4) # commit bound
    B = 2**(k//l) # challenge bound
    p = getPrime(512)
    q = getPrime(512)
    N = p * q
    print(f"{N = }")

    phi = (p - 1) * (q - 1)
    gen_z = random.Random(0xc0ffee)
    print("Do you know I know the factorization of N? ( ╹ -╹)?")
    for i in range(l):
        try:
            z = gen_z.randrange(2, N)
            r = getRandomRange(0, A)
            x = pow(z, r, N)
            print(f"{x = }")

            e = int(input("e = "))
            y = r + (N - phi) * e
            print(f"{y = }")

        except Exception as err:
            print(f"(ノ ゜Д゜)ノ ︵ ┻━┻ \nError: {err}")

    print("Wait... do I know if YOU know the factorization of N? (╭ರ_•́)")

    for i in range(l):
        try:
            z = gen_z.randrange(2, N)
            x = int(input("x = "))
            e = getRandomRange(0, B)
            print(f"{e = }")

            y = int(input("y = "))
            assert x == pow(z, y - N * e, N) and 0 <= y < A
        except Exception as err:
            print("You don't knowww (💢⪖ ⩋⪕)")
            raise Exception("bye")
    print("(づ*ᴗ͈ˬᴗ͈)づ*.ﾟ✿", os.environ.get("FLAG", "FLAG MISSING, PLEASE OPEN A TICKET"))
if __name__ == "__main__":
    sys.stdout = open(sys.stdout.fileno(), 'w', buffering=1)
    try:
        main()
    except Exception as e:
        print(e)
```
Due to the fixed seed, we can find $z$. 
As $y$ is bounded, ($0\leq y < A = 2^{1020}$), finding $y$ such that
$$ x \equiv z^{y - Ne} \mod{N} $$
does not seem possible, even though we can pick $x = z^{k}$ for some $k$, we 
cannot have $y = Ne + k$ directly due to the boundary condition. This degenerates into a DLP or factorization:

- solving $x = z^{c}$ for $c \in \{y - Ne|0\leq y < 2^{1020}\}$
- or finding $\phi(N)$ so we can put $x = 1, y = \phi e - Ne$ 

which is infeasible, thus, we need extra information to convince the verifier.


Looking at this part of code, where the verifier assert that they know the factorization:
```python
z = gen_z.randrange(2, N)
r = getRandomRange(0, A)
x = pow(z, r, N)
print(f"{x = }")

e = int(input("e = "))
y = r + (N - phi) * e
print(f"{y = }")
```

We, the prover, can show that the verifier does indeed know the factorization of N by evaluating 
$\\ x \cdot x^{Ne}$ and $z^{y}$, which are equal due to euler's theroem, asserting the knowledge on $\phi(N)$

However, $e$ is unconstrainted, so, we can input a very large $e$ such that $e >> r$ and retrieve $\phi$ by:
$$ N - \phi(N) = \lfloor \frac{y}{e} \rfloor$$
As $ r/e \approx 0$

### Solve Script (Manual)
```python
# send e = 10^2000
temp = # N - phi, which cannot be a multiple of 10, so we slice off characters until a zero, yeah we don't even need to evaluate phi
while True:
    e = int(input('e : '))
    print(e * temp) # y value
```
### Flag
```python
'PUCTF25{n0_n33D_70_kN0w_Wh3n_c0d3r_15_clu3les5_659250f0c7f3dbb05c8cb13d519161fd}'
```





