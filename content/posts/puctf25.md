+++
date = '2025-04-22T00:41:11+08:00'
draft = false
title = 'puctf25'
math = true
+++

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
$$ f(x) \equiv p_{0} + x \mod N $$
Where $p_{0} = o * \mathrm{leak}$ (high-bits)

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
l = list(map(to_o, l)) # get 

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
