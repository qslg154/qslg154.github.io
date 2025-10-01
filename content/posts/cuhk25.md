+++
date = '2025-10-01T20:17:16+08:00'
draft = false
title = 'cuhk ctf 2025'
math = true
+++

Played the ctf with the team *Grey Bricks*, and we solved all crypto, most are pretty standard tho unfortunately.

## Schrödinger's Encryption

```python
import secrets

def andcryption(message: bytes, key: bytes) -> bytes:
    assert len(message) == len(key)
    n = len(message)
    m, k = int.from_bytes(message, "big"), int.from_bytes(key, "big")
    return int.to_bytes(m & k, n, "big")


def orcryption(message: bytes, key: bytes) -> bytes:
    assert len(message) == len(key)
    n = len(message)
    m, k = int.from_bytes(message, "big"), int.from_bytes(key, "big")
    return int.to_bytes(m | k, n, "big")


def schrodingers_cat(message: str) -> str:
    key = secrets.token_bytes(len(message))
    encrypted = secrets.choice([andcryption, orcryption])(message.encode(), key)
    return f"0x{bytes.hex(encrypted)}"
    
# we can call schrodingers_cat on flag indefinitely
```

An oracle $f$ is given:
$$ f(m, k) = 
\begin{cases}
m  ⅋  k & \text{for 50\%} \\\\
m  \|  k & \text{for 50\%} 
\end{cases}
$$
Where $ \|, ⅋ $ denote the bitwise or/and, and $m$ is the flag and $k$ is a random stream.

Notice that when the $i$-th bit of m is $0$ , then $\mathbb(m) = 0.25$ as $f(m, k) = 1$ iff we use 'or' and the $i$-th bit of k is $1$. similarly, $\mathbb{E}(m)$ = $0.75$ when $m=1$, so we can just carry out a statistical attack on a lot of samples.

### Script
```python
from pwn import *
from Crypto.Util.number import long_to_bytes

chal = remote('...')
const = 768  # num of bits


def hex_to_binary_dict(hex_string):
    hex_to_bin_map = {
        '0': '0000', '1': '0001', '2': '0010', '3': '0011',
        '4': '0100', '5': '0101', '6': '0110', '7': '0111',
        '8': '1000', '9': '1001', 'A': '1010', 'B': '1011',
        'C': '1100', 'D': '1101', 'E': '1110', 'F': '1111',
        'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101',
        'e': '1110', 'f': '1111'
    }

    hex_digits = hex_string[2:] if hex_string.startswith('0x') else hex_string
    binary_digits = [hex_to_bin_map[digit] for digit in hex_digits]
    return '0b' + ''.join(binary_digits)


def hamming_weight(s):  # return numb. of 1
    a = int(s, 16)
    return a.bit_count()

gather = False
if gather:
    with open('ct.txt', 'a') as f:
        for i in range(1000):
            chal.recvuntil(
                b"Now tell me the flag, I will check if you are right.")
            chal.recvuntil(b"Alice: ")
            chal.sendline(b'0')
            chal.recvuntil(b'I will send my flag once again, here you go... ')
            d = chal.recvline().decode().strip()
            print(hamming_weight(d))
            f.write(d + '\n')

brute = True
if brute:
    with open('ct.txt', 'r') as f:
        l = f.readlines()

    l = [hex_to_binary_dict(i.strip())for i in l]
    print(l)

    ind = 2
    rec = ''
    broken_index = []

    iter = 600
    for ind in range(2, len(l[0])):
        s = 0
        for i in l[:iter]:
            print(ind, i[ind])
            if i[ind] == '1':
                s += 1
        print(s)
        if s < iter * 0.5:
            rec += '0'
        elif s > iter * 0.5:
            rec += '1'
        else:
            broken_index.append(ind)
            rec += 'x'

    print(rec)
l = []
print(len(rec))

for i in range(0, len(rec)//8, 1):
    block = rec[i*8: (i+1)*8]
    block = '0b' + block
    bt = long_to_bytes(int(block, 2))
    print(bt)
    l.append(bt.decode())

print(''.join(l))

```

## Trustworthy Person

```python
from SquigglyStuff import Point, Squiggle, deserialize_point
from Crypto.Random.random import randint
import time
from sage.all import *

# Do you like Bitcoins?
# Introducing the Bitcoin Squiggle! (｡♥‿♥｡)
squiggle = Squiggle(0, 7, 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1) # Y^2 = X^3 + 7
G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
print(is_prime(order))

def trust():
    return input("> ").strip().lower()[0] == 'y'

def main():
    start_time = time.time()

    d = randint(2, order - 1)
    Q = squiggle.mul(d, G)

    print("Ciallo～(∠・ω< )⌒★")
    print("I know a secret number d, and I can tell you Q.")
    print("Q:", Q)

    print("I really know the value of d! (≧▽≦)")
    print("Do you trust me? 0v0")
    continue_protocol = not trust()
    round_no = 0

    while continue_protocol:
        if round_no == 10:
            print("You don't trust me? (╯°□°）╯︵ ┻━┻")
            print("I am a trustworthy person, I swear! (｡•́︿•̀｡)")
            print("Me go cry in the corner now... (ಥ﹏ಥ)")
            print("Bye! (╯︵╰,)")
            return
        round_no += 1
        
        print("Why no trust me? QAQ")
        print("OK fine, I will prove it to you.")
        print("The protocol goes as follows:")
        print(r"1. Nah I am too lazy to write it down, just read the code by yourself... ¯\_(ツ)_/¯")
        print("2. Yes, CTF players should know how to read code. AwA")
        # UwU
        
        print("Now give me C1 and C2! >w<")
        print("I don't want C4, I don't wanna get exploded! :3")
        C1 = deserialize_point(input("C1: ").strip())
        C2 = deserialize_point(input("C2: ").strip())

        print("The thing you need is", squiggle.add(C2, squiggle.mul(-d, C1)))

        print("Now do you trust me? OwO")
        continue_protocol = not trust()

    print("I knew you would trust me, I am a trustworthy person after all! ^_^")
    print("Now, it's time for you to prove that to me! (¬‿¬)")
    print("I can also prove that you don't know the secret number! UwU")

    for i in range(10):
        print(f"Round {i + 1}:")
        P = squiggle.mul(randint(1, order - 1), G)
        k = randint(1, order - 1)
        C1 = squiggle.mul(k, G)
        C2 = squiggle.add(P, squiggle.mul(k, Q))
        print("C1:", C1)
        print("C2:", C2)

        print("Now tell me a secret!")
        secret = deserialize_point(input("Secret: ").strip())
        if secret == P:
            print("You got lucky...")
        else:
            print("Haha, told you that you don't know the secret number!")
            print("I am always right! (¬‿¬)")
            return

    print("Well... Umm... Err... I guess you are really lucky...")

    if time.time() - start_time >= 30:
        print("It is a bit late now, I need to go to bed... (｡•́︿•̀｡)")
        print("I am sleeeeeepy... zzzzz... (￣o￣) . z Z Z")
        print("https://tinyurl.com/trustworthy-person-UwU")
        return

    flag = open("flag.txt", "r").read()

    print("Fine, here is what you wanted to know:", flag)
    print("You made me a non-trustworthy person! >.<")
    print("Hope you are happy now! (｡•́︿•̀｡)")
    print("Bye! (╯°□°）╯︵ ┻━┻")

if __name__ == "__main__":
    main()
```
Denote the curve as $E$ , generator as $G$ and secret as $d$. 

In this ZKP protocol, we need to prove that we know the point $P = C_2 - dC_1$ given $C_1 = kG$ and $C_2 = kdG + P$ for random $k$ after $10$ rounds of verification.
 
The verification is done via sending 2 points $C_1, C_2$ which we will obtain the point $C_2 - d C_1$ .

The proving process is basically obtaining 10 pairs of $(C, dC)$ , so we will need to solve the discrete log over $E$, and the curve is safe as well.

Let's look at the implementation of elliptic curve operations:

```python
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        if self.is_infinity() and other.is_infinity():
            return True
        return self.x == other.x and self.y == other.y

    def __repr__(self):
        if self.is_infinity():
            return "Point(infinity)"
        return f"Point({self.x}, {self.y})"

    def __hash__(self):
        if self.is_infinity():
            return hash((None, None))
        return hash((self.x, self.y))
```

Wait, there's no check on whether a point lies in the curve!
Since the arithmetic of performing elliptic curve operations on the curve $y^2 = x^3 + Ax + B$ is independent of $B$ , we can obtain a pair $(C, dC)$ on a curve that discrete log is fast, which we picked $y^2 = x^3$ (isomorphic to additive group with a simple mapping)
So, we can send a point on $y^2=x^3$ and find $d$ easily.

### Script
```python
from SquigglyStuff import Point, Squiggle, deserialize_point
from pwn import *

p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

squiggle = Squiggle(0, 7, 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1)

G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

# Consider y^2 = x^3 mod p
def mod_inverse(a, p):
    return pow(a, p - 2, p)

def solve_dlog_on_singular_curve(p, xp, yp, xq, yq):

    # Check points are non-singular (y != 0 implies x != 0 on curve)
    if yp == 0 or yq == 0:
        raise ValueError("Points must be non-singular affine points (y != 0).")
    
    # Check points lie on the curve
    if (yp * yp) % p != (xp * xp * xp) % p:
        raise ValueError("P is not on the curve.")
    if (yq * yq) % p != (xq * xq * xq) % p:
        raise ValueError("Q is not on the curve.")
    
    # Compute phi(P) = xp / yp mod p
    phi_p = (xp * mod_inverse(yp, p)) % p
    
    # Compute phi(Q) = xq / yq mod p
    phi_q = (xq * mod_inverse(yq, p)) % p
    
    # Compute k = phi_q / phi_p mod p
    k = (phi_q * mod_inverse(phi_p, p)) % p
    
    return k

d = randint(2, order - 1)
inj = Point(1, 1)
np = squiggle.mul(d, inj)

assert np.y ** 2 % p == np.x ** 3 % p
assert d == solve_dlog_on_singular_curve(p, 1, 1, np.x ,np.y)

chal = remote('...')
chal.recvuntil(b"Q: ")
q = deserialize_point(chal.recv().split(b'\r')[0].decode().strip())

chal.sendline(b'x')
chal.recvuntil(b"C1: ")
chal.sendline(b'Point(1, 1)')
chal.recvuntil(b"C2: ")
chal.sendline(b'Point(infinity)')
chal.recvuntil(b'The thing you need is ')

chal_pt = chal.recv()
print(f'pt: {chal_pt}')

def deserialize_remote(s):
    s = s.split(b'\r')[0].strip().removeprefix(b'The thing you need is ')
    s = s.decode('utf-8')
    s = deserialize_point(s)
    return s

chal_pt = squiggle.negate(deserialize_remote(chal_pt))

d = solve_dlog_on_singular_curve(p, 1, 1, chal_pt.x, chal_pt.y)
assert squiggle.mul(d , G) == q

chal.sendline(b'y')
for i in range(1 , 11):
    chal.recvuntil(f'Round {i}:')
    chal.recvuntil(b"C1: ")
    c1 = deserialize_point(chal.recvline().decode().strip())
    chal.recvuntil(b"C2: ")
    c2 = deserialize_point(chal.recvline().decode().strip())
    P = squiggle.add(squiggle.negate(squiggle.mul(d, c1)), c2)
    chal.recvuntil(b'Now tell me a secret!\r\n')
    chal.recvuntil(b'Secret: ')
    chal.sendline(f'Point({P.x}, {P.y})')

while True:
    print(chal.recvline())
```

## Trustworthy Person Revenge 

Now, there is a check on whether a point lies on the curve, but only partially:
```python
def normalize(self, P):
        if P.is_infinity():
            return P
        
        # PATCHED UWU
        new_x = P.x % self.p
        new_y = P.y % self.p
        if pow(new_x, 3, self.p) == pow(new_y, 2, self.p):
            raise ValueError("U DOING SOMETHING BAD BAD >.<")
        # END PATCHED

        return Point(new_x, new_y)
```

So now we cannot send points on $y^2 = x^3$ , but the server still allows other points not on the the original curve.

But still, we can send other points on $y^2 = x^3 + B$ , which the order isn't prime. We then send generators of cyclic subgroups with small orders $\{n_1,...,n_{10}\}$ on these curves, and obtain a list of residues $\{r_1,...,r_{10}\}$ of $d$ by discrete log on the groups, lifting to $d$ mod some large modulus $n$. We can find $d$ immediately the modulus is greater than upper bound of $d$ , or recover it by solving dlog with pollard's lambda.
$$
\begin{align*} 
dG &= Q \\\
(a + kn)G &= Q \\\
k(nG) &= Q - aG
\end{align*}
$$

To find these curves and subgroups , we can loop through order of $y^2 = x^3 + B$
and factorize it, and then since elliptic curves over $F_p$ is isomorphic to either cyclic group or product of two cyclic groups, we can also find the generators of small cyclic group easily. Ideally the order of each generators should be around ~$2^{25.6}$ to minimize the total runtime.

Unfortunately, the set of orders really isn't that big (I can only find 6 curves with distinct order, and one is prime) and we will have to opt for some groups with larger orders to compensate for this. 

There is a time constraint of 30s on the server, so we will definitely have to optimize the order we use.

### Find curves
```python
def get_factors(order):
    return list(factor(order))

def find_curve_with_prime_factor(args=[1, p]):
    b, p = args

    try:
        print(f'factoring {b}')
        E_test = EllipticCurve(GF(p), [0, b])
        order = E_test.order()
        l = get_factors(order)
        return l
        

with open('fact.txt', 'a') as f:
    for i in range(-1000, 1000):
        if i == 0:
            continue
        order_t = EllipticCurve(Zmod(p), [0, i]).order()
        print(f'{i}')

        if order_t in order_list:
            print('y')
            continue
        fact = find_curve_with_prime_factor([i, p])
        factor_tuple = (i, fact, mult(fact))

        f.write(str(factor_tuple) + '\n')
```
### List of orders and curve they correspond to
```python
# I picked these manually from the file
# The curves have the structure:
# 4: cyclic
# 9: Z_3 x ...
# 183: Z_14 x ...
# 33: cyclic
# -10: Z_2 x ...
# then we find generators in the larger group
b_list = [4, 9, 9, 183, 183, 183, 33, 33, 33, -10]
l1 = [3 * 199 * 18979, 13**2*3319, 22639, 2*7*10903, 5290657, 10833080827, 109903, 12977017, 383229727, 20412485227]
```
### Constructing generators
```python
pt_send = []
for b, ord_try in zip(b_list, l1):
    F = Zmod(p)
    ec = EllipticCurve(F, [0, b])
    pt = ec.random_point() 
    pt = pt * (pt.order() // ord_try)
    print(pt.order() % ord_try)
    while pt.order() != ord_try:
        pt = ec.random_point() 
        pt = pt * (pt.order() // ord_try)
    assert pt.order() % ord_try == 0
    pt_send.append(pt.xy())
```

### Solve

```python
p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
F = Zmod(p)
ori_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ec_ori = EllipticCurve(Zmod(p), [0, 7])

from pwn import *
from SquigglyStuff import deserialize_point

def serialize_point(t):
    return f"Point({t[0]}, {t[1]})"

def deserialize_point(s):
    s = s.split(b'\r')[0].decode().strip()
    if s == "Point(infinity)":
        return (0, 0)
    else:
        pattern = r"Point\(\d+, \d+\)"
        match = re.match(pattern, s)
        if not match:
            raise ValueError(f"Invalid point format: {s}")
        arr = s[6:-1].split(", ")
        return (int(arr[0]), int(arr[1]))

@parallel
def dlog(ec, chal_pt, pt, order):
    return (int(pari.elllog(ec, chal_pt, pt)), order)

while True:
    chal = remote('...')
    chal.recvuntil(b"Q: ")

    Q = ec_ori(deserialize_point(chal.recv())) # modified
    chal_pt_list = []
    res_list = []

    for i in range(10):
        chal.sendline(b'x')
        chal.recvuntil(b"C1: ")
        chal.sendline(serialize_point(pt_send[i]))
        chal.recvuntil(b"C2: ")
        chal.sendline(b'Point(infinity)')
        chal.recvuntil(b'The thing you need is ')
        chal_pt = chal.recv()
        chal_pt_list.append(deserialize_point(chal_pt))

    print(chal_pt_list)

    F = Zmod(p)
    ec_fac_list = [EllipticCurve(F, [0, b]) for b in b_list]
    pt_ec = [ec(pt) for ec, pt in zip(ec_fac_list, pt_send)]
    chal_pt = [-ec(pt) for ec, pt in zip(ec_fac_list, chal_pt_list)]

    tmp = list(zip(ec_fac_list, chal_pt, pt_ec, l1))
    start_time = time.time()
    res_list = [i[-1] for i in list(dlog(tmp))]
    print(res_list)
    t = time.time()-start_time
    print(t)
    if t > 30: # time constraint
        chal.close()
        continue

    d_res = CRT_list(*list(map(list, zip(*res_list))))
    lifted = lcm(l1)
    G = ec_ori(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )

    k = discrete_log_lambda(Q - d_res * G, lifted*G, (1, ori_order//lcm(l1)+1), operation='+')

    assert (d_res + k * lifted) * G == Q
        
    d = d_res + k * lifted
    chal.sendline(b'y')

    for i in range(1 , 11):
        chal.recvuntil(f'Round {i}:')
        chal.recvuntil(b"C1: ")
        c1 = ec_ori(deserialize_point(chal.recvline()))
        chal.recvuntil(b"C2: ")
        c2 = ec_ori(deserialize_point(chal.recvline()))
        P = c2 - d * c1
        chal.recvuntil(b'Now tell me a secret!\r\n')
        chal.recvuntil(b'Secret: ')
        chal.sendline(f'Point({P.x()}, {P.y()})')

    while True:
        print(chal.recvline())

#13.43s

```

### Afterwords

> Initially, I thought the order of cyclic group has to be a prime which had me in dlogging in a group of order ~ $10^{12}$ , thus failing the time constraint (1-min solve). 
> I did figured out some ways to make the solve script to run faster without fixing the main logic tho.

- Parallelizing (implemented)
- Calling pari_ecllog (implemented)
- Increasing memory in WSL (this speeds up the script up by margins)
- Precomputing baby steps in bsgs (I failed cuz not enough RAM when loading 10^8 points, and I eventually gave up)

Indeed, now I know that I don't know abstract algebra :cry:


