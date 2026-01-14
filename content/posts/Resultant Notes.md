+++
date = '2026-01-14T12:04:01+08:00'
draft = false
title = 'Resultant Notes'
math = true
+++
## Multiplication as linear map
Let $p, q$ have degree $m, n\geq 1$ and $R$ be an integral domain.
Consider the linear map $\phi : R_{n-1}[x]\times R_{m-1}[x] \rightarrow R_{a+b-1}[x]$ by:
$$\phi(r, s) = pr + qs$$
>_Theorem 1_
>$\mathrm{Im}\ \phi$  is isomorphic to some $kR_{a+b-1}[x]$ for $k \in R$ if and only if $p, q$ don't have a common factor of positive degree over $Frac(R)$. 

_Proof_: If $\phi$ is invertible, then $\phi(r, s) = pr+qs = c$ for some $r, s$ since $\phi$ is surjective. The constant polynomial $c$ assert that no such factor exist. Conversely, if $p, q$ don't have such factor then we can consider the equation $pr = -qs$ , since $p, q$ are coprime over $Frac(R)$,  
$p$ must divide $s$ , but $\deg s < m$ so $s = 0$ . Similarly $r=0$ , we have $\ker \phi = {(0, 0)}$, so $\phi$ is injective, thus is an isomorphism .

We can write out the matrix of $\phi$ and calculate its determinant to determine whether $\phi$ is an isomorphism, and whether $p, q$ have a common factor (thus common zero possibly over some field extension)

>_Remark:_ The condition of common factor over $Frac$ is to prevent issues of non-UFD
## Defining the resultant

Let $p = a_mx^m+...+a_0, q = b_n^n+...+b_0$
The matrix of $\phi$ , under the basis $\{1, x, x^2, ..., x^{m+n-1}\}$ is:

$$M = Mat(\phi)= \begin{pmatrix} 
a_0      & 0           & \cdots & 0          & b_0        & 0              & \cdots & 0       \\
a_1    & a_0       & \cdots & 0           & b_1     & b_0           & \cdots & 0  \\
a_2    & a_1     & \ddots & 0           & b_2     & b_1         & \ddots & 0 \\
\vdots  &\vdots   & \ddots & a_0        & \vdots   &\vdots       & \ddots & b_0  \\
a_m       & a_{m-1} & \cdots & \vdots   & b_n       & b_{n-1}     & \cdots & \vdots\\
0          & a_m       & \ddots &  \vdots  & 0          & b_n          & \ddots &  \vdots  \\
\vdots  & \vdots   & \ddots & a_{m-1}  & \vdots  & \vdots      & \ddots & b_{n-1}   \\
0          & 0          & \cdots  & a_m       & 0           & 0              & \cdots & b_n   
\end{pmatrix}$$
> This is called the _Sylvester matrix_

We can define the resultant of $p, q$: $\mathrm{Res}(p, q) = \det(M)$ , since for any polynomial $f$,
$f$ has repeated root if and only $f, f'$ has common zero, we can define $\mathrm{Disc}(f)$ = $\mathrm{Res}(f, f')$ .

> _Corollary 2:_ $Res(p, q) = 0$ if and only $p, q$ share common zeros (possibly over some field extensions)
## Cool applications

> _Theorem 3:_ $\bar{\mathbb{Q}}$ set of algebraic number is closed under addition and multiplication

The idea is to use resultant to construct some bivariate polynomial such that when taking resultant regarding to some variable, we have the resultant, which is a single variable polynomial vanish at the points we need.

_Proof:_ let $x, y \in \bar{\mathbb{Q}}$ , then $p(x) = q(y) = 0$ for some $p, q$ $\in \mathbb{Q}[x]$ .
The polynomial
$$ r(z) = \mathrm{Res}_x(p(x), q(z-x)) $$
has root $x+y$ , and the polynomial
$$ t(z) = \mathrm{Res}_x(p(x), x^nq(z/x))$$
has root $xy$ .

> Such proof applies for $\bar{\mathbb{Z}}$ also.

The method of resultant also comes handy for constructing polynomials for coppersmith attack.

### hkcert2025: Bivariate Copper

```python
from Crypto.Util.number import *
from sage.all import *
message = b'?'
flag = b'?' 

m = bytes_to_long(flag)
message = bytes_to_long(message)

p = getPrime(1024)
q = getPrime(25)
N = p * q
e = 65537

c = pow(message, e, N)
r1, r2 = getPrime(512), getPrime(512)
k = getPrime(64)

T1 = (k * inverse(m + r1, p)) % p
T2 = (k * inverse(m + r2, p)) % p

l1 = T1 // 2 ** 244
l2 = T2 // 2 ** 244

# print(f'{e = }')
# print(f'{N = }')
# print(f'{c = }')

# print(f'{k = }')
# print(f'{r1 = }')
# print(f'{r2 = }')
# print(f'{leak1 = }')
# print(f'{leak2 = }')
```
We can factor $N$ easily by brute force, and notice that we have

$$\begin{align} T_i(m+r_i) - k = 0 \pmod{p}\\\end{align}$$

This suggest that we can take

$$ p(t_1, t_2) = \mathrm{Res}_m( T_1(m+r_1) - k,  T_2(m+r_2) - k ) = 0$$

by writing $T_i$ as $2^{244}l_i+t_i$ , where $t_i$ are the low bits that we don't know.
We can solve $t_1, t_2$ by using standard coppersmith method.


