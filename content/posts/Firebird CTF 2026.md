+++
date = '2026-01-26T17:29:28+08:00'
draft = false
title = 'Firebird CTF 2026'
+++
## Intro
Played with the team _grey bricks_, and achieved 8th place overall and 2nd in secondary divison. Our team is also the first team to full solve crypto.
## Crypto
### Secure AI Cert Server
#### Challenge flow

- The server prints out an encrypted certificate $\mathrm{Enc}_k(C)$ using key $k$ , $N$ and $e$, we know some parts of $C$ 
```python
def cert_generate():
    cert_data = json.dumps({
        "alg": "RSA",
        "iss": "Firebird Chan",
        "e": 65537,
        "exptime": exptime, # random
        "N": N, # 2048 bits semiprime
        "sig": siguature # random
    })
    print("e:", e)
    print("N:", N)
    iv, enc_cert = encrypt_cert(cert_data) # DES CBC, 8 bytes block
    return iv + enc_cert
```
- We need to produce a certificate $C_f$ that $\mathrm{Dec}_k(C_f)$ will be accepted by the server, `exptime` and `sig` will be checked
```python
def cert_data_verify(cert_json):
    assert cert_json["exptime"] == exptime
    assert cert_json["sig"] == siguature
```
- Using the value of $N_f$ and $e_f$ in the json, we need to find $m$ given $c=m^{e_f} \mod{N_f}$ 
```python
def token_verify(e, N):
    token = f"This is your verification token {secrets.token_hex(8)}"
    m = bytes_to_long(token.encode())
    print(m.bit_length())
    print("This is the encryped token used by your certificate:", encrypt_message(m, e, N)) # rsa
    user_token = input("Please provide your verification token: ")
    return token == user_token
```
#### Analysing the problem

- We need to do RSA decryption in the last part, so we clearly can't use the server $N, e$ 
- This suggests we need to somehow forge a certificate without knowing server's $k$ for a easy RSA decryption.
- If we can control one of $e, N$ , then RSA is easy.
#### CBC decryption

![image](/images/CBC_decryption.svg)
A natural approach is to modify $N$ , but due to CBC's chaining nature, we couldn't do that without modify the previous blocks.

However, we also see that IV is independent from the decryption function, suggesting we can modify the first block?
Moreover, we can also remove the first $i$ blocks if we set IV = $B_{i-1}$ , The ciphertext will be decrypted in the same way with the first $i$ block of plaintext removed.

With this in mind, we can remove everything before `e": 6553` and set it to `{   "e":` by choosing an appropriate IV , the resulting json will look like:

```python
{   "e":
7, "expt
ime": 17
69255639
, "N": 1
...
```
The rest is just RSA stereotyped message.

#### Solve script
```python
from sage.all import *
from pwn import *
r = remote("roasted-chal.firebird.sh", 36042)
r.recvuntil("N:")
N = int(r.recvline().strip())
print(N)
r.recvuntil("Your generated CERT:")
dat = base64.b64decode(r.recvline().strip())
iv, cert_enc = dat[:8], dat[8:]
prev_b = cert_enc[32:40]
str1 = b"""e": 6553"""
str2 = b"""{   "e":"""
iv_forge = xor(str2, xor(prev_b, str1))
r.recvuntil("Enter your encrypted CERT data: ")
r.sendline(base64.b64encode(iv_forge+cert_enc[40:]))
r.recvuntil("s the encryped token used by your certificate: ")
tok_pow = int(r.recvline().strip().decode())
r.sendline(solve_tok(tok_pow, N)) # solve the hex token
print(r.recvall())
```

### Hidden Threads of Inequality/Equality
TBD




