---
title: "Writeup for Crypto problems in WMCTF 2020"
date: 2020-08-03 13:33:02
math: true
tags: ["Crypto", "CRT", "RSA"]
category: "Writeup"
---

## piece_of_cake

两个函数大概都是一个类似 RSA 的操作，加上一个加密算法，之前的一篇博客有介绍，

*An Introduction to Mathematical Cryptography* 书里称这个算法是 *“a toy model of a real public key cryptosystem”*。（bitlength 凑的刚刚好可以保证解密，很巧妙）

`make_cake()`这边的`cake`很小（256bits）符合正常解密的条件，可以直接用高斯格基规约算法，然而`eat_cake()`这边的`cake`是比较大的（768bits）就会导致在取模的时候值容易发生改变，所以给它加上几个`g`，并使用给出的`pow`来验证是否是正确的`cake`。

规约得到的密钥对 $(F, G)$ 是不一定等于原来的密钥对 $(f, g)$，但它们在解密过程是等价的，我们得到的密钥对 长度都是 768bits。

exp 多跑几次就能得到 flag。

```python
from gmpy2 import iroot, sqrt, invert
from pwn import remote
from string import ascii_letters, digits
from hashlib import sha256

r = remote('170.106.35.18', 8631)

def proof_of_work(txt, Hash):
    for a in ascii_letters+digits:
        for b in ascii_letters+digits:
            for c in ascii_letters+digits:
                if sha256((a+b+c+txt).encode()).hexdigest() == Hash:
                    return a+b+c


def gaussian(v1, v2):
    while True:
        if sqrt(v2[0]**2 + v2[1]**2) < sqrt(v1[0]**2 + v1[1]**2):
            v1, v2 = v2, v1
        m = int((v1[0]*v2[0] + v1[1]*v2[1]) / (v1[0]**2 + v1[1]**2))
        if m == 0:
            return (v1, v2)
        v2 = [v2[0] - m * v1[0], v2[1] - m * v1[1]]


r.recvuntil("XXX+")
nonce = r.recv(17).decode()
r.recvuntil(" == ")
target = r.recv(64).decode()
r.recvuntil("\nGive me XXX:")
w = proof_of_work(nonce, target)
r.send(str(w)+"\n")
r.recvuntil("What's your choice?\n")
r.send("1\n")
r.recvline()
temp = r.recvline().strip().decode().split(" ")
q, h, c = [int(i) for i in temp]
N = int(r.recvline().strip().decode())
cip = int(r.recvline().strip().decode())
s1, s2 = gaussian([1, h], [0, q])
f, g = s1[0], s1[1]
cake = (c * f % q) % g
cake = invert(f, g) * cake % g
for k in range(10000):
    if pow(cake, 0x10001, N) == cip:
        print("cake is: ", cake)
        break
    cake += g
r.send(str(cake) + "\n")
print(r.recvline().strip().decode())

#WMCTF{Wh4t_A_pi3ce_of_CAKE!}
```

## babySum

密度接近 0.8 的子集和问题（Subset sum problem），BKZ-24 跑得比较慢好在成功率高一点。

```python
from json import load

def check(sol, A):
    s = 0
    for x, a in zip(sol, A):
        s += x * a
    return s


k, n, d = 20, 120, 0.8
s, A = load(open("data", "r"))

N = 50
lat = []
for i, a in enumerate(A):
    lat.append([1 * (j == i) for j in range(n)] + [N * a] + [N])
lat.append([0] * n + [N * s] + [k * N])

itr = 0
while True:
    itr += 1
    print(itr)
    nums = lat[::]
    shuffle(nums)
    m = matrix(ZZ, nums)
    ml = m.BKZ(block_size=24)
    for i, row in enumerate(ml):
        if not (-1 <= min(row[:-1]) and max(row[:-1]) <= 1):
            continue
        for i in range(len(row)):
            if row[i] < 0:
                row[i] *= -1
        temp_bool = (check(row, A) == s)
        if temp_bool == True:
            print(i, row)
            quit()
#0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0
```

到 check.py 里面运行输入得到 flag：`WMCTF{83077532752999414286785898029842440}`

## Game

对 AES 选择明文攻击，逐个字节爆破。

CBC 模式的 AES 加密，块长度为 b，C0 是初始向量 IV，IV 是和服务器端同步的最新的加密向量。

IV 始终和服务器端的 IV 同步，用来消除掉当前加密的一次异或，再用 C0 异或一下就构造出了 Step2 的加密结果的第一个 block。所以爆破一个 byte 最多会和服务器交互 256 次，不过平均下来约 128 次得到一个 byte。

以 16bytes 块长度为例，让服务器把已知的 15bytes 的 r 和未知部分的前 1byte 拼起来加密，然后本地去枚举最后一个 byte 和 15bytes 拼起来发送到服务器加密，如果加密后的第一个块和在服务器端拼起来的那段是相等的，就说明猜对了。就多知道了一个 secret 的 byte，把它当作已知，再进行下一个 byte 的枚举。

```python
from pwn import remote
from hashlib import sha256
from Crypto.Util.number import *
import string
import os


r = remote('81.68.xxx.xx', 16442)

def proof_of_work(txt, Hash):
    S = string.ascii_letters + string.digits
    for a in S:
        for b in S:
            for c in S:
                for d in S:
                    if sha256((a + b + c + d + txt).encode()).hexdigest() == Hash:
                        print(a + b + c + d)
                        return a + b + c + d

def select_x(x):
    r.recvuntil("3. exit\n")
    r.recvuntil(">")
    r.send(str(x))
    r.recvuntil("(in hex): ")


r.recvuntil("XXXX+")
nonce = r.recv(16).decode()
r.recvuntil(" == ")
target = r.recv(64).decode()
print("waiting....")
w = proof_of_work(nonce, target)
r.send(str(w))
print("----------proof of work is ok!----------")
r.recvuntil("IV is: ")
IV = r.recv(32).decode()  # 16 bytes -> 32 hexlength
print("IV is: {}".format(IV))


secret = b""
for Byte in range(48):
    byte_len = (15 - (Byte % 16)) if ((Byte % 16) != 15) else 16
    bound = ((byte_len + Byte + 1) // 16) * 32
    select_x(1)
    r_ = os.urandom(byte_len)
    r.send(r_.hex())
    C_ = r.recvline().strip().decode()
    C0 = IV if bound == 32 else C_[bound-64:bound-32]
    IV = C_[-32:]
    print("brute force {} byte".format(Byte+1))
    for i in range(256):
        select_x(1)
        Pi = int(C0, 16) ^ int(IV, 16) ^ int((r_.hex() + secret.hex())[-30:] + long_to_bytes(i).hex(), 16)
        r.send(long_to_bytes(Pi).hex())
        Ci = r.recvline().strip().decode()
        IV = Ci[-32:]
        if Ci[:32] == C_[bound-32:bound]:
            secret += long_to_bytes(i)
            print("Current secret: {}".format(secret))
            break

print("secret is: {}".format(secret))
select_x(2)
r.send(secret.hex())
flag = r.recvline().strip().decode()
print(flag)
```
