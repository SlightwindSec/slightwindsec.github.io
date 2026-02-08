---
title: Learn Paillier crytposystem from "not_RSA" in DASCTF
date: 2020-04-25 13:33:02
math: true
tags: ["Crypto", "Paillier"]
category: "Writeup"
---

## "not_RSA" in DASCTF

看了大佬的博客才知道是 Paillier cryptosystem，wtcl... 不过还是记录一下自己推导的解题过程

直接使用现成的 Paillier cryptosystem 解密算法解决这题非常容易，分解 n 然后直接套 decrypt 函数就解开了...

题目：
```python
from Crypto.Util.number import getPrime as getprime ,long_to_bytes,bytes_to_long,inverse
from secret import flag,p,q
from sympy import isprime,nextprime
import random

m = bytes_to_long(flag)
n = p * q
g = n + 1
r = random.randint(1, n)

c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)

print('c =', c)
print('n =', n)
```

主要加密过程是：

$$
\begin{aligned} 
c&\equiv(g^m \ mod \ n^2)(r^n \ mod \ n^2) \   &(mod \ n^2)  \\\\ 
&\equiv g^m r^n \ &(mod \ n^2)
\end{aligned}
$$

其中有

$$
\begin{aligned}
g^m&\equiv (n+1)^m \ &(mod \ n^2) \\\\ 
&\equiv C_m^0 n^0 + C_m^1 n^1 +C_m^2n^2+...+C_m^mn^m \ &(mod \ n^2) \\\\ 
&\equiv C_m^0 n^0 + C_m^1 n^1 \ &(mod \ n^2)\\\\ 
&\equiv 1 + mn \ &(mod \ n^2)
\end{aligned}
$$

所以得到 $c\equiv g^m r^n\equiv (1 + mn)r^n \ (mod \ n^2)$

现在就要想办法消除掉 $r^n$ 的影响，不难发现 $r^n\ mod\ n = c\ mod\ n$。

所以我们需要由 $r^n\ mod\ n$ 得到 $r$ 的值或者 $r^n\ mod\ n^2$的值，才可以对 $r^n$ 在模 $n^2$ 下求逆元。这里我这个菜鸡想了好久...最终想到将 $r^n\ mod\ n$ 分别对 $n$ 的两个因数 $p,q$ 取模，然后再用中国剩余定理（CRT）合并，从而得到 $r$。

然后我们只需要计算 $r^n\ mod\ n^2$ 的逆元并与 $c$ 相乘，就得到 $(1+mn)\ mod\ n^2$，也就得到了 $m$。

```python
from Crypto.Util.number import long_to_bytes, inverse
from functools import reduce

c = 29088911054711509252215615231015162998042579425917914434962376243477176757448053722602422672251758332052330100944900171067962180230120924963561223495629695702541446456981441239486190458125750543542379899722558637306740763104274377031599875275807723323394379557227060332005571272240560453811389162371812183549
n = 6401013954612445818165507289870580041358569258817613282142852881965884799988941535910939664068503367303343695466899335792545332690862283029809823423608093
p = 80006336965345725157774618059504992841841040207998249416678435780577798937819
q = 80006336965345725157774618059504992841841040207998249416678435780577798937447
g = n + 1
phi = (p - 1) * (q - 1)
rn = c % n

x1 = rn % p
d1 = inverse(q, p - 1)
r1 = pow(x1, d1, p)

x2 = rn % q
d2 = inverse(p, q - 1)
r2 = pow(x2, d2, q)


def CRT(m, a):
    Num = len(m)
    M = reduce(lambda x, y: x * y, m)
    Mi = [M // i for i in m]
    t = [inverse(Mi[i], m[i]) for i in range(Num)]
    x = 0
    for i in range(Num):
        x += a[i] * t[i] * Mi[i]
    return x % M


r = CRT([p, q], [r1, r2])

R = pow(r, n, n * n)
R_inv = inverse(R, n * n)
mn = (c * R_inv) % (n * n)
m = (mn - 1) // n
print(long_to_bytes(m))
```

## Paillier Crytposystem

选取素数 $p, q$，计算 $n=p\cdot q$，$\lambda =lcm(p-1,q-1)$，选取 $g\in\Z_{n^2}^*$满足 $g$ 的阶是 $n$ 的倍数。

其中公钥为：$n, g$，私钥为：$p, q,\lambda$。

加密时明文 $m<n$，选取随机的 $r \in \Z_n^*$，计算出密文 $c=g^m r^n \ mod \ n^2$。

解密时的密文 $c<n^2$，明文 $m=\cfrac{L(c^\lambda\ mod\ n^2)}{L(g^\lambda\ mod\ n^2)}\ (mod\ n)$，其中 $L(u)=\cfrac{u-1}{n}$。

在选取合适的 $g$ 的时候，需要判断 $g$ 的阶是否为 $n$ 的倍数，等价于判断 $GCD(L(g^\lambda\ mod\ n^2),n)=1$。

```python
from Crypto.Util.number import *
from gmpy2 import lcm


class Paillier():
    def __init__(self):
        pass

    def encrypt(self, m):
        p, q = getPrime(512), getPrime(512)
        n = p * q
        self.n = n
        assert m < n
        Lcm = lcm(p - 1, q - 1)
        g = getRandomRange(1, n*n)
        while GCD(self.L(pow(g, Lcm, n * n)), n) != 1:
            g = getRandomRange(1, n * n)
        r = getRandomRange(1, n)
        return (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n), p, q, g

    def decrypt(self, c, p, q, g):
        n = p*q
        assert c < n*n
        Lcm = lcm(p - 1, q - 1)
        self.n = n
        self.d = inverse((p - 1) * (q-1), n)
        m_c = self.L(pow(c, Lcm, n * n))
        m_g = self.L(pow(g, Lcm, n * n))
        m = m_c*inverse(m_g, n) % n
        return m

    def L(self, u):
        return (u - 1) // self.n

m = bytes_to_long(b'flag{1234567890}')
P = Paillier()
c, p, q, g = P.encrypt(m)
M = P.decrypt(c, p, q, g)
print(long_to_bytes(M))
# b'flag{1234567890}'
```

使用 Paillier 解密就可以直接解这一题。

exp:
```python
from Crypto.Util.number import long_to_bytes,inverse
from gmpy2 import lcm
c = 29088911054711509252215615231015162998042579425917914434962376243477176757448053722602422672251758332052330100944900171067962180230120924963561223495629695702541446456981441239486190458125750543542379899722558637306740763104274377031599875275807723323394379557227060332005571272240560453811389162371812183549
n = 6401013954612445818165507289870580041358569258817613282142852881965884799988941535910939664068503367303343695466899335792545332690862283029809823423608093
p = 80006336965345725157774618059504992841841040207998249416678435780577798937819
q = 80006336965345725157774618059504992841841040207998249416678435780577798937447
g = n + 1
phi = (p - 1) * (q - 1)

def decrypt(c, p, q, g):
    n = p * q
    Lcm = lcm(p - 1, q - 1)
    m_c = (pow(c, Lcm, n * n) - 1) // n
    m_g = (pow(g, Lcm, n * n) - 1) // n
    m = m_c * inverse(m_g, n) % n
    return m

m = decrypt(c, p, q, g)
print(long_to_bytes(m))
#b'flag{5785203dbe6e8fd8bdbab860f5718155}'
```
