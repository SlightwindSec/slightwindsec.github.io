---
title: 0xGame 2020 Crypto Problems
date: 2020-12-21 00:00:00
math: true
tags: ["RSA", "Crypto"]
category: "Writeup"
---

0xGame2020是第一届0xGame比赛，时间持续一个月，面向零基础的新生。题目和exp可以在我的GitHub上找到：https://github.com/Am473ur/My-CTF-Challenge/tree/main/0xGame2020 ，这里记录一下出题人角度的 wp。


## Week 1

### Calendar 


![2020-10-Calendar](/blog/0xgame-2020-crypto-problems/1.png)


题目给了一张图片和一串逗号隔开的坐标信息，没看出来的话不难想到去百度一下“日历加密”，这题只是做了简单的修改。

>SAT1,THU1,MON3,MON2,WED3,SUN2,THU1,SUN4,FRI3,THU1,MON4,MON4,FRI4,THU3,SUN4,SUN2,TUE4,THU1,FRI1,MON3,MON2

懒得百度的话，也不难看出前三个字母代表周一到周日，紧跟的数字范围是 1～4，所以他们代表两个坐标，列举出来并用a～z替换1～26，即可得到 flag。

### easyXor

做出这题只需要知道异或的逆运算还是异或，反过来跑一遍就拿到了flag。

exp:

```python
cipher = [72, 63, 38, 12, 8, 30, 30, 6, 82, 4, 84, 88, 92, 7, 79, 29, 8, 90, 85, 26, 25, 87, 80, 10, 20, 20, 9, 4, 80, 73, 31, 5, 82, 0, 1, 92, 0, 0, 94, 81, 4, 85, 27, 35]
flag = ""
cipher += [ord("^")]
for i in range(len(cipher)-1):
    flag = chr(cipher[len(cipher) - i - 2] ^ cipher[len(cipher) - i - 1]) + flag
    cipher[len(cipher) - i - 2] = ord(flag[0])
print(flag)
# 0xGame{ec15a9eb-08b7-4c39-904d-27eed888f73f}
```

发现有的学弟跑完脚本手动补0，exp正确的话，是可以得到完整flag的。

### supperAffine

这题其实就是普通的仿射加密，看起来是套了三层，但是一旦展开化简，仍然是 $Ax+B$ 的一次式。

$$
\begin{aligned}
f(x)&=A_1(A_2(A_3\cdot x+B_3)+B_2)+B_3\\\\
&=(A_1A_2A_3)\cdot x+(A_1A_2B_3+A_1B_2+B_1)\\\\
&=A\cdot x+B
\end{aligned}
$$


其中 $A = A_1A_2A_3,\ B = A_1A_2B_3+A_1B_2+B_1.$

并且过大的 $A$ 和 $B$ 都是没有意义的，可以等效为模数以内的数，所以解普通的仿射加密的脚本都可以直接解这一题。

exp:

```python
from Crypto.Util.number import *
from string import ascii_letters, digits

table = ascii_letters + digits
cipher = "t6b7Tn{2GByBZBB-aan2-JRWn-GnZB-Jyf7a722ffnZ}"
MOD = len(table)


def find_ab():
    for a in range(MOD):
        for b in range(MOD):
            if (a * table.find("0") + b) % MOD == table.find(cipher[0]):
                if (a * table.find("x") + b) % MOD == table.find(cipher[1]):
                    if (a * table.find("G") + b) % MOD == table.find(cipher[2]):
                        if (a * table.find("a") + b) % MOD == table.find(cipher[3]):
                            print("a, b = {}, {}".format(a, b))
                            return (a, b)


flag = ""
A, B = find_ab()
for i in cipher:
    if i not in table:
        flag += i
    else:
        flag += table[inverse(A, MOD) * (table.find(i) - B) % MOD]
print(flag)
```

`0xGame{1b292822-33e1-46fe-be82-49ca3a11cce8}`

### equationSet

这题是个简单的解方程组，可以发现给出的值有
$$
\begin {aligned}
n&= p\cdot q\cdot r\\\ s&= p + q + r\\\ t&= p\cdot(q+r)
\end {aligned}
$$

我们需要求的是 

$$
\phi(n)=(p-1)\cdot (q-1)\cdot (r-1)
$$

其中

$$
p = GCD(n, t)
$$

所以

$$
\begin {aligned}
\phi(n) &= (p-1)\cdot( q\cdot r-(q+r)+1) \\\ 
 &= (p-1)\cdot( (n-t)/p+1)
\end {aligned}
$$

exp:

```python
from Crypto.Util.number import *

c = 216719040256186298397028655750064798850...
n = 894056034566447301955142597300391580123...
s = 296550633935119159669335323468002356547...
t = 157435908314881832180551915807491465031...

p = GCD(n, t)
phi = (p - 1) * ((n - t) // p + 1)
d = inverse(65537, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

这题也可以使用sagemath直接解，甚至不需要简单的公式推导：

```python
var('p q r')
solve([p + q + r == s, p * q * r == n, p * q + p * r == t],[p, q, r])
```

可以直接求出`3`个素数的值，然后进行解密。

### Fibonacci

这题的考点是斐波那契数列对一个模数`n`取模，会出现循环节，求出循环周期这题就相当于解决了。

这个周期就是皮萨诺周期（Pisano periods），先对 $n$ 进行素因数分解，然后求解每个素数幂的周期，最后通过中国剩余定理（Chinese remainder theorem）合并，一个素数幂 $p^n$ 的周期等于 $p^{n-1}$ 乘以 $p$ 的周期，所以需要求出每个素因数的周期。这里分为两种情况，如果 $5$ 是模 $p$ 的二次剩余，那么 $p$ 的周期是 $p-1$ 的一个因数；如果不是，那么周期为 $2(p+1)$ 的一个因数。$5$ 是否为模 $p$ 的二次剩余，可以通过勒让德（Legrend）符号来判断。

> 不过这题的 $n$ 很小，直接爆破就可以很快得到它的周期。。。（而且还挺快的orz）

这里给出通过定理求解的脚本（用C++写矩阵快速幂来实现的话会快很多）。

```python
from Crypto.Util.number import *
from gmpy2 import next_prime

def genFibonacci():
    a = [1, 1]
    for i in range(2, 2**16):
        a.append(a[i-1] + a[i-2])
    return a

def Legrend(a, p):
    if a == 1:
        return 1
    if p % a == 0:
        return 0
    if a % 2 == 0:
        return Legrend(a // 2, p) * pow(-1, (pow(p, 2) - 1) // 8)
    return Legrend(p % a, a) * pow(-1, (a - 1)*(p - 1) // 4)


def isPeriod(T, a):
    for t in range(T):
        p = t + T
        while p < len(a):
            if a[p] != a[t]:
                return False
            p += T
    return True


def Factor_n(n):
    a = []
    for i in range(2**3, 2**5):
        if (not isPrime(i)) or (n % i):
            continue
        a.append([i, 0])
        n //= i
        while n % i == 0:
            n //= i
            a[-1][1] += 1
    return a


def Factor_x(x):
    a = []
    for i in range(2, x):
        if x % i == 0:
            a.append(i)
    return a


def solve(a):
    per = []
    for i in range(len(a)):
        prime = a[i][0]
        if Legrend(5, prime) == 1:
            fac = Factor_x(prime - 1)
            tmp = prime-1
        else:
            fac = Factor_x(2*(prime + 1))
            tmp = 2*(prime + 1)
        fib_mod = [(k % prime) for k in fib]
        for t in fac:
            if isPeriod(t, fib_mod):
                per.append(t*(prime**a[i][1]))
                break
        else:
            per.append(tmp*(prime**a[i][1]))

    LCM = per[0]
    for i in range(1, len(per)):
        LCM = (per[i] * LCM) // GCD(LCM, per[i])
    return LCM

r = 6799657976717333
n = 34969
c = 18230697428395162035214602694158399484881314...
N = 18856119995376203055253776689360000192482523...

fib = genFibonacci()
a = Factor_n(n)
T = solve(a)

fib_mod = [(k % n) for k in fib]
S = sum(fib_mod[:T]) * (r // T)+sum(fib_mod[:r%T])
p = next_prime(S**16)
q = N // p
m = pow(c, inverse(65537, (p - 1) * (q - 1)), N)
print(long_to_bytes(m))
```

## Week 2

### smallModulus

这题很简单，只是过一层 proof of work​ 然后用 CRT 就可以拿到 flag，是想让大家熟悉一下远程的题目，写个自动的脚本，~~但是这题可以 nc 连上去手动拿 8 组数据出来，然后本地计算出flag......~~

> 爆破 pow 可以用 pwntools 的 mbruteforce() 函数来多线程爆，速度相对快很多。

```python
from pwn import *
import hashlib
import string
from functools import reduce
from Crypto.Util.number import*
from gmpy2 import invert

HOST = "xx.xxx.xxx.xx"
PORT = 10000
r = remote(HOST, PORT)


def proof_of_work():
    rev = r.recvuntil("sha256(XXXX+")
    suffix = r.recv(16).decode()
    rev = r.recvuntil(" == ")
    tar = r.recv(64).decode()

    def f(x):
        hashresult = hashlib.sha256(x.encode() + suffix.encode()).hexdigest()
        return hashresult == tar

    prefix = util.iters.mbruteforce(f, string.digits + string.ascii_letters, 4, 'upto')
    r.recvuntil("Give me XXXX:")
    r.sendline(prefix)


def CRT(a, m):
    Num = len(m)
    M = reduce(lambda x, y: x*y, m)
    Mi = [M // i for i in m]
    t = [invert(Mi[i], m[i]) for i in range(Num)]
    x = 0
    for i in range(Num):
        x += a[i] * t[i] * Mi[i]
    return x % M


def getData():
    line = r.recvuntil(b"> ")
    r.sendline(b"1")
    line = r.recvline().decode().strip()
    mod, res = int(line[9:25], 16), int(line[37:54], 16)
    return (mod, res)


proof_of_work()
m = []
a = []
for i in range(8):
    mod, res = getData()
    m.append(mod)
    a.append(res)
flag = CRT(a, m)
print(long_to_bytes(flag))
r.interactive()
# 0xGame{3a8f45be-a0cf-457e-958e-b896056841d7}
```

### parityOracle

RSA parity oracle 是一个经典的攻击，并且给出了 CTF Wiki 上相关部分的链接，我把模数改成了 4，理解一下就可以自己编写脚本解决这一题了。

这是一个不断更新上下界来缩小范围逼近正确的明文值的过程，对不同余数下的上下界的更新需要分类讨论。

```python
from pwn import *
from Crypto.Util.number import *

HOST = "xx.xxx.xxx.xx"
PORT = 10001
r = remote(HOST, PORT)


def proof_of_work():
    rev = r.recvuntil("sha256(XXXX+")
    suffix = r.recv(16).decode()
    rev = r.recvuntil(" == ")
    tar = r.recv(64).decode()

    def f(x):
        hashresult = hashlib.sha256(x.encode()+suffix.encode()).hexdigest()
        return hashresult == tar

    prefix = util.iters.mbruteforce(f, string.digits + string.ascii_letters, 4, 'upto')
    r.recvuntil("Give me XXXX:")
    r.sendline(prefix)
    
def getNum(c):
    r.sendline(b"1")
    r.recvuntil(b"Your cipher (in hex): ")
    r.sendline(hex(c)[2:].encode())
    return int(r.recvline().decode().strip())

proof_of_work()
r.recvuntil(b"n = ")
n = int(r.recvline().decode().strip())
r.recvuntil(b"c = ")
c = int(r.recvline().decode().strip())
e = 65537

upper = n
lower = 0
i = 1
while True:
    power = pow(4, i, n)
    new_c = (pow(power, e, n)*c) % n
    rev = getNum(new_c)
    if rev == 0:
        upper = (3 * lower + upper) // 4
    elif rev == 1:
        temp = upper
        upper = (lower + upper) // 2
        lower = (3 * lower + temp) // 4
    elif rev == 2:
        temp = upper
        upper = (lower + 3 * upper) // 4
        lower = (lower + temp) // 2
    else:
        lower = (lower + 3 * upper) // 4
    if (upper - lower) < 2:
        break
    i += 1
for i in range(100):
    if pow(lower + i, e, n) == c:
        print(long_to_bytes(lower + i))
        break
r.interactive()
# 0xGame{a9abdec6-7b84-4443-afb8-ee4dada8bdca}
```

## Week 3

### signinRSA

很简单的一题，发送密文，服务器会返回解密后的结果，只是不能发送flag的密文。

> 没想到有两位学弟用 parityOracle 的脚本打。。。

因为 $c\cdot 2^e\equiv m^e\cdot 2^e\equiv (2m)^e\ mod\ n$  所以可以发送 $c\cdot pow(2,e,n)$ 收到 $2m$，除 $2$ 得到 flag。

> 有位学弟想到发送 -c，得到返回 -m，tql

### easyRSA

这题是给了 $x=11\cdot d + 7\cdot (p-1)\cdot (q-1)$ ，我们知道 $e\cdot d\equiv 1\ mod\ (p-1)\cdot (q-1)$ ，所以存在 $r$ 使 

$$
e\cdot d= 1\ +\ r\cdot(p-1)\cdot (q-1)
$$

所以

$$
x\cdot e=11\cdot e\cdot d +7\cdot e\cdot \phi(n)\\\ 
x\cdot e=11\cdot (1+r\cdot \phi (n)) +7\cdot e\cdot \phi(n)\\\ 
x\cdot e-11=(11\cdot r+7\cdot e)\cdot \phi (n)
$$

枚举 $r$ 即可得到 $\phi(n)$ .

```python
from Crypto.Util.number import *

n = 15321211041844905603734344178124947...
c = 14896093236493033914781929755936872...
x = 26506090189848554080676908570070818...
e = 65537
kphi = x * e - 11
for r in range(e):
    k = 7 * e + 11 * r
    if kphi % k:
        continue
    phi = kphi // k
    if len(bin(n - phi + 1)[2:]) > 1025:
        continue
    print(long_to_bytes(pow(c, inverse(e, phi), n)))
# 0xGame{cfac8284-3013-439b-8ff3-884decb642bb}
```

### paddingOracle

题目名称直接告诉了是 **Padding Oracle Attack**，学弟们也都学会并实现了这种攻击，~~网上资料也非常多，我就不详细写了（其实是因为懒）~~。

这种攻击针对的是块加密的 CBC 模式，通过求得正确的中间值（Intermediary Value）并在最终和正确的向量异或得到明文。需要对密文分块从后往前破解，对于每一块，从最后一字节往前破解。

对于一块需要破解的密文，需要先构造一个`IV`，并枚举`IV`的最后一字节，直到服务器告诉我们解密后的 padding 是正确的，将枚举到的这个字节的值和 padding 的值（`\x01`）异或即可得到当前位置的中间值。然后更新`IV`的最后一字节（中间值最后一字节和`\x02`异或）来保证枚举倒数第二字节的时候，倒数第一字节解密后的值是`\x02`（这样爆破倒数第二字节的时候，只要服务器解密后倒数第二字节是`\x02`就会 padding 正确）。

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from pwn import *


HOST = "49.235.239.97"
PORT = 10003
r = remote(HOST, PORT)


def proof_of_work():
    rev = r.recvuntil("sha256(XXXX+")
    suffix = r.recv(16).decode()
    rev = r.recvuntil(" == ")
    tar = r.recv(64).decode()

    def f(x):
        hashresult = hashlib.sha256(x.encode() + suffix.encode()).hexdigest()
        return hashresult == tar

    prefix = util.iters.mbruteforce(f, string.digits + string.ascii_letters, 4, 'upto')
    r.recvuntil("Give me XXXX:")
    r.sendline(prefix)


proof_of_work()
r.recvuntil(b"iv : ")
iv = [long_to_bytes(int(r.recvline().decode().strip(), 16))]
r.recvuntil(b"crypttext : ")
crypttext = long_to_bytes(int(r.recvline().decode().strip(), 16))
blocks = [crypttext[i*16:i*16+16] for i in range(len(crypttext) // 16)]
iv += blocks[:-1]
flag = b""
for block in range(len(blocks)):
    mid_value = []
    new_iv = bytearray(b"\x00"*16)
    for i in range(16):
        for j in range(256):
            new_iv[15 - i] = j
            r.recvuntil(b"> ")
            r.sendline(b"1")
            r.recvuntil(b"Your IV (in hex): ")
            r.sendline(new_iv.hex())
            r.recvuntil(b"Your cipher (in hex): ")
            r.sendline(blocks[block].hex().encode())
            data = r.recvline()
            if b"success" in data:
                ans = j ^ (i + 1)
                break

        mid_value.append(ans)
        for m in range(15 - i, 16):
            new_iv[m] = (i + 2) ^ mid_value[15 - m]
    find = ""
    for i in range(16):
        find += hex(iv[block][i] ^ mid_value[15 - i])[2:].rjust(2, '0')
    flag += long_to_bytes(int(find, 16))
    print(flag)
r.interactive()
```

## Week 4

### littleTrick

逐字节构造服务器端的 flag，使服务器发送给我们的密文解密后只有一字节是我们未知的，所以我们只需要本地枚举一下这个字节，并在本地加密，本地的密文和服务器返回的密文一致的话，就说明爆破对了。

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from pwn import *


HOST = "xx.xxx.xxx.xx"
PORT = 10004
r = remote(HOST, PORT)


def proof_of_work():
    rev = r.recvuntil("sha256(XXXX+")
    suffix = r.recv(16).decode()
    rev = r.recvuntil(" == ")
    tar = r.recv(64).decode()

    def f(x):
        hashresult = hashlib.sha256(x.encode() + suffix.encode()).hexdigest()
        return hashresult == tar

    prefix = util.iters.mbruteforce(f, string.digits + string.ascii_letters, 4, 'upto')
    r.recvuntil("Give me XXXX:")
    r.sendline(prefix)


proof_of_work()
r.recvuntil(b"n : ")
n = int(r.recvline().decode().strip(), 16)
e = 65537
flag = b""
for i in range(44):
    mask = b"1" * (44 - i - 1)
    print(mask)
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Your mask (in hex): ", hex(pow(bytes_to_long(mask), e, n))[2:].encode())
    tar = int(r.recvline().decode().strip(), 16)
    for j in range(32, 128):
        guess = flag + long_to_bytes(j) + mask
        if pow(bytes_to_long(guess), e, n) == tar:
            flag += long_to_bytes(j)
            print(flag)
            break
r.interactive()
```

### ElGamal

这题的考点是判断二次剩余，如果发现了`y`是二次剩余的话，那么只需要判断`c1`是否为二次剩余就可以了。

```python
from Crypto.Util.number import *

y = 2101136318398982764494355697982735290351867853540128399809061806690701481465143258501856786165972388085070268979718711434744226290744692988395355120277617
g = 8401562798890834492298947403582806359769363301996138198850077614144023393945770711612546197987255078645962298286362268504959833530010137313108031112774451
p = 10946148224653120484646906462803901217745837751637974066354601688874051778651193811412739372059281847771491564589986518154039493312147458591216351424346123

datalist = [c.split(", ") for c in open("data", "r").read().split("\n")[:-1]]
flag = "".join(["0" if pow(int(c[1], 16), (p - 1) // 2, p) == 1 else "1" for c in datalist])
print(long_to_bytes(int(flag, 2)))
```

如果`y`不是二次剩余的话，就需要多进行一层判断。

> 这题改自 CVE-2018-6594

```python
from Crypto.Util.number import *

f = open("data", "r").read().split("\n")[:-1]
datalist = [c.split(", ") for c in f]

y = 2101136318398982764494355697982735290351867853540128399809061806690701481465143258501856786165972388085070268979718711434744226290744692988395355120277617
g = 8401562798890834492298947403582806359769363301996138198850077614144023393945770711612546197987255078645962298286362268504959833530010137313108031112774451
p = 10946148224653120484646906462803901217745837751637974066354601688874051778651193811412739372059281847771491564589986518154039493312147458591216351424346123

flag = ""
for c in datalist:
    output = -1
    if (pow(y, (p - 1) // 2, p) == 1) or (pow(int(c[0], 16), (p - 1) // 2, p) == 1):
        if pow(int(c[1], 16), (p - 1) // 2, p) == 1:
            flag += "0"
        else:
            flag += "1"
    else:
        if pow(int(c[1], 16), (p - 1) // 2, p) == 1:
            flag += "1"
        else:
            flag += "0"
flag = long_to_bytes(int(flag, 2))
print(flag)
```
