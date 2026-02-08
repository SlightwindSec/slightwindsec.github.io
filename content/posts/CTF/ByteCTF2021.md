---
title: ByteCTF 2021 Crypto
date: 2021-10-29 10:46:00
math: true
tags: ["Crypto", "XOR", "CBC", "OFB", "Protocol", "ECC", "ECDLP", "Coppersmith"]
category: "Writeup"
---

## easyxor

`shift`函数是个常见的移位异或操作，`convert`是对一个数字使用不同的 key 和 mask 进行 4 次移位异或，这个函数在已知 key 的情况下是可逆的。

`encrypt`函数是对明文块进行两种模式（CBC和OFB）的块加密，块长度为 8，对于每一块的加密使用的就是上面的`convert`函数。

首先通过密文的长度可以得知一共被分成了 6 块；前 3 块明文使用 OFB 模式，后三块明文使用 CBC 模式；keys 是一个长度为 4 的列表，列表中每个值的范围是(-32, 32)，$64^4$ 爆破也是可以接受的。

读完题目代码之后可以想到其实我们已经知道第一块明文了，就是 flag 的格式`ByteCTF{`，而OFB模式实际上是加密的key，最终结果和明文块异或，所以第一个明文块异或第一个密文块就可以知道第一个 key 加密的结果，也就是`cur_c = convert(last, k)`的`cur_c`，这样就可以得到第二块的 last。

现在对于第二块，已知 IV（last），未知 keys，已知明文是可显示字符，所以可以爆破 keys 了，把能解出可显示字符明文的 keys 都保留出来，发现有 4836 个 keys 是满足的，那么我们还要借助第三块再筛一次，最终只得到一组 keys。


```python
from itertools import product
from tqdm import tqdm
from Crypto.Util.number import bytes_to_long, long_to_bytes

def check(s):
    return min([((i < 129) and (i > 31)) for i in s])

c = "89b8aca257ee2748f030e7f6599cbe0cbb5db25db6d3990d3b752eda9689e30fa2b03ee748e0da3c989da2bba657b912"
c_list = [int(c[i*16:i*16+16], 16) for i in range(len(c) // 16)]
known_m = bytes_to_long(b'ByteCTF{')
range64 = list(range(-32, 33))
cur_c = known_m ^ c_list[0]
print(cur_c)
k_cnt = 0
for a,b,c,d in tqdm(product(range64, range64, range64, range64)):
    last = cur_c
    k = [a, b, c, d]
    try_cur_c = convert(last, k)
    m1 = long_to_bytes(try_cur_c ^ c_list[1])
    if check(m1): # 只筛选这第一轮的话，4836个k是满足条件的，所以得筛第二轮
        last = try_cur_c
        try_cur_c = convert(last, k)
        m2 = long_to_bytes(try_cur_c ^ c_list[2])
        if check(m2):
            k_cnt += 1
            try:
                print(m1.decode() + m2.decode(), k)
            except:
                print("error")
print(k_cnt)
# keys = [-12, 26, -3, -31]
# ByteCTF{5831a241s-f30980
```

现在已经得到了keys和前三块的明文，可以接着解后三块明文了。

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes

k = [-12, 26, -3, -31]
c = "89b8aca257ee2748f030e7f6599cbe0cbb5db25db6d3990d3b752eda9689e30fa2b03ee748e0da3c989da2bba657b912"
cl = [int(c[i*16:i*16+16], 16) for i in range(len(c) // 16)]
cur_c = bytes_to_long(b'ByteCTF{') ^ cl[0]

def shift(m, k, c):
    if k < 0:
        return m ^ m >> (-k) & c
    return m ^ m << k & c

def convert(m, key):
    c_list = [0x37386180af9ae39e, 0xaf754e29895ee11a, 0x85e1a429a2b7030c, 0x964c5a89f6d3ae8c]
    for t in range(4):
        m = shift(m, key[t], c_list[t])
    return m

def unshift_right(value, key, mask=None, nbits=32):
    if not mask: mask = (1 << (nbits + 1)) - 1
    i = 0
    while i * key < nbits:
        part_mask = ((((1 << nbits)-1) << (nbits - key)) & ((1 << nbits)-1)) >> (i * key)
        part = value & part_mask
        value ^= (part >> key) & mask
        i += 1
    return value

def unshift_left(value, key, mask=None, nbits=32):
    if not mask:
        mask = (1 << (nbits + 1)) - 1
    i = 0
    while i * key < nbits:
        part_mask = ((((1 << nbits)-1) >> (nbits - key)) & ((1 << nbits)-1)) << (i * key)
        part = value & part_mask
        value ^= (part << key) & mask
        i += 1
    return value

def my_unshift(m, k, c):
    if k < 0:
        tmp = unshift_right(m, -k, c, 64)
        return tmp
    tmp = unshift_left(m, k, c, 64)
    return tmp

def re_convert(m, key):
    c_list = [0x37386180af9ae39e, 0xaf754e29895ee11a, 0x85e1a429a2b7030c, 0x964c5a89f6d3ae8c]
    for t in range(3, -1, -1):
        m = my_unshift(m, key[t], c_list[t])
    return m

IV = re_convert(cur_c, k)
assert IV.bit_length() == 64

last = IV
cur = re_convert(cl[3], k)
m3 = long_to_bytes(cur ^ last)
print(m3)

last = cl[3]
cur = re_convert(cl[4], k)
m4 = long_to_bytes(cur ^ last)
print(m4)

last = cl[4]
cur = re_convert(cl[5], k)
m5 = long_to_bytes(cur ^ last)
print(m5)
print(m3 + m4 + m5)
# q535af-2156547475u2t}$$$
```
拼接起来得到完整 flag:`ByteCTF{5831a241s-f30980q535af-2156547475u2t}$$$`

## abusedkey

首先把用到的数据放在了`task_data.py`，方便些其他脚本时直接导入：

```python
URL = "http://39.105.181.182:30000"
msg11 = URL+"/abusedkey/server/msg11"
msg13 = URL+"/abusedkey/server/msg13"
msg21 = URL+"/abusedkey/server/msg21"
msg23 = URL+"/abusedkey/ttp/msg23"
msg25 = URL+"/abusedkey/server/msg25"

# -------------------------------- Secp256k1 --------------------------------
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a, b = 0, 7
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
# ------------------ https://en.bitcoin.it/wiki/Secp256k1 -------------------

Pc = (0xb5b1b07d251b299844d968be56284ef32dffd0baa6a0353baf10c90298dfd117,
      0xea62978d102a76c3d6747e283091ac5f2b4c3ba5fc7a906fe023ee3bc61b50fe)
```

协议2的部分，想要拿到hint很简单，只要按照描述实现出来，就拿到了hint，`hint.sage`:

```python
import requests, os, random
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from task_data import p, a, b, G, msg21, msg23, msg25
from hashlib import sha256

E = EllipticCurve(IntegerModRing(p), [a, b])
G = E(G)

# sid2 = hex(random.getrandbits(256))[2:]
sid2 = "8d1a95ce724141a0ea7c8ffa7eddc48605b3117c8aa886bcc2aff3b0c2175b56"
msg22 = requests.get(msg21, data=sid2).text
Qs_hex = msg22

rc = 1 # random.randint(1, p)
Rc = rc * G

Pic = long_to_bytes(int('FFFF', 16))
hc = int(sha256(Pic).hexdigest(), 16)
Qc = hc * Rc
Qc_hex = hex(Qc[0])[2:].rjust(64) + hex(Qc[1])[2:].rjust(64)
assert len(Qc_hex) == 128

msg24 = requests.get(msg23, data=Qc_hex+Qs_hex).text
assert len(msg24) == 256
Yc_hex, Ys_hex = msg24[:128], msg24[128:]

msg26 = requests.get(msg25, data=sid2+Yc_hex).text

Ys = E((int(Ys_hex[:64], 16), int(Ys_hex[64:], 16)))
Zcs = rc*Ys
Zcsx = long_to_bytes(int(Zcs[0]))
sk2 = sha256(Zcsx).digest()

msg26 = bytes.fromhex(msg26)
iv, ciphertext, mac = msg26[:12], msg26[12:-16], msg26[-16:]
cipher = AES.new(sk2, mode=AES.MODE_GCM, nonce=iv)
try:
    m = cipher.decrypt_and_verify(ciphertext, mac)
    print(m.decode())
except ValueError:
    print("MAC check failed")
# off-line guessing on protocol_II, and key compromise impersonation on protocol_I
```

> Hint: off-line guessing on protocol_II, and key compromise impersonation on protocol_I

hint和题目描述都在说明，两个协议共用一个 Server 端的 key，那么大概思路就是通过协议 2 拿到 key，再将这个 key 用于解协议 1 的 flag，可以先简单分析一下：

```python
已知 rc-(随机), hc-H(c口令)
未知 rs-(随机), hs-H(s口令)
Qc = rc * hc * G --- 已知
Qs = rs * hs * G --- 已知

Yc = rc * rt * G --- 已知
Ys = rs * rt * G --- 已知

Zcs = rc * rs * rt * G --- 已知 公共密钥
```

这里面的rc是我们可以控制的，所以可以令rc=1让问题看起来简单一点。

```python
rc = 1 时：

Qc = hc * G --- 已知
Qs = rs * hs * G --- 已知

Yc  =      rt * G --- 已知
Ys  = rs * rt * G --- 已知
Zcs = rs * rt * G --- 已知 公共密钥
```

$hs$ 是两个字节的sha256结果，显然是让我们爆破的，也就是说我们需要得到一组形式为 $hs\cdot Point$ 和 $Point$ 的数据，这样去爆两个字节就可以了，为了得到这样的数据，我们需要构造一下发送的数据。

```python
发送假的 Qc = hc * rs * hs * G = hc * Qs
得到    Yc = hs * rs * rt * G

发送 Qs = rs * hs * G
得到 Ys = rs * rt * G
```

这样以来，$Ys$ 和 $Yc$ 刚好是我们需要的一组数据，$Yc=hs\cdot Ys$，然后爆破一下两个字节的哈希，如果某两个字节的 sha256 乘 $Ys$ 等于 $Yc$，那么这个 sha256 的值就是 $hs$：

```python
import requests, os, random, tqdm
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from task_data import p, a, b, G, msg21, msg23, msg25
from hashlib import sha256

E = EllipticCurve(IntegerModRing(p), [a, b])
G = E(G)

sid2 = "8d1a95ce724141a0ea7c8ffa7eddc48605b3117c8aa886bcc2aff3b0c2175b56"
msg22 = requests.get(msg21, data=sid2).text
Qs = E((int(msg22[:64], 16), int(msg22[64:], 16)))


rc = 1 # random.randint(1, p)
Rc = rc*G

Pic = long_to_bytes(int('FFFF', 16))
hc = int(sha256(Pic).hexdigest(), 16)
fake_Qc = hc * Qs  # hc * rs * hs * G
fake_Qc_hex = hex(fake_Qc[0])[2:].rjust(64) + hex(fake_Qc[1])[2:].rjust(64)

msg24 = requests.get(msg23, data=fake_Qc_hex+msg22).text
assert len(msg24) == 256
Yc_hex, Ys_hex = msg24[:128], msg24[128:]

# hs * rs * rt * G
Yc = E((int(Yc_hex[:64], 16), int(Yc_hex[64:], 16)))
#      rs * rt * G
Ys = E((int(Ys_hex[:64], 16), int(Ys_hex[64:], 16)))

for pis in tqdm.tqdm(range(0xff, 0xffff+1)):
    hs = int(sha256(long_to_bytes(pis)).hexdigest(), 16)
    if ((hs*Ys) == Yc):
        print(f'pis = {pis}\nhs = {hs}')
        break

'''
pis = 36727
hs = 67294392667457530634966084521984708026794776225602296684920633502274376489620
'''
```

协议 2 搞到了 $hs$，也就是协议 1 中的服务端私钥 ds，所以服务端的公钥也很容易得到，这样就有了 $(d_S,P_S)$，还有题目给我们的 $P_C$，一旦计算出 $K_{CS}$ 就可以解出 flag 了，那么问题是看起来我们必须知道 $t_S$ 和 $d_C$ 中的一个，所以需要想办法把它消掉，在要求上传 $T_C$ 的时候，上传 $-T_C$ 就可以了。

```python
import requests, random
from Crypto.Util.number import *
from Crypto.Cipher import AES
from task_data import p, a, b, G, msg11, msg13, Pc
from hashlib import sha256


E = EllipticCurve(IntegerModRing(p), [a, b])
G = E(G)
sid1 = "8d1a95ce724141a0ea7c8ffa7eddc48605b3117c8aa886bcc2aff3b0c2175b56"

msg12 = requests.get(msg11, data=sid1).text
ds = 67294392667457530634966084521984708026794776225602296684920633502274376489620
Ps = ds*G
Pc = E(Pc)
invPc = -1*Pc
print(invPc)
invPc_hex = hex(invPc[0])[2:].rjust(64) + hex(invPc[1])[2:].rjust(64)
msg14 = requests.get(msg13, data=sid1+invPc_hex).text

Kcs = ds * invPc
sk1 = sha256(long_to_bytes(int(Kcs[0]))).digest()

msg26 = bytes.fromhex(msg14)
iv, ciphertext, mac = msg26[:12], msg26[12:-16], msg26[-16:]
cipher = AES.new(sk1, mode=AES.MODE_GCM, nonce=iv)
try:
    m = cipher.decrypt_and_verify(ciphertext, mac)
    print(m.decode())
except ValueError:
    print("MAC check failed")
```

## JustDecrypt

和美团 CTF 决赛的 secret_decryption_system 几乎是一样的题，不同的地方是给的交互次数不够，最后 unpad 不一定会被截断到什么地方，所以用一样的脚本跑出结果的概率是`1/256`

```python
from Crypto.Util.number import *
from pwn import *
from tqdm import tqdm

def main():
    r = remote('39.105.181.182', '30001')
    plaintext = b"Hello, I'm a Bytedancer. Please give me the flag!"+b"\x0f"*15

    def my_XOR(a, b):
        assert len(a) == len(b)
        return b''.join([long_to_bytes(a[i]^b[i]) for i in range(len(a))])

    def proof_of_work():
        rev = r.recvuntil(b"sha256(XXXX+")
        suffix = r.recv(28).decode()
        rev = r.recvuntil(b" == ")
        tar = r.recv(64).decode()

        def f(x):
            hashresult = hashlib.sha256(x.encode() + suffix.encode()).hexdigest()
            return hashresult == tar

        prefix = util.iters.mbruteforce(f, string.digits + string.ascii_letters, 4, 'upto')
        r.recvuntil(b'Give me XXXX > ')
        r.sendline(prefix.encode())

    def decrypt(msg):
        newmsg = msg + b'\x00'*(256+64-len(msg))
        r.recvuntil(b'Please enter your cipher in hex > ')
        r.sendline(newmsg.hex().encode())
        r.recvline()
        result = r.recvline().decode().strip()
        return bytes.fromhex(result)

    def decrypt_(msg):
        newmsg = msg + b'\x00'*(256-len(msg))
        r.recvuntil(b'Please enter your cipher in hex > ')
        r.sendline(newmsg.hex().encode())
        r.recvline()
        result = r.recvline().decode().strip()
        return bytes.fromhex(result)
    
    proof_of_work()
    msg = b'\x00'*16
    decrypt(msg)
    c = b""
    for i in range(50):
        t = decrypt(c)[i]
        c += long_to_bytes(t^plaintext[i])

    decc = decrypt_(c)
    print(decc)
    res = r.recvline()+r.recvline()
    if b"Here is your flag" in res:
        print(r.recvline())
        print(r.recvline())
        r.close()
        return (True, len(decc))
    r.close()
    return (False, len(decc))

ll = []
while True:
    ss = main()
    ll.append(ss[1])
    if ss[0]:
        break
    print(len(ll), ll)
```

## Overheard

相当于一个 Oracle，给返回`pow(msg, b, p)`的高位，可以想办法利用 coppersmith 定理。先后发送 Alice 和 `pow(Alice, 2, p)`的值，然后得到`x1`，`x2`，那么在模 p 的多项式$f(x) = (x1 + a)^2 - x2 - b$ 的值为 0，所以解这个方程的 small roots 就可以得到被舍弃的值（小于 64-bit）。

```python
from pwn import remote
from Crypto.Util.number import *
import itertools

r = remote('39.105.38.192', 30000)
p = 62606792596600834911820789765744078048692259104005438531455193685836606544743
g = 5

r.sendlineafter(b"$ ", b"1")
Alice = int(r.recvline().decode().strip()) 

r.sendlineafter(b"$ ", b"2")
Bob = int(r.recvline().decode().strip()) 


r.sendlineafter(b"$ ", b"3")
r.sendlineafter(b"To Bob: ", str(Alice).encode())
x1 = int(r.recvline().decode().strip()) 

r.sendlineafter(b"$ ", b"3")
r.sendlineafter(b"To Bob: ", str(pow(Alice, 2, p)).encode())
x2 = int(r.recvline().decode().strip()) 

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m + 1):
        base = N ^ (m-i) * f ^ i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1 / factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B * monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []

PR.<a,b> = PolynomialRing(Zmod(p))
f = (x1 + a)**2 - x2 - b
ans = small_roots(f, (2**64, 2**64), m=8)
print("ans =", ans)
r.sendlineafter(b'$ ', b'4')
r.sendlineafter(b'secret: ', str(x1 + ans[0][0]).encode())
print(r.recvline().decode().strip())
r.close()
'''
ans = [(275016199582168079, 3988784878785365375)]
b'ByteCTF{0fcca5ab-c7dc-4b9a-83f0-b24d4d004c19}'
'''
```
