---
title: Writeup for Crypto problems in SCTF 2020
date: 2020-07-07 23:08:14
math: true
tags: ["Crypto", "RSA", "Lattice", "Misc"]
category: "Writeup"
---

## Crypto

### RSA

同一个解密指数用了三次加密同一段明文，这本书第129页介绍了 *Common Private Exponent Attack*：

[CRYPTANALYSIS OF RSA AND ITS VARIANTS](https://www.researchgate.net/publication/266171887_Cryptanalysis_of_RSA_and_Its_Variants)

这题的情况和里面的样例是一样的，可以直接套用这个格子然后LLL即可算出d：

![图片已丢失]()

![图片已丢失]()

```python
from binascii import hexlify, unhexlify
e0 = 0x9a7dc3e0f2a3531035b18541df28b8407502c2101970862d19b107ea7dc37554e5ac620b3ce4be38e5d6fd6b1920aef9e017aa383e3c1dd8e7847dc7715832fa450d1b572cfe133c702c598ed022d40ad193608bcfeb9b9aebc910dd3257caa42e503764475b89bb99056822e21ba5723d9eee3196a6fca3debd1c7687fd310d
n0 = 0xa98c363cf72b3bce39bae63a9d3d5ba0acaa7e81f9b1191ce20bb0b54a8c19216d20af640121c482e882c0772671280af9f42c764128a94104266dd65c0bcd93766e0f0ce119072302b7f3e5cc4b5cfece38e4124041a8f8dcbdb9193f35bede2c284e40f80398bf0ba0609229fa27faa2d51c552ff1ed911a6f6f220b7b6fed
c0 = 0x57fcf94d27451fc35386e0f6eff53c6540ccff51862c992f4b59d0d49fa350493041c5be2f54a37f3afe81aa5e9a738461b3b709a4611a7289c83d769cb02f3c5d18e65d68f6fff1df0418c8a7351be1d7cce1a7514797c9bdc67d969224d783a5d004d67a5ef986d564ab1945e5c83a53d8d1dcb5e45323764a200e737b80c

e1 = 0xbb31e6433057edfed88b6a37e4419a828d1575b2b9d04a5058cd912d5efb06b2f0c5c06c5d0dd35ebeda8afa8a9cc945c244c13fc501c76e720c2c04cab70c9f906c4a810defdd84c3a38507cdf79b4e4b0c7770cc3d2d862ea9bd5fe2469290d9d2a09c8164437e9d5b7b3a9c49d111e5caa9577f8ed1ef1916ec4cb71bbb8d
n1 = 0xbcc2c4f4f51abb236b411f1f9d86d71133eb2d4ffe45a319b6ab6df1174b9ee619e696666702655b6c185735298cc008e9b7df842c480d3d42bb67228b6c7408a7afe68ab85ee1c80f43c8c52764c79ffdecc6e3a5ea76c1123affe9f02c649e5f5ca0a4082107ce4a2040e5756bf6a2b34757aefa5fb6fec6d7a9e86f0c8159
c1 = 0xacf91d2b6a300a60193485ef2e1127b5863c69da71ab9e7d71a3213e960a73e42f8e8031bf0ef20184ae0a259fd50260aacce06546af2f8bbef8a2f360c8f7511ad9c99d8715012ce0a4fa8dbba8c10d74f477156076bdfda80dc449eec3b45c7cd82802ecce7635e186d29744df04fcf812dc7e2d2f3c8cd751e4fcea43db1e

e2 = 0x332f82f338c8b84524103d310d59fc541b66705948c57eaf972b26bb209a6ddde3d6930948a559ac1a3a26790cb1a133a90b999b164d4e22014b27660dad4e5639ffc19bcd2e4961c5b00b9116f49c3c02880bb3ad32972287442d6a86a9c86cd3981ee1084df4322edb9c5da39146e10de0586c8b5433a851d649a45c5a73cd
n2 = 0xd0ad4d11576bb041ea2ce53f354dba362a93411a37f4a529e8b5eeae83a3437df6bd5e4e1f87a4d324a6ce2850f3568c929f5d5f73fef45bda03fa7bff00304a1eb833ce3535ee3552aa62b644f0d3c1679fe2c57b978c695f03e5b2d18d9b0821c7e0ca332f552b12e2b7109210d051bbe9d9b9e3cc3b16c81e77ebca65aca3
c2 = 0xc59078ae7cb454c970f272f595da71ae2b681156a1ce7112d9b96346f38bcdca87192ea39ac273851210e9f98f0d89f1bc657ce69ca14708cba8b319160a1f67b8cfc3643dc9b6a70769d8d64a9a3504d799f3d9afca7c7114880f4ccb5bef35738e660e4ede1c884f4a60f1f0e559fb754abd8e4b905ad3626a876bea43ec8e

M = isqrt(max(n0, n1, n2))
M = 10704523536419069847275584063070587220303695362157261593514212717132031073368631333467085885236049291630529090309346493924305038011673707087598638071644281

B = matrix(ZZ, [
    [M,  e0,  e1,  e2],
    [0, -n0,   0,   0],
    [0,   0, -n1,   0],
    [0,   0,   0, -n2],
])

BL = B.LLL()

temp = int(BL[0, 0])
if temp < 0:
    temp *= -1
d = int(temp // M)
m = hex(pow(c2, d, n2))[2:]
print(unhexlify(m))
print(d)
#b'SCTF{673ff064da31c0d7aee56884b01a09}'
#1235666648165896286568418878956456259719846117790808720561608081687435539909970845494445047046945948132187344353861
```

### Lattice

这题是109维的NTRU加密，在*An Introduction to Mathematical Cryptography*书里有介绍使用格基规约攻击NTRU的算法，如图构建一个格子，然后进行约减，一开始用LLL，没有找到合适的约减基，然后用BKZ-24很容易找到了，可能由于格比较稀疏，尽管格子相当于是218维，测试了BKZ-32都可以在20秒之内规约完成，取约减后的最短向量，就得到了 $f'$ 和 $g'$（前 $n$ 位是 $f'$，后 $n$ 位 $g'$）。

![图片已丢失]()

用得到的 $f'$ 进行NTRU解密得到的明文应该是一个01串，在头部补合适数量的0变成全部可打印字符就是`flag`了。

```python
Zx.<x> = ZZ[]
n = 109
q = 2048
p = 3

pub_key = 510*x ^ 108 - 840*x ^ 107 - 926*x ^ 106 - 717*x ^ 105 - 374*x ^ 104 - 986*x ^ 103 + 488*x ^ 102 + 119*x ^ 101 - 247*x ^ 100 + 34*x ^ 99 + 751*x ^ 98 - 44*x ^ 97 - 257*x ^ 96 - 749*x ^ 95 + 648*x ^ 94 - 280*x ^ 93 - 585*x ^ 92 - 347*x ^ 91 + 357*x ^ 90 - 451*x ^ 89 - 15*x ^ 88 + 638*x ^ 87 - 624*x ^ 86 - 458*x ^ 85 + 216*x ^ 84 + 36*x ^ 83 - 199*x ^ 82 - 655*x ^ 81 + 258*x ^ 80 + 845*x ^ 79 + 490*x ^ 78 - 272*x ^ 77 + 279*x ^ 76 + 101*x ^ 75 - 580*x ^ 74 - 461*x ^ 73 - 614*x ^ 72 - 171*x ^ 71 - 1012*x ^ 70 + 71*x ^ 69 - 579*x ^ 68 + 290*x ^ 67 + 597*x ^ 66 + 841*x ^ 65 + 35*x ^ 64 - 545*x ^ 63 + 575*x ^ 62 - 665*x ^ 61 + 304*x ^ 60 - 900*x ^ 59 + 428*x ^ 58 - 992*x ^ 57 - 241*x ^ 56 + 953*x ^ 55 - 784*x ^ 54 - 730*x ^ 53 - 317*x ^ 52 + 108*x ^ 51 + 180*x ^ 50 - 881*x ^ 49 - 943*x ^ 48 + 413*x ^ 47 - 898*x ^ 46 + 453*x ^ 45 - 407*x ^ 44 + 153*x ^ 43 - 932*x ^ 42 + 262*x ^ 41 + 874*x ^ 40 - 7*x ^ 39 - 364*x ^ 38 + 98*x ^ 37 - 130*x ^ 36 + 942*x ^ 35 - 845*x ^ 34 - 890*x ^ 33 + 558*x ^ 32 - 791*x ^ 31 - 654*x ^ 30 - 733*x ^ 29 - 171 * x ^ 28 - 182*x ^ 27 + 644*x ^ 26 - 18*x ^ 25 + 776*x ^ 24 + 845*x ^ 23 - 675*x ^ 22 - 741*x ^ 21 - 352*x ^ 20 - 143*x ^ 19 - 351*x ^ 18 - 158*x ^ 17 + 671*x ^ 16 + 609*x ^ 15 - 34*x ^ 14 + 811*x ^ 13 - 674*x ^ 12 + 595*x ^ 11 - 1005*x ^ 10 + 855*x ^ 9 + 831*x ^ 8 + 768*x ^ 7 + 133*x ^ 6 - 436*x ^ 5 + 1016 * x ^ 4 + 403*x ^ 3 + 904*x ^ 2 + 874*x + 248
e = -453*x ^ 108 - 304*x ^ 107 - 380*x ^ 106 - 7*x ^ 105 - 657*x ^ 104 - 988*x ^ 103 + 219*x ^ 102 - 167*x ^ 101 - 473*x ^ 100 + 63*x ^ 99 - 60*x ^ 98 + 1014*x ^ 97 - 874*x ^ 96 - 846*x ^ 95 + 604*x ^ 94 - 649*x ^ 93 + 18*x ^ 92 - 458*x ^ 91 + 689*x ^ 90 + 80*x ^ 89 - 439*x ^ 88 + 968*x ^ 87 - 834*x ^ 86 - 967*x ^ 85 - 784*x ^ 84 + 496*x ^ 83 - 883*x ^ 82 + 971*x ^ 81 - 242*x ^ 80 + 956*x ^ 79 - 832*x ^ 78 - 587*x ^ 77 + 525*x ^ 76 + 87*x ^ 75 + 464*x ^ 74 + 661*x ^ 73 - 36*x ^ 72 - 14*x ^ 71 + 940*x ^ 70 - 16*x ^ 69 - 277*x ^ 68 + 899*x ^ 67 - 390*x ^ 66 + 441*x ^ 65 + 246*x ^ 64 + 267*x ^ 63 - 395*x ^ 62 + 185*x ^ 61 + 221*x ^ 60 + 466*x ^ 59 + 249*x ^ 58 + 813*x ^ 57 + 116*x ^ 56 - 100 * x ^ 55 + 109*x ^ 54 + 579*x ^ 53 + 151*x ^ 52 + 194*x ^ 51 + 364*x ^ 50 - 413*x ^ 49 + 614*x ^ 48 + 367*x ^ 47 + 758*x ^ 46 + 460*x ^ 45 + 162*x ^ 44 + 837*x ^ 43 + 903*x ^ 42 + 896*x ^ 41 - 747*x ^ 40 + 410*x ^ 39 - 928*x ^ 38 - 230*x ^ 37 + 465*x ^ 36 - 496*x ^ 35 - 568*x ^ 34 + 30*x ^ 33 - 158*x ^ 32 + 687*x ^ 31 - 284*x ^ 30 + 794*x ^ 29 - 606 * x ^ 28 + 705*x ^ 27 - 37*x ^ 26 + 926*x ^ 25 - 602*x ^ 24 - 442*x ^ 23 - 523*x ^ 22 - 260*x ^ 21 + 530*x ^ 20 - 796*x ^ 19 + 443*x ^ 18 + 902*x ^ 17 - 210*x ^ 16 + 926*x ^ 15 + 785*x ^ 14 + 440*x ^ 13 - 572*x ^ 12 - 268*x ^ 11 - 217*x ^ 10 + 26*x ^ 9 + 866*x ^ 8 + 19*x ^ 7 + 778*x ^ 6 + 923*x ^ 5 - 197 * x ^ 4 - 446*x ^ 3 - 202*x ^ 2 - 353*x - 852

pub_key_coeffs = pub_key.coefficients()

def mul(f, g):
    return (f * g) % (x ^ n-1)

def bal_mod(f, q):
    g = list(((f[i] + q // 2) % q) - q // 2 for i in range(n))
    return Zx(g)

def inv_mod_prime(f, p):
    T = Zx.change_ring(Integers(p)).quotient(x ^ n - 1)
    return Zx(lift(1 / T(f)))

M_h = Matrix(n * 2, n * 2, 0)
for i in range(n):
    M_h[i, i], M_h[n + i, n + i] = 1, q
    for j in range(n):
        M_h[i, n + j] = pub_key_coeffs[j]
    pub_key_coeffs.insert(0, pub_key_coeffs.pop())

M_r = M_h.BKZ(block_size=24)
t = [i for i in M_r[0]]
f, g = Zx(t[:n]), Zx(t[n:])
fp = inv_mod_prime(f, p)
a = bal_mod(mul(f, e), q)
m = bal_mod(mul(fp, a), p)
for k in range(8):
    flag = k * "0" + "".join([str(i) for i in m.list()])
    flag += (8 - len(flag) % 8) * "0"
    temp = ""
    for i in range(len(flag) // 8):
        temp += chr(int(flag[i*8:i*8+8], 2))
    print(temp)
```

flag：`SCTF{@#26f35b89d3#@}`

## Misc

### Can you hear

用MMSSTV，可以直接看到`flag`: `SCTF{f78fsd1423fvsa}`

### easymisc

倒序补上文件头得到可以正常显示的图片（又是熟悉的这个男人），图片上有`flag{that_is_not_right_man}`。

```python
from binascii import hexlify,unhexlify
data = hexlify(open("galf_si_erehw.jpg","rb").read())
open("where_is_flag.jpg","wb").write(unhexlify(data[::-1]))
```

然后winhex打开可以看到一堆字符串，提示用RC4解密密文`xoBTuw36SfH4hicvCzFD9ESj`，密钥就是图片上花括号里的字符串，找网站在线解密就可以得到flag：`SCTF{St@Y_@T_H0Me}`
