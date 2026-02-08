---
title: "Writeup for 强网杯 2020"
date: 2020-08-24 16:23:55
math: true
tags: ["Crypto", "CRT", "RSA"]
category: "Writeup"
---

## 强网先锋

### baby_crt

考点是 CRT-RSA，找到一篇paper：[Wagner’s Attack on a Secure CRT-RSA Algorithm Reconsidered](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.510.3146&rep=rep1&type=pdf)

然后看到里面提到可以这样获取 $p$：

$$
\large gcd(m^{c_1}-Sig^e,N)=p
$$


这个题目只有 $c_1$ 没有给出，但是很小，可以直接爆破。

```python
from Crypto.Util.number import *
from hashlib import sha1

e = 65537
n = 26318358382258215770827770763384603359524444566146134039272065206657135513496897321983920652242182112479484135343436206815722605756557098241887233837248519031879444740922789351356138322947108346833956405647578838873425658405513192437479359531790697924285889505666769580176431360506227506064132034621123828090480606055877425480739950809109048177976884825589023444901953529913585288143291544181183810227553891973915960951526154469344587083295640034876874318610991153058462811369615555470571469517472865469502025030548451296909857667669963720366290084062470583318590585472209798523021029182199921435625983186101089395997
m = 26275493320706026144196966398886196833815170413807705805287763413013100962831703774640332765503838087434904835657988276064660304427802961609185997964665440867416900711128517859267504657627160598700248689738045243142111489179673375819308779535247214660694211698799461044354352200950309392321861021920968200334344131893259850468214901266208090469265809729514249143938043521579678234754670097056281556861805568096657415974805578299196440362791907408888958917063668867208257370099324084840742435785960681801625180611324948953657666742195051492610613830629731633827861546693629268844700581558851830936504144170791124745540
sig = 20152941369122888414130075002845764046912727471716839854671280255845798928738103824595339885345405419943354215456598381228519131902698373225795339649300359363119754605698321052334731477127433796964107633109608706030111197156701607379086766944096066649323367976786383015106681896479446835419143225832320978530554399851074180762308322092339721839566642144908864530466017614731679525392259796511789624080228587080621454084957169193343724515867468178242402356741884890739873250658960438450287159439457730127074563991513030091456771906853781028159857466498315359846665211412644316716082898396009119848634426989676119219246

for c1 in range(1, 65536):
    p = GCD(pow(m, c1, n) - pow(sig, e, n), n)
    if p == 1:
        continue
    print(p)
    break

q = n // p
flag = "flag{" + sha1(long_to_bytes(p if p < q else q)).hexdigest() + "}"
print(flag)
# flag{601cb6f6d990ed5b89cf0de60508a95c07543793}
```

### bank

proof_of_work:

```python
from hashlib import sha256
from string import digits, ascii_letters
from pwn import *

r = remote("39.101.xxx.xx", "8005")

def proof_of_work():
    rev = r.recvuntil("sha256(XXX+")
    suffix = r.recv(17).decode()
    rev = r.recvuntil(" == ")
    tar = r.recv(64).decode()

    def f(x):
        hashresult = sha256(x.encode()+suffix.encode()).hexdigest()
        return hashresult == tar
    prefix = util.iters.mbruteforce(f, digits + ascii_letters, 3, 'upto')
    r.recvuntil("Give me XXX:")
    r.sendline(prefix)


def send_teamtoken():
    r.recvuntil("teamtoken:")
    r.sendline("icqc487d794f00cdb22409bd5ea7e736")


proof_of_work()
send_teamtoken()
r.interactive()
```

连上去过完 proof of work，输入一个字符串作为名字，会给出余额和菜单：

> your cash:10
> you can choose: transact, view records, provide a record, get flag, hint

试了一下发现可以向某个商人交易，例如 Alice 1 向 Alice 支付，然后会通过 hint 里面的函数生成这次交易的记录，同时我们也可以给他发送一条记录来伪造一次交易。有了足够的余额（1000）就可以买 flag 了。

但是，出题人好像没滤交易时的负数？然后....

可以交易负金额可还行，就拿到了flag

## Web

### dice2cry

题目描述：web+cry，输入`team_token`进入一个掷骰子的页面，在`cookie`可以看到`encrypto_flag`，`public_n`，`public_e`，应该是 RSA，然后每次掷骰子都会向`abi.php` get一次数据，`abi.php`也可以单独调用，相当于于一个随机返回 0～2 整数的 api，以 json 的形式返回值。然后有 js 来操作一下返回 1～6 的点数。

然后可以在 *http://106.14.66.189/abi.php.bak* 拿到 `abi.php` 的源码：

```php
<?php
session_start();
header("Content-type:text/html;charset=utf-8");

        $data = json_decode($json_string, true);

        $rand_number = isset($_POST['this_is.able']) ? $_POST['this_is.able'] : mt_      rand();
        $n = gmp_init($data['n']);
        $d = gmp_init($data['d']);
        $c = gmp_init($rand_number);
        $m = gmp_powm($c,$d,$n);
        $v3 = gmp_init('3');
        $r = gmp_mod($m,$v3);
        $result=(int)gmp_strval($r);
        $dice = array("num"=>$result);
        $json_obj = json_encode($dice);
        echo $json_obj;
?>
```

如果没有 post 一个数字，`$rand_number` 就是随机的，否则就是 post 的那个数字，所以 `$rand_number` 是可控的。

然后服务端会通过私钥 d 对 `$rand_number` 解密，并返回解密后模 3 的值，也就是一开始看到的 0～2 的“随机数”，所以这题显然是选择密文攻击，CTF wiki 上有关于 RSA parity oracle 原理的详细介绍，和这一题唯一的区别是 CTF wiki 上的是模 2。

我们可以类比 CTF wiki 上的推理来对这题模三情况的推理，最终的思想是一样的，不断缩小上下界的范围逼近正确值。

`upper`和`lower`的初始值分别为`n`和`0`，这是明文的范围。还要知道这一题的`n`模`3`得`2`。

第 $i$ 次，明文P的范围是：

$$
\frac { x N } { 3 ^ { i } } \leq P < \frac { x N + N } { 3 ^ { i } }.\ \ (\ 1\ )
$$

第 $i+1$ 次，明文P的范围是：

$$
\frac { k N } { 3 ^ { i+1 } } \leq P < \frac { k N + N } { 3 ^ { i+1 } }.\ \ (\ 2\ )
$$

对于不同的返回值（0～2），可以体现出 $k$ 模 3 后的特征（0～2）：

$$
\begin{cases}
k=3y,   &if&\ k\ \equiv 0\ (mod\ 3),y\in N^* \\\\ 
k=3y+1, &if&\ k\ \equiv 1\ (mod\ 3),y\in N^* \\\\ 
k=3y+2, &if&\ k\ \equiv 2\ (mod\ 3),y\in N^*
\end{cases}
$$

将不等式（1）分子分母同时乘 3，第 $i$ 次的：

$$
\frac { 3x N } { 3 ^ { i+1 } } \leq P < \frac { 3x N + 3N } { 3 ^ { i+1 } }.\ \ (\ 3\ )
$$


如果返回 0，将 $k = 3y$ 带入 (2) 得：

$$
\frac { 3y N } { 3 ^ { i+1 } } \leq P < \frac { 3y N + N } { 3 ^ { i+1 } }.\ \ (\ 4\ )
$$

由于P一定存在，所以（3）和（4）存在交集，所以 y = x，那么只需要更新上界“upper”：

    upper = (2*lower+upper)//3

如果返回 1，将 $k = 3y + 1$ 带入（2），

$$
\frac { 3y N+N } { 3 ^ { i+1 } } \leq P < \frac { 3y N + 2N } { 3 ^ { i+1 } }.\ \ (\ 5\ )
$$

由于P一定存在，所以（3）和（5）存在交集，所以 $y = x$，那么需要同时更新上界和下界：

    upper = (lower + 2*upper)//3; lower = (2*lower + upper)//3

如果返回 2，将 $k = 3y + 2$ 带入（2），

$$
\frac { 3y N +2N} { 3 ^ { i+1 } } \leq P < \frac { 3y N + 3N } { 3 ^ { i+1 } }.\ \ (\ 6\ )
$$

由于P一定存在，所以（3）和（6）存在交集，所以 $y = x$，那么只需要更新下界“lower”：

    lower = (lower + 2*upper) // 3

这样每一次范围的更新都会缩小范围，最终逼近明文`m`。

```python
import requests
from Crypto.Util.number import*

PHPSESSID = "jpa80o0gbpi4djabq80iopu7st"
c = 47901621682590941572620529757837523913923282588404656329721569362138054509808822622251355379677887022457532571566654200359453443547599919220729099865254694139150169466016053324444883650312695408132078436223779808465475540169329172223457636008422506025071303750315470905372763770412921709244110136409268083274
n = 0x8f5dc00ef09795a3efbac91d768f0bff31b47190a0792da3b0d7969b1672a6a6ea572c2791fa6d0da489f5a7d743233759e8039086bc3d1b28609f05960bd342d52bffb4ec22b533e1a75713f4952e9075a08286429f31e02dbc4a39e3332d2861fc7bb7acee95251df77c92bd293dac744eca3e6690a7d8aaf855e0807a1157
e = 0x10001
head = {
    'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36"
}
cookies = {"PHPSESSID": "jpa80o0gbpi4djabq80iopu7st", "public_n": "8f5dc00ef09795a3efbac91d768f0bff31b47190a0792da3b0d7969b1672a6a6ea572c2791fa6d0da489f5a7d743233759e8039086bc3d1b28609f05960bd342d52bffb4ec22b533e1a75713f4952e9075a08286429f31e02dbc4a39e3332d2861fc7bb7acee95251df77c92bd293dac744eca3e6690a7d8aaf855e0807a1157", "public_e": "010001",
           "encrypto_flag": "47901621682590941572620529757837523913923282588404656329721569362138054509808822622251355379677887022457532571566654200359453443547599919220729099865254694139150169466016053324444883650312695408132078436223779808465475540169329172223457636008422506025071303750315470905372763770412921709244110136409268083274"}
r = requests.post("http://106.14.66.189/main.php", cookies=cookies, headers=head)


def getNum(new_c):
    r = requests.post(
        "http://106.14.66.189/abi.php",
        data={'this[is.able': new_c}, cookies=cookies, headers=head)
    print(r.text)
    return int(r.text[7])


upper = n
lower = 0
i = 1
while True:  # n % 3 == 2
    power = pow(3, i, n)
    new_c = (pow(power, e, n) * c) % n  # pow(3^{i}*m, e, n)
    rev = getNum(new_c)
    if rev == 0:  # power * m mod n == 0
        upper = (2 * lower + upper) // 3
    elif rev == 1:  # power * m mod n == (1 or 2)
        temp = upper
        upper = (lower + 2 * upper) // 3
        lower = (2 * lower + temp) // 3
    else:
        lower = (lower + 2 * upper) // 3
    if (upper - lower) < 2:
        break
    i += 1

print(long_to_bytes(upper))
```

## Crypto

### modestudy

```python
from Crypto.Util.number import *
from string import digits, ascii_letters
from binascii import unhexlify
from hashlib import sha256
from pwn import *
import os


r = remote("139.224.254.172", "7777")


def proof_of_work():  # 多线程爆破
    rev = r.recvuntil("sha256(")
    suffix = r.recvuntil("+")[:-1].decode()
    rev = r.recvuntil("?=")
    def f(x):
        hashresult = hashlib.sha256(suffix.encode()+x.encode()).digest()
        bits = ''.join(bin(j)[2:].zfill(8) for j in hashresult)
        return bits.startswith('0' * 5)
    prefix = util.iters.mbruteforce(f, digits + ascii_letters, 8, 'upto')
    r.sendline(prefix)


def challenge1():
    r.recvuntil("your choice:")
    r.sendline("1")
    r.recvuntil("session=")
    session = r.recv(16)
    r.recvuntil("checksum=")
    checksum = r.recv(64)
    r.recvuntil("cookie:")
    plain = "session={};admin=0".format(session)
    bit = ((unhexlify(checksum)[15]) ^ ord('0') ^ ord('1'))
    checksum = checksum.decode()
    checksum_final = checksum[:30] + hex(bit)[2:] + checksum[32:]
    newcookie = "session={};admin=1;checksum={}".format(
        session.decode(), checksum_final)
    r.sendline(newcookie)


def challenge2():
    r.recvuntil("your choice:")
    r.sendline("2")
    r.recvuntil("sha256(iv)=")
    sha_iv = r.recv(64).decode()
    r.recvuntil("your choice:")
    r.sendline("1")
    r.sendline("A" * 32)
    r.recvuntil("[+] ")
    plain = r.recvuntil("\n")[:-1]
    m0 = bytes.fromhex(plain[:32].decode())
    m1 = bytes.fromhex(plain[32:].decode())
    iv = long_to_bytes(bytes_to_long(m0) ^ bytes_to_long(m1) ^ bytes_to_long(b"A"*16))
    r.recvuntil("your choice:")
    r.sendline("2")
    assert sha256(iv).hexdigest() == sha_iv
    r.sendline(iv.hex())


def challenge3():
    r.recvuntil("your choice:")
    r.sendline("3")
    r.recvuntil("128bit_ecb_encrypt(cookie):")
    cipher = r.recvuntil("\n")[:-1].decode()
    cipher = bytearray.fromhex(cipher)
    for i in range(16):
        cipher[32 + i] = cipher[64 + i]
    r.sendline(cipher.hex())


def challenge4():
    r.recvuntil("your choice:")
    r.sendline("4")
    r.recvuntil("sha256(secret)=")
    sha_secret = r.recv(64).decode()
    secret = b""
    for Byte in range(16):
        byte_len = (15 - (Byte % 16)) if ((Byte % 16) != 15) else 16
        bound = ((byte_len + Byte + 1) // 16) * 32
        r.recvuntil("your choice:")
        r.sendline("1")
        r.recvuntil("input(encode hex):")
        r_ = os.urandom(byte_len)
        r.sendline(r_.hex())
        r.recvuntil("encrypted msg: ")
        C_ = r.recvuntil("\n")[:-1].decode()
        print("brute force {} byte".format(Byte+1))
        for i in range(256):
            r.recvuntil("your choice:")
            r.sendline("1")
            r.recvuntil("input(encode hex):")
            Pi = int((r_.hex()+secret.hex())[-30:]+long_to_bytes(i).hex(), 16)
            r.sendline(long_to_bytes(Pi).hex())
            r.recvuntil("encrypted msg: ")
            Ci = r.recvuntil("\n")[:-1].decode()
            if Ci[:32] == C_[bound-32:bound]:
                secret += long_to_bytes(i)
                print("Current secret: {}".format(secret))
                break
    r.recvuntil("your choice:")
    r.sendline("2")
    r.recvuntil("secret(encode hex):")
    r.sendline(secret.hex())


def challenge5():
    r.recvuntil("your choice:")
    r.sendline("5")
    r.recvuntil("sha256(secret)=")
    sha_secret = r.recv(64).decode()
    r.recvuntil("(secret).encode(\"hex\")=")
    c = r.recv(32)
    secret = ""
    for i in range(8):
        part_c = c[i*4:i*4+4]
        guess = ""
        for j in range(0xffff):
            temp = "0" * (4 - len(hex(j)[2:])) + hex(j)[2:]
            guess += temp
            if len(guess) == 1024: # 由于向服务端发送接收时间成本较高，所以一次发送1024bits加快爆破速度
                r.recvuntil("your choice:")
                r.sendline("1")
                r.recvuntil("input(encode hex):")
                r.sendline(guess)
                r.recvuntil("encode(\"hex\"):")
                temp_c = r.recv(1024)
                flag = False
                for k in range(256):
                    if temp_c[k*4:k*4+4] == part_c:
                        secret += guess[k*4:k*4+4]
                        flag = True
                        break
                if flag:
                    break
                guess = ""
        print("Current secret:", secret)
    r.recvuntil("your choice:")
    r.sendline("2")
    r.recvuntil("secret(encode hex):")
    r.sendline(secret)


def challenge6():
    r.recvuntil("your choice:")
    r.sendline("6")
    r.recvuntil("iv+aes128_cbc(key,iv,padding(secret)):")
    iv_cbc = r.recvuntil("\n")[:-1].decode()
    iv = bytearray.fromhex(iv_cbc[:32])
    cbc = bytearray.fromhex(iv_cbc[32:64])
    mid = []
    new_iv = bytearray(b'\x00' * 16)
    count = 1
    for i in range(16):
        for j in range(256):
            new_iv[15 - i] = j
            upload = new_iv + cbc
            r.sendline('1')
            r.recvuntil("input your iv+c (encode hex):")
            r.sendline(upload.hex())
            search = r.recvuntil("your choice:")
            if b"success" in search:
                print(search)
                ans = j ^ count
                break
        count += 1
        mid.append(ans)
        for m in range(15 - i, 16):
            new_iv[m] = count ^ mid[15 - m]
    find = ""
    for i in range(16):
        find += hex(iv[i] ^ mid[15 - i])[2:].rjust(2, '0')
    r.sendline('2')
    r.recvuntil("secret(encode hex):")
    r.sendline(find)


proof_of_work()
r.recvuntil("teamtoken=")
r.sendline("icqc487d794f00cdb22409bd5ea7e736")

challenge1()
challenge2()
challenge3()
challenge4()
challenge5()
challenge6()
r.interactive()
# 这边再输入7得到flag
# icqc487d794f00cdb22409bd5ea7e736
# flag{86ac04cc901a04462c55923eedf5affe}
```
