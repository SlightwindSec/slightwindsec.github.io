---
title: Chinese Remainder Theorem
date: 2020-02-29 00:00:00
math: true
tags: ["CRT", "Algorithm"]
category: "Implementation"
---

## 模数两两互素时

```python
from Crypto.Util.number import inverse
from functools import reduce

def crt(a, m):
    '''Return a solution to a Chinese Remainder Theorem problem.
    '''
    M = reduce(lambda x, y: x * y, m)
    Mi = [M // i for i in m]
    t = [inverse(Mi[i], m[i]) for i in range(len(m))]
    x = sum([a[i] * t[i] * Mi[i] for i in range(len(m))])
    return x % M
```

## 不满足模数两两互素时

这种情况有最小解 $x$ 满足条件，很多博客也讲的很详细，但是没找到 Python 写的...

与 $m$ 互素时一样，$m$ 不互素时显然也会有无限个解 $X = k \cdot M + x$ ，但是 $m$ 之间不互素时，在模 $M$ 的意义下也可能会有多个解。

$x$ 为最小解，$m_1 , m_2 , \dots , m_n$ 的最小公倍数为 $L$，$X < M$ ，易知 $X = x + k \cdot L$ ，枚举 $k$ 就可以了。

```python
from Crypto.Util.number import GCD, inverse
from functools import reduce


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def crt_minial(a, m):
    '''Return the minial solution to a Chinese Remainder Theorem problem.
    '''
    assert len(a) == len(m), f"length of {a} is not equal to {b}"
    m1, a1, lcm = m[0], a[0], m[0]
    for i in range(1, len(m)):
        c = a[i] - a1
        g, k, _ = egcd(m1, m[i])
        lcm = lcm * m[i] // GCD(lcm, m[i])
        assert c % g == 0, 'No Answer!'
        t = m[i] // g
        a1 += m1 * (((c // g * k) % t + t) % t)
        m1 = m[i] // g * m1
    return a1
```
