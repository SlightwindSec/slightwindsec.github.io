---
title: "定点数和浮点数"
date: 2024-09-17T11:17:00+08:00
category: "Model Quantization"
tags: ["Floating-point", "IEEE 754"]
math: true
---

定点和浮点中的“点”指的是小数点，定点数在比特位的定义上确定了小数点的位置，而浮点数使用更复杂的表示方式，导致小数点在若干个比特位上没有直接体现，所以称它是浮点。

## 定点数

### 1. "定点"表示的整数

`4-bit`无符号整数可以用下面这种方式来表示：

{{< figure src="/blog/fixed-point-and-float-point/001_.svg" darksrc="/blog/fixed-point-and-float-point/001_dark.svg" align=center >}}

整数不存在小数点，也可以说我们默认小数点固定在整数的末尾，所以整数的表示也可以看作是“定点”。

### 2. 定点表示的小数

使用7位二进制，前4位表示整数部分，后3位表示小数部分，可以这样表示：

$$
\begin{array}{c:c:c:c|c:c:c}
   2^3 & 2^2 & 2^1 & 2^0 & 2^{-1} & 2^{-2} & 2^{-3}
\end{array}
$$

小数点固定在第4、第5个比特之间，分别计算每个位置的值并求和即可得到这段二进制表示的小数值：

{{< figure src="/blog/fixed-point-and-float-point/002.svg" darksrc="/blog/fixed-point-and-float-point/002_dark.svg" align=center >}}

可以表示的范围是 $[0.0, 15.875]$，表示的数之间的最小间隔是 $0.125$，并且间隔是均匀的。

定点数的特点：

* 定点数和整数的表示很接近，计算也像整数一样简单高效；
* 几乎可以重用为整数运算设计的硬件；
* 表示的数值间隔均匀，但是整体范围较小。

## 浮点数

为了方便理解，我们还是从最简单的无符号整数开始，逐步定义出浮点数。

`4-bit`可以表示出集合 $A=\\{i|0\leq i \leq 15, i\in \Z\\}$，如果把它们看作 $2$ 的指数，就可以表示出数值更大的集合 $B=\\{2^i|i\in A\\}$，但是数据变得非常稀疏，并且是距离0越远越稀疏。

{{< figure src="/blog/fixed-point-and-float-point/003.svg" darksrc="/blog/fixed-point-and-float-point/003_dark.svg" align=center >}}

前 $4$ 位二进制可以称为指数（*Exponent*），简写为 $E$；为了表示小数，我们再加入 $3$ 位尾数（*Mantissa*），简写为 $M$，尾数部分和之前的计算方式相同：

$$
\begin{array}{c:c:c}
   2^{-1} & 2^{-2} & 2^{-3}
\end{array}
$$

> 例如：尾数`101`可以计算得到 $\bold{1}\times 0.5+\bold{0}\times 0.25+\bold{1}\times 0.125=0.625$

将指数部分的值与尾数部分的值相乘得到十进制的结果：

{{< figure src="/blog/fixed-point-and-float-point/004.svg" darksrc="/blog/fixed-point-and-float-point/004_dark.svg" align=center >}}

发现这样会导致出现重复的表示，比如 $2\times 0.25 = 4\times 0.125 = 0.5$，我们可以在全部的尾数前都加入一个**隐式前导位**（*implicit leading bit*），（除保留的特殊值 $0$ 以外）前导位永远为 $1$，我们不用花费一个比特位来存储它，所以它是“隐式”的。隐式前导位使尾数的范围从 $[0, 1)$ 变成了 $[1, 2)$，在区间 $[1, 2)$ 内就不存在 $2$ 倍、$4$ 倍这样的关系了。

{{< figure src="/blog/fixed-point-and-float-point/005.svg" darksrc="/blog/fixed-point-and-float-point/005_dark.svg" align=center >}}

但这又引入了新的问题，指数部分 $E \geq 0$，$2^E \geq 1$，与 $M\in [1, 2)$ 相乘也只能得到大于等于 $1$ 的结果，区间 $[0, 1)$ 内的值无法表示。

这时，我们可以引入**指数偏差**（[*Exponent bias*](https://en.wikipedia.org/wiki/Exponent_bias)）$bias$ 来得到有符号的指数 $E - bias$，当 $bias=7$ 时，就可以得到 
$$
2^{E-bias} \in \\{2^{-7}, 2^{-6}, 2^{-5}, 2^{-4}, 2^{-3}, 2^{-2}, 2^{-1}, 2^{0}, 2^{1}, 2^{2}, 2^{3}\\}
$$

{{< figure src="/blog/fixed-point-and-float-point/006.svg" darksrc="/blog/fixed-point-and-float-point/006_dark.svg" align=center >}}

另外，我们还需要保留一些特殊值，例如 $0$、$NaN$ 以及 $INF$。
$$
\begin{align}
   0 &= 0000.000_2 \\\\
   NaN &= 1111.111_2
\end{align}
$$

这时我们的 7 位无符号浮点数能够表示的最小非 $0$ 值为

$$
0000.001_2 = 2^{-7} \times (1.0 + 2^{-3}) = 0.0087890625
$$

我们希望 $0$ 到最小非 $0$ 值之间的下溢空隙尽可能的小，就可以在计算过程中更少出现算术下溢（比如两个很接近的浮点数相减，出现下溢可能导致除 $0$ 风险），我们可以约定当 $E = 0$ 时，隐式前导位为 $0$，$E \neq 0$ 时，隐式前导位为 $1$：

* $E = 0$ 且 $M = 0$ 时，即 $0000.000$ 作为 $0$ 保留
* $E = 0$ 且 $M \neq 0$ 时，约定隐式前导位为 $0$，这种浮点数用于填充最小正规数与 $0$ 之间的空隙，被称为**次正规数**（[*Subnormal number*](https://en.wikipedia.org/wiki/Subnormal_number)）
* $E \neq 0$ 时，约定隐式前导位为 $1$，这种浮点数被称为**正规数**（[*Normal number*](https://en.wikipedia.org/wiki/Normal_number_(computing))）


> 由于我们可以通过 $E$ 是否为 $0$ 来约定隐式前导位是否为 $0$，所以仍不需要单独用 $1$ 比特来存储前导位。

在 $E = 0$ 时，令隐式前导位也为 $0$，就可以表示出更小的非零值（称这种特殊场景为次正规数）

$$
0000.001_2 = 2^{-7} \times 2^{-3} = 0.0009765625
$$

次正规数使我们的 7 位浮点数可以表示的最小非 $0$ 值从 $0.0087890625$ 缩小到了 $0.0009765625$，如下图所示，相比正规数（以红色表示），使用次正规数（蓝色）可以扩展表示的范围：

{{< figure src="/blog/fixed-point-and-float-point/Denormalized_numbers_on_a_line.svg" darksrc="/blog/fixed-point-and-float-point/Denormalized_numbers_on_a_line_dark.svg" align=center >}}

最后，为了表示负数，可以在前面增加 1 位符号位，符号位为 1 时表示负数，这样就完成了比较完整的 8 位浮点数定义，我们来总结一下：

{{< figure src="/blog/fixed-point-and-float-point/007.svg" darksrc="/blog/fixed-point-and-float-point/007_dark.svg" align=center >}}

使用 $S.E.M$ 的格式来定义这个 8 位的浮点数：

* Sign：使用 1 bit 来表示符号，值为 1 时表示负数；
* Exponent：使用 4 bits 来表示指数；
* Mantissa：使用 3 bits 来表示尾数。

1. 正规数（$E\neq 0$ 时）：

$$
value = (-1)^{sign} \times 2^{(E-7)} \times \Bigg(1 + \sum_{i=1}^{3}b_{3-i}2^{-i} \Bigg)
$$

2. 次正规数（$E=0, M\neq 0$ 时）：

$$
value = (-1)^{sign} \times 2^{(E-7)} \times \Bigg(0 + \sum_{i=1}^{3}b_{3-i}2^{-i} \Bigg)
$$

3. 特殊值：
   * $0 = 0000.000_2$
   * $NaN = 1111.111_2$

## 常见的浮点类型

前面已经介绍了一些概念，比如：尾数、隐式前导位、次正规数等，这些概念普遍存在于实际应用的常见浮点类型。

### FP64, FP32, FP16

#### FP64

FP64 也称双精度浮点数（Double-precision floating-point）


### FP32


### FP16

### FP16
