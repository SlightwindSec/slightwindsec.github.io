---
title: "模型量化简介"
date: 2024-09-24T15:05:00+08:00
category: "Model Quantization"
tags: ["Quantization"]
math: true
---

## 模型量化是什么

模型“量化（Quantization）”区别于金融领域的量化交易（Quantitative Trading）和量化分析（[Quantitative analysis](https://en.wikipedia.org/wiki/Quantitative_analysis_(finance))）中的量化，模型量化是为了在尽可能保持模型推理效果的前提下压缩模型的大小，从而降低推理部署的成本，提高推理效率，有时也可以降低模型微调的成本（QLoRA）。

目前大语言模型参数量通常达到了7B、13B、70B、甚至405B，如果用`FP16`或`BF16`类型来存储这些参数，大约需要几十到几百GB的空间，对这些`16-bit`的浮点类型参数进行量化，例如量化到`8-bit`、`6-bit`或`4-bit`等，可以有显著的内存收益，可以在显存更小的显卡上运行模型。


