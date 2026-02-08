---
title: "评估模型量化压缩损失的方法"
date: 2025-12-21T00:00:00+08:00
category: "Model Quantization"
tags: []
math: true
---


## 调试模型权重精度的困境

生成式任务评测的方式和LLM/VLM模型真实使用场景很接近，因此我们可以通过一些生成式任务数据集评测大模型的能力，例如GPQA、LiveCodeBench、AIME等（或使用CEval等加上CoT进行评测），但是这些评测成本较高，进行一轮评测需要较长时间，并且由于很多模型的最优temperature不是0，可能还需要对同一个数据集进行多轮测试取平均值，这导致调试阶段就需要耗费很多时间。

还有一些数据集例如CEval、MMLU等，只需要模型在ABCD中做出选择，可以通过Prompt引导的方式让模型完成续写，让模型输出的首个token即可完成准确率评测，并且一般来说Greedy Search (temperature=0)时就能拿到较好的效果，效率很高，但是会存在一些问题：

1. 首token精度不能代表模型长文本输出时的精度，真实使用场景通常是长文本问答，而不是让模型仅仅输出一个token；
2. 量化模型的测试结果存在大量翻转，翻转率可能是比正确率更好的指标。

通过Unsloth的文章[Unsloth Dynamic 2.0 GGUFs](https://unsloth.ai/docs/basics/unsloth-dynamic-2.0-ggufs)了解到微软的一篇论文[Accuracy is Not All You Need](https://arxiv.org/abs/2407.09141)，里面详细的探讨了测试数据集答案翻转的问题，并提供了一个比首token评测更合理、比长文本生成式任务更快的基于KL散度的评测方式。

