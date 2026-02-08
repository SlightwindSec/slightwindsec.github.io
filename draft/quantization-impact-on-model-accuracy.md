---
title: "Quantization Impact on Model Accuracy"
date: 2024-03-01 15:30:00
category: "Model Quantization"
tags: ["LLM", "bitsandbytes", "MMLU"]
math: true
---

## Mistral-7B's performance on 5-shot MMLU

如果对测试细节不感兴趣，只需要看下面给出的汇总表格即可。

## Overview

量化/非量化版本的 Mistral-7B-v0.1 模型在 5-shot MMLU 上的表现：

| Quant Type | Compute Dtype | Double Quant | Group Size | Avg (%) | Total Time (s) |
| ---------- | ------------- | ------------ | ---------- | ------- | -------------- |
| BF16       | BF16          | N/A          | N/A        | $61.00$ | $312.79$       |
| INT8       | BF16&INT8     | N/A          | N/A        | $60.87$ | $614.43$       |
| FP4        | FP16          | False        | 64         | $59.37$ | $347.00$       |
| FP4        | FP16          | True         | 64         | $59.17$ | $353.22$       |
| FP4        | FP32          | False        | 64         | $59.50$ | $1061.27$      |
| NF4        | FP16          | False        | 64         | $59.04$ | $361.19$       |
| NF4        | FP16          | False        | 128        | $58.78$ | $352.65$       |
| AWQ-q4     | FP16          | N/A          | 128        | $59.76$ | $377.72$       |
| GPTQ-q4    | FP16          | N/A          | 128        | $59.30$ | $251.72$       |

5-shot C-Eval：

| Quant Type | Compute Dtype | Double Quant | Group Size | Avg (%) | Total Time (s) |
| ---------- | ------------- | ------------ | ---------- | ------- | -------------- |
| BF16       | BF16          | N/A          | N/A        | $47.47$ | -              |
| INT8       | BF16&INT8     | N/A          | N/A        | $48.29$ | $683.67$       |
| FP4        | FP16          | False        | 64         | $46.21$ | $292.20$       |
| FP4        | FP16          | True         | 64         | $46.21$ | $292.51$       |
| FP4        | FP32          | False        | 64         | $46.21$ | $874.55$       |
| NF4        | FP16          | False        | 64         | $45.76$ | $299.82$       |
| NF4        | FP16          | False        | 128        | $44.13$ | $298.83$       |
| AWQ-q4     | FP16          | N/A          | 128        | $46.35$ | $345.56$       |
| GPTQ-q4    | FP16          | N/A          | 128        | $45.98$ | $214.87$       |

同时，也简单记录了量化对模型推理速度的影响：

| Quant Type | Compute Dtype | Batch Size | Input (tokens) | Output (tokens) | First Token (ms) | Non-first Token (ms) |
| ---------- | ------------- | ---------- | -------------- | --------------- | ---------------- | -------------------- |
| BF16       | BF16          | 1          | 128            | 128             | $38.5$           | $22.0$               |
| BF16       | BF16          | 8          | 128            | 128             | $242$            | $25.9$               |
| INT8       | BF16&INT8     | 1          | 128            | 128             | $193$            | $88.6$               |
| INT8       | BF16&INT8     | 8          | 128            | 128             | $403$            | $101$                |
| NF4        | FP16          | 1          | 128            | 128             | $69.3$           | $15.2$               |
| NF4        | FP16          | 8          | 128            | 128             | $270$            | $56.8$               |

> 4-bit 当 batch size 为 1 时，会使用性能更好的 `gemv` 算子，速度较快。

## BF16 Inference

Mistral-7B 是一个很强的 7B 开源模型，在 Mistral [官网](https://mistral.ai/news/announcing-mistral-7b/)和[论文](https://arxiv.org/abs/2310.06825)中声称可以在 5-shot MMLU 上达到 **60.1%** 的准确率，首先下载官方的模型权重文件（[Mistral-7B-v0.1](https://huggingface.co/mistralai/Mistral-7B-v0.1/tree/main)）并直接在原精度（`BF16`）上进行推理，尝试复现出官方的准确率。

### llmtask

这里使用 [llmtask](https://github.com/SlightwindSec/LLM-Task) 来进行下游任务测试，非常方便快捷，只需要

```shell
pip install llmtask==0.0.2
```

即可完成安装，可以直接测试模型在 [C-Eval](https://cevalbenchmark.com/) 和 [MMLU](https://paperswithcode.com/sota/multi-task-language-understanding-on-mmlu) 数据集上的表现。

示例代码：

```python
import random

from llmtask import TaskGenerator

choices = ("A", "B", "C", "D")

TG = TaskGenerator("mmlu", max_shot=4)

for task in TG:
    TG.feedback(random.choice(choices))

print(TG.summary())
```

测试 Mistral-7B 原精度推理脚本：

```python
import time

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from llmtask import TaskGenerator


def log(msg):
    with open("mmlu_5shot_bf16.log", "a") as f:
        f.write(f"{msg}\n")

device = "cuda"

model = AutoModelForCausalLM.from_pretrained("/path/to/Mistral-7B-v0.1", torch_dtype=torch.bfloat16).to(device)
tokenizer = AutoTokenizer.from_pretrained("/path/to/Mistral-7B-v0.1")

cnt = 0
TG = TaskGenerator("mmlu", max_shot=5)
for task in TG:
    model_inputs = tokenizer([task], return_tensors="pt").to(device)
    input_tokens = len(model_inputs['input_ids'][0])
    t0 = time.time()
    generated_ids = model.generate(**model_inputs, max_new_tokens=1, pad_token_id=tokenizer.eos_token_id)
    ans = tokenizer.batch_decode([generated_ids[0][input_tokens:]])[0]
    log(f"[{cnt:5}] [{(time.time() - t0):5.3f} s] => ans:{ans}")
    cnt += 1
    TG.feedback(ans)
    log(TG.summary())
    torch.cuda.empty_cache()
```

测试结果如下（每次只推理一个 Token 作为模型选择的答案，很快就可以测试完成）：

| Precision | Avg (%) | STEM (%) | Social Science (%) | Humanities (%) | Other (%) | Total Time (s) |
| :-------: | :-----: | :------: | :----------------: | :------------: | :-------: | :------------: |
| **BF16**  | $61.00$ | $50.46$  |      $75.07$       |    $53.47$     |  $68.16$  |    $312.79$    |

平均每道题耗时 $204$ms，最后的测试结果还算比较接近官方的结果，以此作为 baseline 和量化后的模型权重对比推理下游任务准确率的损失情况。



## 8-bit/4-bit Quantization

量化使用 transformers 内置的 bitsandbytes 提供的`LLM.int8()`作为`8-bit`量化算法（`threshold=6.0`），`4-bit`量化包含两种`4-bit`的数据类型`FP4`和`NF4`，以及`torch.float32`和`torch.float16`两种计算类型，接下来分别对这些场景进行测试。

### 8-bit

进行`8-bit`推理只需要修改加载权重的这一行即可：

> 虽然官方已经不推荐这样做了，但是这里不需要在`BitsAndBytesConfig`配置额外的参数，可以直接这样使用默认参数。

```python
model = AutoModelForCausalLM.from_pretrained("/path/to/Mistral-7B-v0.1", load_in_8bit=True)
```

`8-bit`量化后平均每道题耗时 $401$ms，测试结果如下：

| Precision | Avg (%) | STEM (%) | Social Science (%) | Humanities (%) | Other (%) | Total Time (s) |
| :-------: | :-----: | :------: | :----------------: | :------------: | :-------: | :------------: |
| **INT8**  | $60.87$ | $51.09$  |      $73.59$       |    $52.89$     |  $69.29$  |    $614.43$    |

### 4-bit

通过`BitsAndBytesConfig`来配置量化类型（`FP4`/`NF4`）测试脚本： 

```python
import time

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from llmtask import TaskGenerator


def log(msg):
    with open("mmlu_5shot_fp4_fp16.log", "a") as f:
        f.write(f"{msg}\n")

device = "cuda"

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_quant_type="fp4",
    bnb_4bit_use_double_quant=False,
    bnb_4bit_quant_storage=torch.uint8
)

model = AutoModelForCausalLM.from_pretrained("/path/to/Mistral-7B-v0.1", quantization_config=bnb_config)
tokenizer = AutoTokenizer.from_pretrained("/path/to/Mistral-7B-v0.1")

TG = TaskGenerator("mmlu", max_shot=5)
cnt = 0
for task in TG:
    model_inputs = tokenizer([task], return_tensors="pt").to(device)
    input_tokens = len(model_inputs['input_ids'][0])
    t0 = time.time()
    generated_ids = model.generate(**model_inputs, max_new_tokens=1, pad_token_id=tokenizer.eos_token_id)
    ans = tokenizer.batch_decode([generated_ids[0][input_tokens:]])[0]
    log(f"[{cnt:5}] [{(time.time() - t0):5.3f} s] => ans:{ans}")
    cnt += 1
    TG.feedback(ans)
    log(TG.summary())
    torch.cuda.empty_cache()
```

下面是改变其中某个参数后在 MMLU 数据集上的准确率，可以看出即使是`4-bit`对准确率影响都没有很大，首 Token 性能还可以接近原精度，还节省了大量的空间。

| Quant Type | Compute Dtype | Double Quant | Avg (%) | Total Time (s) |
| ---------- | ------------- | ------------ | ------- | -------------- |
| **FP4**    | **FP16**      | **False**    | $59.37$ | $347.00$       |
| FP4        | FP16          | **True**     | $59.17$ | $353.22$       |
| FP4        | **FP32**      | False        | $59.50$ | $1061.27$      |
| **NF4**    | FP16          | False        | $59.04$ | $361.19$       |

> 在对显卡进行清灰并更换导热硅脂后，我重新测试了`FP4-FP16-False` 和 `FP4-FP16-True` 这两组，分别只需要 $340.66$s 和 $343.25$s 就完成了推理，相比之前分别快了 $6.34$s 和 $9.97$s。



## Versions

| Python Packages | Version |
| :-------------- | :------ |
| torch           | 2.2.1   |
| transformers    | 4.39.1  |
| bitsandbytes    | 0.43.0  |
| accelerate      | 0.28.0  |
| llmtask         | 0.0.2   |

