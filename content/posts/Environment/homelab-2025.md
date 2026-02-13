---
title: "2025 HomeLab Setup"
date: 2026-02-13 00:00:00
category: "Environment Setup"
tags: ["HomeLab", "NAS", "RTX5090", "Ubuntu"]
---

## 前言

为了满足在家观看高清影视资源、进行 AI 相关实验、以及尝试 Kaggle 的需求，我搭建了一套多功能 HomeLab 机柜。本文详细记录了整个搭建方案，该方案经过实际使用验证，稳定可靠且使用体验良好。

### 核心优势

1. **高速局域网访问**：延迟低、带宽大，可通过投影仪访问 NAS 观看高清资源
2. **便捷的资源管理**：Windows 服务器挂机下载资源，通过千兆网线直连 NAS 传输（1000Mbps）
3. **灵活的网络代理**：GPU 服务器可方便地使用 Windows 服务器提供的代理服务
4. **低功耗设计**：24/7 运行的设备功耗极低，将预算集中在关键硬件上

### 系统架构

整个 HomeLab 包含三个核心模块：

1. **NAS**：存储影视资源和大文件备份
2. **GPU 服务器**：高性能计算平台（Ubuntu Server + RTX5090），按需开机使用
3. **Windows 服务器**：低功耗中转站，提供下载和代理服务，长时间运行

{{< figure src="/blog/homelab2025/1.svg" darksrc="/blog/homelab2025/1.dark.svg" align=center >}}

### 运行策略

基于功耗和使用频率，三台设备采用差异化的运行策略：

1. **NAS**：24/7 运行，待机功耗低，无需频繁开关机
2. **Windows 服务器**：需要下载资源或使用 GPU 时开机，待机功耗低，即使忘记关机也不必担心电费
3. **GPU 服务器**：功耗较高，仅在需要 GPU 计算时开机

这种分层运行策略在保证使用体验的同时，有效控制了整体功耗和运行成本。

## 一、NAS 存储方案

我选择了成品 NAS 而非基于开源项目（如 TrueNAS、Unraid）自建方案，主要考虑以下因素：

- **稳定可靠**：商用成品 NAS 经过充分验证，稳定性有保障
- **低功耗**：适合 24/7 运行，待机功耗通常在 10-20W
- **易用性**：开箱即用，支持 SSH 访问，具备一定可玩性

对于折腾需求，有 GPU 服务器和 Windows 服务器来满足，NAS 只需要做好存储本职工作即可。

## 二、Windows 中转服务器

这台服务器采用"洋垃圾"配置方案，以极低的成本实现了稳定的 24/7 运行能力。总成本仅 **715.9 元**：

| 配件 | 品牌型号              | 价格 |
| ---- | --------------------- | ---- |
| 主板 | 华南x79               | 230  |
| CPU  | E5-2650 V2，8核16线程 | 45   |
| 内存 | 三星 8GB DDR3 1600M   | 76*2 |
| 硬盘 | 七彩虹120G            | 83   |
| 机箱 |                       | 32.9 |
| 电源 | 长城电源400W          | 173  |

### 核心功能

这台低功耗服务器在 HomeLab 中承担两个关键角色：

1. **下载中转站**：NAS 上的网盘客户端下载速度较慢，在 Windows 上挂机下载后通过千兆网线上传到 NAS，效率更高
2. **网络代理服务**：Windows 平台的代理工具体验更好，GPU 服务器直接使用 Windows 提供的代理服务，配置简单且稳定

## 三、GPU 计算服务器

GPU 服务器是整个 HomeLab 的核心，也是成本最高的部分。

### 硬件配置

以下是完整的硬件清单及价格变化对比：

| 配件 | 品牌型号              | 价格 | 目前价格 (2026.2) |
| ---- | --------------------- | ---- | ---- |
| 显卡 | RTX5090 夜神 32GB       | 27000   | **32599** (<a style="color:red">+20%</a>) |
| 主板 | 华硕ProArt Z790         | 4000  | - |
| CPU  | i5-13600KF         | 1199   | - |
| 内存 | 英睿达D5 4800 32GB *2   | 1381 | **6962**  (<a style="color:red">+404%</a>) |
| 机械硬盘 | 西数 8TB            | 1352 | **3657** (<a style="color:red">+170%</a>) |
| 固态硬盘 | 三星980 Pro 2TB | 1026 | **3399** (<a style="color:red">+151%</a>) |
| 机箱 | 开放式机架 | 127 | - |
| 电源 | 长城电源1200W       | 864 | **769** (<a style="color:green">-11%</a>) |
| 风扇 | 机箱风扇/CPU散热等 | 335 | - |
| 汇总 | - | 37284 | 53047 (<a style="color:red">+42%</a>) |


### 1. GPU 选型

预算主要分配给显卡。i5-13600KF 有 20 条 PCIe 通道，4 条给 NVMe，剩下 16 条给显卡，主板支持单卡 x16 或双卡 x8+x8。

选显卡比较纠结：

**2080Ti 22GB 魔改版** — 1000 多块钱性价比爆棚，但魔改卡感觉不太靠谱，万一翻车维修麻烦。

**双 3090 24GB** — 48GB 显存挺大，性能也很不错，但拆过的二手卡用它长时间满载总担心它温度过高或者出其他问题。轻度使用了一年，后来还是换掉了。

**RTX 5090 32GB** — 最后上了新卡，稳定可靠，性能强劲，就是 27000 块比较贵，但单卡性能强，支持 Blackwell 架构和 FP8/FP4。

### 2. 主板与 CPU 选择

服务器平台多一些 PCIe 通道，但预算内只能买到低主频的二手 CPU，单线程性能拉胯，~~开个 MC 服务器都卡~~，不太划算。

最后选了消费级平台：**i5-13600KF**（6 个 P-Core 最高 5.1 GHz + 8 个 E-Core）配 **华硕 ProArt Z790**。这块主板虽然贵点，但稳定性好，扩展性也不错，支持 PCIe 4.0 拆分。

### 3. 机箱方案

最终选择开放式机架方案：

| 方案 | 优点 | 缺点 | 是否采用 |
|------|------|------|----------|
| 塔式机箱 | 常见、易搬运 | 需自行规划风道，空间利用率一般 | ❌ |
| 刀片机箱 | 适合数据中心显卡 | 暴力风扇噪音大，体积大，单卡空间浪费 | ❌ |
| 开放式机架 | 散热优秀，空间灵活 | 易落灰 | ✅ |

**开放式机架优化方案**：
- 将机架放置在封闭机柜内，起到一定防尘作用
- 复用机柜通风系统，无需额外机箱风扇
- 消费级显卡自带三风扇主动散热，无需依赖机箱风道

## 四、GPU 服务器环境配置

### 系统选择

使用 **Ubuntu 24.04.2 LTS**，Ubuntu 22.04 可能存在驱动兼容性问题。

### 1. 安装 NVIDIA 驱动

首先配置好系统代理（http/https），然后添加显卡驱动 PPA 源：

```bash
sudo -E add-apt-repository ppa:graphics-drivers/ppa -y
```

安装开源版本驱动（推荐用于 RTX 5090）：

```bash
sudo apt install nvidia-driver-570-open
```

### 2. 安装 CUDA Toolkit 12.8

按照以下步骤安装 CUDA 工具链：

```bash
# 下载并配置 CUDA 源
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-ubuntu2404.pin
sudo mv cuda-ubuntu2404.pin /etc/apt/preferences.d/cuda-repository-pin-600

# 下载本地安装包
wget https://developer.download.nvidia.com/compute/cuda/12.8.0/local_installers/cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb

# 安装 CUDA 仓库
sudo dpkg -i cuda-repo-ubuntu2404-12-8-local_12.8.0-570.86.10-1_amd64.deb
sudo cp /var/cuda-repo-ubuntu2404-12-8-local/cuda-*-keyring.gpg /usr/share/keyrings/

# 更新并安装 CUDA Toolkit
sudo apt-get update
sudo apt-get -y install cuda-toolkit-12-8
```

安装完成后，`nvcc` 编译器位于 `/usr/local/cuda-12.8/bin/nvcc`。

### 3. 安装 PyTorch

安装支持 CUDA 12.8 的 PyTorch：

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu128
```

## 总结

本文详细介绍了一套成本优化、功能完整的 HomeLab 搭建方案：

- **NAS**：存储中枢，24/7 低功耗运行，承载影视资源和文件备份
- **Windows 服务器**：低成本中转站（715.9 元），提供下载和代理服务
- **GPU 服务器**：高性能计算平台（37284 元），RTX 5090 + i5-13600KF + 64GB DDR5，专注深度学习任务

整套方案通过**分层架构**和**差异化运行策略**，在满足高性能计算、高清媒体存储、便捷资源下载等多元化需求的同时，有效控制了整体功耗和运行成本。
