---
title: Install SageMath for Apple Silicon M1
date: 2021-10-09 10:00:00
category: "Environment Setup"
tags: ["SageMath", "Apple Silicon M1"]
---

## Install conda

官网上没有直接给出 M1 Mac 版本的 SageMath 二进制安装文件，不过给出了使用 conda 安装 Sage 的方法，参考[Install from conda-forge](https://doc.sagemath.org/html/en/installation/conda.html)。

所以如果自己的 Mac 上还没有安装 conda 的话，可以先安装一下，然后使用 conda 安装 SageMath。

首先下载[Miniforge3-MacOSX-arm64.sh]()，cd 进入`Miniforge3-MacOSX-arm64.sh`所在的目录。

```bash
bash Miniforge3-MacOSX-arm64.sh
```

接着一路回车，直到确认条款：

```bash
Do you accept the license terms? [yes|no]  
[no] >>> yes
```

然后编辑配置文件`vim ~/.zshrc`，在最下面加入如下内容：

```
path=('/Users/「这里替换成Mac用户名」/miniforge3/bin' $path)  
export PATH
```

`:wq`保存并退出，然后`source ~/.zshrc`，`conda info`应该就可以看到了，到这里 conda 安装完成。

在终端输入下面这些，给 conda 换到清华源，这样在使用国内网络不走代理的情况下安装一些东西就更快了：

```bash
conda config --add channels https://mirrors.ustc.edu.cn/anaconda/pkgs/main/  
conda config --add channels https://mirrors.ustc.edu.cn/anaconda/pkgs/free/  
conda config --add channels https://mirrors.ustc.edu.cn/anaconda/cloud/conda-forge/  
conda config --add channels https://mirrors.ustc.edu.cn/anaconda/cloud/msys2/  
conda config --add channels https://mirrors.ustc.edu.cn/anaconda/cloud/bioconda/  
conda config --add channels https://mirrors.ustc.edu.cn/anaconda/cloud/menpo/  
conda config --set show_channel_urls yes
```

然后输入`conda config --show | grep https`可以看到已经更新成功的上面的链接。

> 如果是直接新开的终端，直接输入conda是没有反应的，需要先`source ~/.zshrc`一下。

## Install SageMath

```bash
conda config --append channels conda-forge
conda config --set channel_priority strict
conda create -n sage sage python=3.9

# Proceed ([y]/n)? y
# 然后就开始下载安装了
```

这时输入`conda activate sage`，然后输入`sage`就可以看到sage启动了，也可以使用`sage xxx.sage`来执行一个sage脚本，这样就是安装完成了。

> 注意每次都要先`vim ~/.zshrc`进入conda，然后`conda activate sage`进入sage。

<hr>

Mentioned files | - | - 
--|:--:|:--:
Miniforge3-MacOSX-arm64.sh | - | [腾讯微云](https://share.weiyun.com/BbrjO45U)
