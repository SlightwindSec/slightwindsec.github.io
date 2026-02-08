---
title: Install OpenSSL and GmSSL on Win32
date: 2021-12-08 21:34:16
category: "Environment Setup"
tags: ["SSL", "OpenSSL", "GmSSL"]
---

由于参与了一个在 PLC 和上位机之间建立加密信道的项目，需要在PLC的Win7-32bit系统中安装OpenSSL和GmSSL，因为PLC硬盘太小，所以我实际上是在虚拟机里面进行的编译。

## OpenSSL

一开始是打算编译一下的，下载了OpenSSL的源码，OpenSSL的Configure是依赖Perl的。然后下载安装了[Strawberry Perl for win32](https://strawberryperl.com/)，然后发现会出现各种报错，一番搜索了解到需要安装ActivePerl：


> [Install ActivePerl and remove Stawberry Perl as it is not compatible with openssl.](https://stackoverflow.com/questions/34752186/cannot-find-lcrypto-lssl-with-openssl-on-windows-with-mingw)

但是ActivePerl的官网只提供64bit的版本，安装32bit版本的ActivePerl需要支付$912/yr：

> The site states: "if you need 32-bit or other older/legacy versions, they are available through our new ActiveState Platform by subscribing to at least Team Tier. See pricing here."

这就很难搞，只能去下载安装现成的二进制文件：http://slproweb.com/products/Win32OpenSSL.html

## GmSSL

GmSSL官方的[编译与安装](http://gmssl.org/docs/install.html)教程虽然字数不多但是很有帮助，编译过程比较顺利。

虽然也提及要用ActivePerl，但是我在对Configure进行了一点简单修改之后，用Strawberry Perl也可以成功运行`perl Configure VC-WIN32`。

直接运行`perl Configure VC-WIN32`会遇到报错：`"glob" is not exported by the File::Glob module`。

分别在`Configure`和`test/build.info`两个文件中，把：

```bash
use if $^O ne "VMS", 'File::Glob' => qw/glob/;
```

修改为：

```bash
use if $^O ne "VMS", 'File::Glob' => qw/:glob/;
```

就可以了，接下来如果不是在Visual Studio中直接`make`，会报错缺少`stddef.h`，这时需要启动VS中的CMD来进行编译，我的版本是VS Community 2017，需要手动配置一下VS的命令行环境。

#### 在Visual Studio中配置命令行环境

可以参考https://blog.csdn.net/u013553529/article/details/77417058

`工具(T)` -> `外部工具(E)...` -> `添加(A)` -> 

|        |                 |      |
|   :--: |       ----       | ---- |
| 标题:    | `Terminal`                    | 自定义，设置好会显示在`工具(T)`下拉框中    |
| 命令:    | `C:\Windows\System32\cmd.exe` | `cmd.exe`的绝对路径     |
| 参数:    | `/k "C:\Program Files\Microsoft Visual Studio\2017\Common7\Tools\VsDevCmd.bat"` | 英文引号中是`VsDevCmd.bat`的绝对路径 |
| 初始目录: | `$(ProjectDir)` | 自定义，打开cmd时的初始目录 |

-> `确定`

配置完成之后，就可以通过`工具(T)`->`Terminal`来打开cmd，这时再进入GmSSL的目录下就可以make了，遇到了新的报错：无法解析的外部符号 EVP_get_ciphernames，这个问题在https://github.com/guanzhi/GmSSL/issues/1037 有提到解决方法，定位到`EVP_get_ciphernames`和`EVP_get_digestnames`，并把它们注释掉即可。

```cpp
/*
char *EVP_get_ciphernames(int aliases);
char *EVP_get_digestnames(int aliases);
*/
```
现在就可以畅通无阻的`make`、`make install`了。

### 配置环境变量

命令行调用gmssl环境变量：

右键`计算机`->`属性`->`高级系统设置`->`环境变量`->系统变量`Path`->`编辑`->添加`C:\Program Files\GmSSL\bin;`->`确定`->`确定`->`确定`

gcc/g++编译环境变量：

|      变量           |        值                         |         备注        |
| :--                |       ----                        |         ----       |
| PATH               | `C:\Program Files\GmSSL\bin;`     | 命令行可执行文件      |
| LIBRARY_PATH       | `C:\Program Files\GmSSL\lib;`     | 编译时调用的lib      |
| C_INCLUDE_PATH     | `C:\Program Files\GmSSL\include;` | C程序`#include<>`   |
| CPLUS_INCLUDE_PATH | `C:\Program Files\GmSSL\include;` | C++程序`#include<>` |

编译时参数`-lcrypto`一直不能用，结果在`C:\Program Files\GmSSL\lib`中把`libcrypto.lib`重命名为`crypto.lib`后成功解决，可以正常编译包含gmssl的c/cpp程序。