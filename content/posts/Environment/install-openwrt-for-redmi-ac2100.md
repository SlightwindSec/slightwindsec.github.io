---
title: Install OpenWrt for Redmi Router AC2100
date: 2021-10-10 18:38:00
category: "Hardware"
tags: ["Router", "OpenWrt", "Wi-Fi"]
---

## Get shell

小米路由器后台管理页面是不给我们上传并且刷入新固件的，所以要先拿到 shell，ssh 连上路由器就可以往里面刷入新固件了。

先正常启动路由器，并进入路由器后台管理页面，这时可以在浏览器的地址栏看到自己路由器的内网 IP，和自己的 stok，例如我的开头是：

```
http://10.161.145.162/cgi-bin/luci/;stok=e9974e290dd74c4683328c5a5876308b/...
```

我的路由器 IP 是`10.161.145.162`，stok的值为`e9974e290dd74c4683328c5a5876308b`，现在把下面的链接替换成自己的，然后 Enter，浏览器返回`0`说明这一步可以了。

```
http://「这里替换IP」/cgi-bin/luci/;stok=「stok的值」/api/misystem/set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=-h%3B%20nvram%20set%20ssh_en%3D1%3B%20nvram%20commit%3B%20sed%20-i%20's%2Fchannel%3D.*%2Fchannel%3D%5C%22debug%5C%22%2Fg'%20%2Fetc%2Finit.d%2Fdropbear%3B%20%2Fetc%2Finit.d%2Fdropbear%20start%3B
```

然后下面这个链接也是一样的操作，同样应该返回`0`：

```
http://「这里替换IP」/cgi-bin/luci/;stok=「stok的值」/api/misystem/set_config_iotdev?bssid=Xiaomi&user_id=longdike&ssid=-h%3B%20echo%20-e%20'12345678%5Cn12345678'%20%7C%20passwd%20root%3B
```

如果这两个链接都成功返回了`0`，那么就可以使用习惯的工具去 ssh 连接路由器了：

```bash
ssh root@「这里替换IP」
# passwd 12345678
```

不出意外，这边是可以连接到路由器的 shell 的，然后可以看到字符画显示的`are you ok`。

## 上传并刷入固件

前面拿到了 shell，现在可以上传固件了，首先下载[openwrt-RM2100-kernel1.bin](https://share.weiyun.com/J8SYbS7U)和[openwrt-RM2100-rootfs0.bin](https://share.weiyun.com/FOFPmjbr)，然后 cd 进入这两个文件所在的目录，用 SCP 传到路由器上。

```bash
# 把openwrt的固件通过SCP上传到路由器的/tmp目录下
scp openwrt-RM2100-kernel1.bin root@「这里替换IP」:/tmp
scp openwrt-RM2100-rootfs0.bin root@「这里替换IP」:/tmp
```

然后 ssh 连接上路由器，开始刷入固件：

```bash
# 进入/tmp目录下
cd /tmp

mtd write openwrt-RM2100-kernel1.bin kernel1
nvram set uart_en=1
nvram set bootdelay=5
nvram set flag_try_sys1_failed=1
nvram commit
mtd -r write openwrt-RM2100-rootfs0.bin rootfs0
```

等待写入完成，就可以重启路由器了，这个时候路由器的 Wi-Fi 名称变成了 OpenWrt，并且没有密码，可以直接连接，然后用 ssh 连接新的 IP：

```bash
# 用新的IP来ssh连上去，刷完OpenWrt之后，内网IP也会改变
ssh root@192.168.1.1
# 连上之后可以看到：root@OpenWrt:~# 
```

到这里，固件就刷入成功了。路由器管理地址为：`192.168.1.1` 用户名：`root`  密码：`password`

如果现在的固件可以满足使用要求，那么就不需要接着操作了，但是我需要使用路由器上运行一个脚本来自动使用账号密码连接校园网，每当网络断开时再重新去连接，而当前的固件不支持`curl`命令，个人感觉 UI 也不够美观，所以我使用它来写入新的固件，这个固件支持`curl`，也更加美观。

## 刷入新固件

由于最新编译 ROM 较大无法直接通过`telnet`刷入，所以刷完上面 ROM 后需要在路由器管理后台更新最新 OP 固件。

先下载一下[03.10-openwrt-ramips-mt7621-redmi-ac2100-squashfs-sysupgrade.bin](https://share.weiyun.com/VsAhWFO6)固件。

然后登陆`192.168.1.1`后台后点击「`系统`」-「`备份/升级`」-「`刷写新固件（不保留配置）`」-「`上传op固件包`」

选择刚刚下载的 bin 文件进行安装，安装完成后，重启路由器，然后连接上路由器后台就可以了，这里同样要注意，刷入新固件后路由器的IP会改变，最好进电脑的 Wi-Fi 详情里面看一下，我的是变成了 192.168.2.1，ssh 和 web 后台密码都是`password`。

现在就可以在路由器的后台进行一些自己需要的配置操作了。

> 救砖：如果折腾的过程中出现了什么问题，可以使用官方的救砖工具[MIWIFI Repair Tool](https://share.weiyun.com/pDhHZ1pQ)，并刷入官方固件[miwifi_rm2100_firmware_d6234_2.0.7.bin](https://share.weiyun.com/xIFn6CO5)。

<hr>

Mentioned files | - | - 
--|:--:|:--:
openwrt-RM2100-kernel1.bin | [谷歌云盘](https://drive.google.com/file/d/1qY-jqgx9VYpF3jqVIA0QZM8DdFbp356H/view?usp=drive_link) | [腾讯微云](https://share.weiyun.com/J8SYbS7U)
openwrt-RM2100-rootfs0.bin | [谷歌云盘](https://drive.google.com/file/d/1Vx_fmTKOWtmo-ZI68g3uP_0P5HD-mbyd/view?usp=drive_link) | [腾讯微云](https://share.weiyun.com/FOFPmjbr)
03.10-openwrt-ramips-mt7621-redmi-ac2100-squashfs-sysupgrade.bin | [谷歌云盘](https://drive.google.com/file/d/1NC7JMzLJu-Tj66fXaFBWiBmC9CyKjbfu/view?usp=sharing) | [腾讯微云](https://share.weiyun.com/VsAhWFO6)
MIWIFI Repair Tool | [谷歌云盘](https://drive.google.com/file/d/1cocPUd-7Jio7Buh-6II0s1cNx1cqfCK-/view?usp=sharing) | [腾讯微云](https://share.weiyun.com/pDhHZ1pQ)
miwifi_rm2100_firmware_d6234_2.0.7.bin | [谷歌云盘](https://drive.google.com/file/d/1VGSGS55aciqQQZdlOkq2Kz632B1dSLVO/view?usp=sharing) | [腾讯微云](https://share.weiyun.com/xIFn6CO5)

