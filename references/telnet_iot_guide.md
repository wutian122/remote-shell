# Telnet IoT 设备交互指南

## 概述

`telnet_execute.py` 使用 pexpect 实现 Telnet 连接，适用于：
- 标准 Linux 主机的 Telnet 服务
- IoT 设备（BusyBox 嵌入式 Shell）
- 自定义端口的 Telnet 服务（路由器、摄像头等）

## BusyBox 设备特点

大多数 IoT 设备使用 BusyBox 精简 Shell：

```bash
# 检查 BusyBox 版本
busybox | head -1

# 列出可用命令
busybox --list

# 常见可用命令
cat, ls, cd, pwd, echo, cp, mv, rm, mkdir, chmod, chown
ps, kill, top, free, df, mount, ifconfig, route, ping, netstat
grep, find, sed, awk (精简版)
```

**BusyBox 限制**：
- `ps` 输出格式可能与标准 Linux 不同
- 无 Python/Perl/Ruby（存储限制）
- 部分命令选项不可用

## 常见提示符模式

```bash
# 自动检测（默认）
python scripts/telnet_execute.py execute -H 192.168.1.100 -c "uname -a"

# BusyBox Shell：/ # 或 / $
--prompt "/\s*[#\$]"

# 路由器/摄像头：User@device>
--prompt "^User@[^>]+>"

# 通用 root 提示符
--prompt "^[#\$]\s*$"
```

## 设备枚举流程

```bash
# 使用预置枚举脚本
python scripts/telnet_execute.py script -H 192.168.1.100 --port 2222 -f references/enum_system.txt
python scripts/telnet_execute.py script -H 192.168.1.100 --port 2222 -f references/enum_network.txt
python scripts/telnet_execute.py script -H 192.168.1.100 --port 2222 -f references/enum_security.txt
python scripts/telnet_execute.py script -H 192.168.1.100 --port 2222 -f references/enum_files.txt
```

## 会话观察

```bash
# 终端1：启动带日志的会话
python scripts/telnet_execute.py interactive -H 192.168.1.100 --logfile /tmp/session.log

# 终端2：实时观察
tail -f /tmp/session.log
```

## 常见场景

### 无认证 Shell
```bash
python scripts/telnet_execute.py interactive -H 192.168.1.100 --port 2222
```

### 需要登录的设备
通常会自动检测到 `login:` 和 `Password:` 提示符。常见默认凭据：
- root/root、admin/admin、root/（空）

### 受限 Shell 逃逸
```bash
/bin/sh
vi  # 然后 :!/bin/sh
find / -exec /bin/sh \;
awk 'BEGIN {system("/bin/sh")}'
```

## 固件提取

```bash
# 查看 MTD 分区
cat /proc/mtd
# 导出
dd if=/dev/mtd0 of=/tmp/bootloader.bin
# 通过 HTTP 传出
busybox httpd -p 8000 -h /tmp
```

## 故障排查

| 问题 | 解决方案 |
|------|----------|
| Connection refused | 检查 Telnet 服务/端口/防火墙 |
| 输出乱码 | 使用 `--raw` 查看原始输出 |
| 提示符检测失败 | 使用 `--prompt` 指定自定义正则 |
| 命令超时 | 增大 `--timeout` |
