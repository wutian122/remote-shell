# 预置枚举脚本

以下脚本可直接用于 `telnet_execute.py script -f` 命令。
将所需内容保存为 `.txt` 文件，每行一条命令，`#` 开头为注释。

## 系统信息枚举 (enum_system.txt)

```
uname -a
cat /proc/version
cat /proc/cpuinfo
cat /proc/meminfo
hostname
cat /etc/hostname
cat /etc/issue
cat /etc/*release*
uptime
id
whoami
groups
```

## 网络配置枚举 (enum_network.txt)

```
ifconfig -a
cat /etc/network/interfaces
cat /etc/resolv.conf
route -n
netstat -tulpn
iptables -L -n -v 2>/dev/null
arp -n
```

## 安全评估枚举 (enum_security.txt)

```
cat /etc/passwd
cat /etc/shadow 2>/dev/null
cat /etc/group
sudo -l 2>/dev/null
cat /etc/sudoers 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
find / -perm -2 -type f 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -name "*.key" 2>/dev/null
find / -name "*password*" -type f 2>/dev/null
grep -r "password" /etc/ 2>/dev/null
crontab -l 2>/dev/null
ls -la /etc/cron*
```

## 文件系统枚举 (enum_files.txt)

```
ls -la /
mount
cat /proc/mounts
df -h
ls -la /etc/
ls -la /tmp/
ls -la /var/log/
find /etc/ -type f -readable 2>/dev/null
ls -la /etc/nginx/ 2>/dev/null
ls -la /etc/apache2/ 2>/dev/null
ls -la /var/www/ 2>/dev/null
cat /proc/mtd 2>/dev/null
cat /proc/partitions
```

## 使用方法

将上述内容保存后使用：

```bash
python scripts/telnet_execute.py script -H 192.168.1.100 --port 2222 -f enum_system.txt --logfile /tmp/enum.log
```
