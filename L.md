---
name: remote-shell
description: 安全的 SSH、SFTP、Telnet、WinRM 远程操作技能。用于远程执行命令、批量执行、执行脚本、上传下载文件、获取远程系统信息、列出远程目录、检查 Telnet 端口连通性，以及与 IoT 或 BusyBox 设备交互。遇到 Linux/Unix 主机优先使用 SSH，遇到 Windows 远程管理优先使用 WinRM，遇到 Telnet 设备或 IoT 壳优先使用 Telnet，遇到文件上传下载优先使用 SFTP。
---

# Remote Shell

使用此技能时，先选择协议，再选择操作类型，最后调用对应脚本。默认保持只读；涉及修改、删除、安装、服务启停等危险操作时，先等待用户确认，再追加 `--auto-confirm`。

## 工作流

1. 判断目标环境。
2. 判断操作类型。
3. 调用对应脚本。
4. 解析 JSON 输出。
5. 如果命中安全拦截，停止重试并请求用户确认。

## 协议选择

- 使用 `scripts/ssh_execute.py`：目标是 Linux、Unix、网络设备 SSH 服务，或需要执行命令、批量命令、脚本、系统信息、健康检查。
- 使用 `scripts/file_transfer.py`：目标是 SSH/SFTP 文件上传、下载、目录遍历、文件信息读取。
- 使用 `scripts/winrm_execute.py`：目标是 Windows 主机，或需要通过 WinRM 执行 PowerShell / CMD 命令、脚本、系统检查。
- 使用 `scripts/telnet_execute.py`：目标是 Telnet 服务、IoT、BusyBox、嵌入式设备，或需要交互式会话与端口连通性检查。

## 安全规则

- 默认允许查询类命令，例如 `ls`、`cat`、`pwd`、`whoami`、`hostname`、`Get-Process`。
- 默认拦截修改类命令，例如删除、移动、创建、写文件、安装软件、启停服务、修改用户、修改注册表、重启关机。
- 命中安全拦截时，向用户转述警告并请求明确确认。
- 仅在用户明确回复 `yes`、`同意` 或等价确认后，追加 `--auto-confirm` 重试。
- 文件上传/下载会记录审计日志，但不触发命令级安全拦截（因为文件传输不等同 shell 命令执行）。
- 审计日志默认写入 `audit_remote.log`；如需自定义路径，传入 `--audit-log`。

## 常用命令

```bash
python scripts/ssh_execute.py execute -H <host> -u <user> -c "uname -a"
python scripts/ssh_execute.py batch -H <host> -u <user> -c "pwd,whoami,ls"
python scripts/ssh_execute.py script -H <host> -u <user> --script-file <script.sh>
python scripts/ssh_execute.py sysinfo -H <host> -u <user>
python scripts/ssh_execute.py health -H <host> -u <user>

python scripts/file_transfer.py upload -H <host> -u <user> -l <local> -r <remote>
python scripts/file_transfer.py download -H <host> -u <user> -r <remote> -l <local>
python scripts/file_transfer.py info -H <host> -u <user> --path <remote-path>
python scripts/file_transfer.py ls -H <host> -u <user> --path <remote-dir>
# 远程路径推荐绝对路径；加 --no-md5 禁用校验；-P 指定端口；-k 密钥认证；ls 加 --page/--page-size 分页

python scripts/winrm_execute.py execute -H <host> -u <user> -c "Get-Process"
python scripts/winrm_execute.py batch -H <host> -u <user> -c "hostname,whoami"
python scripts/winrm_execute.py script -H <host> -u <user> --script-file <script.ps1>
python scripts/winrm_execute.py sysinfo -H <host> -u <user>
python scripts/winrm_execute.py health -H <host> -u <user>

python scripts/telnet_execute.py execute -H <host> -c "uname -a"
python scripts/telnet_execute.py batch -H <host> -c "pwd,whoami,ls"
python scripts/telnet_execute.py script -H <host> -f <commands.txt>
python scripts/telnet_execute.py interactive -H <host>
python scripts/telnet_execute.py health -H <host>
```

## 路径规则

- 远程路径推荐使用绝对路径（如 `/home/user/file`），代码会自动展开 `~` 和相对路径。
- 如需确认远程 home 目录，先用 `ssh_execute.py execute -H <host> -u <user> -c "echo $HOME"` 查询。
- 详细参数说明和故障排查见 `references/file_transfer_guide.md`。

## 输出处理

- 读取标准 JSON 输出。
- 以 `success` 判断是否成功。
- 对命令执行结果优先读取 `stdout`、`stderr`、`exit_status`。
- 对安全拦截结果关注 `error_type=SecurityInterceptedError`。
- 对连接失败或依赖缺失结果关注 `error_type` 与 `error` 字段。

## 资源导航

- 需要 SSH 进阶参数、认证与故障排查时，读取 `references/ssh_advanced.md`。
- 需要 Telnet / IoT / BusyBox 特例时，读取 `references/telnet_iot_guide.md`。
- 需要预置枚举命令或脚本思路时，读取 `references/enum_scripts.md`。
- 需要文件传输参数、路径规则与故障排查时，读取 `references/file_transfer_guide.md`。

## 备注

- 默认配置位于 `scripts/config/default.json`。
- 支持使用 `REMOTE_SHELL_*` 环境变量覆盖部分默认值。
- 如需增强解码覆盖面，可设置 `REMOTE_SHELL_EXTRA_ENCODINGS`（逗号/分号分隔），例如：`REMOTE_SHELL_EXTRA_ENCODINGS=big5,shift_jis,euc_kr,koi8-r,cp1251`。
- 保持 `SKILL.md` 精简；将细节放入 `references/`，将可执行逻辑放入 `scripts/`。
