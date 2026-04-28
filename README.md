# remote-shell（Remote Shell 技能项目副本）

本目录是 remote-shell 技能的项目化副本，提供一组可直接运行的脚本，用于对远程主机进行安全的 SSH / SFTP / WinRM / Telnet 操作，包括：命令执行、批量执行、脚本执行、系统信息采集、健康检查、文件上传/下载与目录遍历等。

## 目录结构

- SKILL.md：技能使用说明（在 Trae/Claude 等环境中作为技能入口文档）
- scripts/：可执行脚本与公共模块
- scripts/config/default.json：默认运行配置
- references/：参数说明、故障排查与参考资料

## 运行环境

- Python 3.10+（建议 3.11+）
- Windows / Linux / macOS 均可运行（目标主机协议不同，依赖也不同）

## 依赖安装

脚本采用“按需导入”的方式：只有在使用对应能力时才要求安装相应依赖。

- SSH（命令执行/批量/脚本/系统信息/健康检查）
  - `pip install asyncssh`
- WinRM（Windows 远程执行）
  - `pip install pywinrm`
- Telnet（含交互/IoT 场景）
  - `pip install pexpect`

## 快速使用

### SSH

```bash
python scripts/ssh_execute.py execute -H <host> -u <user> -c "uname -a"
python scripts/ssh_execute.py batch -H <host> -u <user> -c "pwd,whoami,ls"
python scripts/ssh_execute.py script -H <host> -u <user> --script-file <script.sh>
python scripts/ssh_execute.py sysinfo -H <host> -u <user>
python scripts/ssh_execute.py health -H <host> -u <user>
```

### SFTP 文件传输

```bash
python scripts/file_transfer.py upload -H <host> -u <user> -l <local> -r <remote>
python scripts/file_transfer.py download -H <host> -u <user> -r <remote> -l <local>
python scripts/file_transfer.py info -H <host> -u <user> --path <remote-path>
python scripts/file_transfer.py ls -H <host> -u <user> --path <remote-dir>
```

### WinRM

```bash
python scripts/winrm_execute.py execute -H <host> -u <user> -c "Get-Process"
python scripts/winrm_execute.py batch -H <host> -u <user> -c "hostname,whoami"
python scripts/winrm_execute.py script -H <host> -u <user> --script-file <script.ps1>
python scripts/winrm_execute.py sysinfo -H <host> -u <user>
python scripts/winrm_execute.py health -H <host> -u <user>
```

### Telnet

```bash
python scripts/telnet_execute.py execute -H <host> -c "uname -a"
python scripts/telnet_execute.py batch -H <host> -c "pwd,whoami,ls"
python scripts/telnet_execute.py script -H <host> -f <commands.txt>
python scripts/telnet_execute.py interactive -H <host>
python scripts/telnet_execute.py health -H <host>
```

## 全编码自适应（本次更新重点）

脚本对远程输出（stdout/stderr）、本地读取的脚本文件/命令文件等，统一采用“多编码候选 + BOM 识别”的自适应解码策略，避免在 Windows/混合编码环境下出现乱码或解码异常。

默认候选编码包含：

- utf-8 / utf-8-sig
- gb18030 / gbk / cp936
- utf-16 / utf-16-le / utf-16-be
- latin-1（兜底）

你也可以通过环境变量扩展候选编码（逗号或分号分隔）：

```bash
REMOTE_SHELL_EXTRA_ENCODINGS=big5,shift_jis,euc_kr,koi8-r,cp1251
```

另外，脚本入口会对标准输出进行统一编码配置（Windows 下优先使用 UTF-8 并以 backslashreplace 避免崩溃）。

## 安全机制

- 默认只允许查询类命令；删除、写文件、安装软件、启停服务等属于高风险行为，会被安全拦截。
- 只有在明确允许的场景下，才应追加 `--auto-confirm` 绕过拦截并执行危险操作。
- 文件传输会记录审计日志（默认 `audit_remote.log`，可通过 `--audit-log` 自定义）。

## 版本发布

- v0.2.1：修正仓库同步/发布过程中的路径与产物问题（清理误上传的 `__pycache__/*.pyc` 与异常路径条目），并保持全编码自适应能力不变。
- v0.2.0：全编码自适应能力增强（多编码候选、BOM 识别、环境变量扩展编码、标准输出编码配置），覆盖 SSH/WinRM/Telnet/SFTP 全链路输出与文件读取。

