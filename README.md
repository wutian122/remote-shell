# Remote Shell Skill

这是一个为 Trae IDE (及其他兼容 AI 代理) 设计的 **Remote Shell** 技能包。它提供了一套安全、统一的远程操作接口，支持 SSH、SFTP、Telnet 和 WinRM 协议。

## 🌟 核心功能

- **多协议支持**：
  - **SSH**：针对 Linux/Unix 系统的命令执行与脚本运行。
  - **SFTP**：高效的文件上传、下载及目录管理，内置 MD5 校验。
  - **WinRM**：针对 Windows 远程管理（PowerShell/CMD）。
  - **Telnet**：针对 IoT、BusyBox 及嵌入式设备的交互式会话。
- **安全拦截器**：内置危险命令识别与审计日志，防止意外破坏。
- **配置中心**：支持 JSON 配置文件及环境变量覆盖。
- **结构化输出**：所有操作均返回标准的 JSON 格式，便于 AI 解析。

## 📂 目录结构

该项目遵循 `skill-creator` 规范组织：

- `SKILL.md`：AI 触发与使用的核心指令文件。
- `agents/`：包含 UI 元数据配置 (`openai.yaml`)。
- `scripts/`：核心 Python 执行脚本与配置文件。
- `references/`：进阶使用指南与协议细节文档。
- `LICENSE`：采用 Apache-2.0 开源许可证。

## 🚀 快速开始

### AI 代理使用
如果你是在 Trae IDE 中使用此技能，AI 代理会自动读取 `SKILL.md` 并根据你的指令选择合适的脚本执行。

### 手动安装与使用
1. 克隆仓库：
   ```bash
   git clone https://github.com/wutian122/remote-shell.git
   ```
2. 安装依赖：
   根据需要安装 `asyncssh`, `pywinrm`, `pexpect` 等 Python 库。
3. 执行示例：
   ```bash
   python scripts/ssh_execute.py execute -H <host> -u <user> -c "uname -a"
   ```

## 🛡️ 安全说明
默认情况下，所有修改类操作（如 `rm`, `stop`, `reboot` 等）都会被安全拦截器拦截。如需执行，请确保在命令中追加 `--auto-confirm` 参数（或通过 AI 代理请求用户确认）。

## 📄 许可证
本项目采用 [Apache-2.0](LICENSE) 许可证开源。
