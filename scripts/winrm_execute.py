#!/usr/bin/env python3
"""WinRM 命令执行脚本。"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from common import (
    dump_json,
    format_error,
    get_config_value,
    get_logger,
    get_password_interactive,
    load_runtime_config,
    load_script_content,
    split_commands,
)
from exceptions import DependencyUnavailableError, SecurityInterceptedError
from security_interceptor import enforce_security

LOGGER = get_logger("remote_shell.winrm")


def get_winrm() -> Any:
    """惰性导入 pywinrm。"""
    try:
        import winrm
    except ImportError as exc:  # pragma: no cover - 依赖外部环境
        raise DependencyUnavailableError("缺少 pywinrm 库，请执行: pip install pywinrm") from exc
    return winrm


class SessionPool:
    """简单的 WinRM 会话池。"""

    _sessions: dict[str, Any] = {}
    MAX_SESSIONS = 20

    @classmethod
    def get_session(
        cls,
        host: str,
        port: int,
        username: str,
        password: str | None,
        auth: str,
        transport: str,
        cert_verify: bool,
    ) -> Any:
        winrm = get_winrm()
        key = f"{host}:{port}:{username}:{auth}:{transport}"
        if key in cls._sessions:
            return cls._sessions[key]
        if len(cls._sessions) >= cls.MAX_SESSIONS:
            raise RuntimeError("SessionPoolExhausted: WinRM 会话池已满 (超过20个)")

        url = f"{transport}://{host}:{port}/wsman"
        session = winrm.Session(
            url,
            auth=(username, password or ""),
            transport=auth,
            server_cert_validation="validate" if cert_verify else "ignore",
        )
        cls._sessions[key] = session
        return session


def infer_shell(command: str, requested_shell: str) -> str:
    """自动推断 shell 类型。"""
    if requested_shell in {"ps", "powershell"}:
        return "ps"
    if requested_shell == "cmd":
        return "cmd"

    ps_keywords = [
        "Get-",
        "Set-",
        "Invoke-",
        "Out-",
        "$",
        "| Select",
        "Where-Object",
        "Write-Host",
    ]
    for keyword in ps_keywords:
        if keyword in command:
            return "ps"
    return "cmd"


def run_winrm_cmd(session: Any, command: str, shell: str) -> dict[str, Any]:
    """根据 shell 类型执行命令并返回标准结果。"""
    try:
        response = session.run_ps(command) if shell == "ps" else session.run_cmd(command)
        return {
            "success": True,
            "exit_status": response.status_code,
            "stdout": response.std_out.decode("utf-8", errors="replace").strip(),
            "stderr": response.std_err.decode("utf-8", errors="replace").strip(),
        }
    except Exception as exc:
        error_type = "WinRMAuthError" if "401" in str(exc) else type(exc).__name__
        return format_error(exc, logger=LOGGER, error_type=error_type)


def execute_command(
    host: str,
    port: int,
    username: str,
    command: str,
    password: str | None = None,
    auth: str = "ntlm",
    transport: str = "http",
    cert_verify: bool = False,
    shell: str = "auto",
    auto_confirm: bool = False,
    audit_log: str = "audit_remote.log",
) -> dict[str, Any]:
    """执行单条 WinRM 命令。"""
    enforce_security(command, host, username, auto_confirm, audit_log)
    try:
        session = SessionPool.get_session(
            host, port, username, password, auth, transport, cert_verify
        )
        actual_shell = infer_shell(command, shell)
        result = run_winrm_cmd(session, command, actual_shell)
        result["host"] = host
        result["command"] = command
        result["shell"] = actual_shell
        return result
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host, command=command)


def execute_batch(
    host: str,
    port: int,
    username: str,
    commands: list[str],
    password: str | None = None,
    auth: str = "ntlm",
    transport: str = "http",
    cert_verify: bool = False,
    shell: str = "auto",
    auto_confirm: bool = False,
    audit_log: str = "audit_remote.log",
) -> list[dict[str, Any]]:
    """批量执行 WinRM 命令。"""
    try:
        session = SessionPool.get_session(
            host, port, username, password, auth, transport, cert_verify
        )
    except Exception as exc:
        return [format_error(exc, logger=LOGGER, host=host)]

    results: list[dict[str, Any]] = []
    for command in commands:
        enforce_security(command, host, username, auto_confirm, audit_log)
        actual_shell = infer_shell(command, shell)
        result = run_winrm_cmd(session, command, actual_shell)
        result["command"] = command
        result["shell"] = actual_shell
        results.append(result)
    return results


def execute_script(
    host: str,
    port: int,
    username: str,
    script: str,
    password: str | None = None,
    auth: str = "ntlm",
    transport: str = "http",
    cert_verify: bool = False,
    shell: str = "ps",
    auto_confirm: bool = False,
    audit_log: str = "audit_remote.log",
) -> dict[str, Any]:
    """执行 WinRM 脚本。"""
    enforce_security(script, host, username, auto_confirm, audit_log)
    try:
        session = SessionPool.get_session(
            host, port, username, password, auth, transport, cert_verify
        )
        actual_shell = infer_shell(script, shell)
        result = run_winrm_cmd(session, script, actual_shell)
        result["host"] = host
        result["script_len"] = len(script)
        result["shell"] = actual_shell
        return result
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host)


def get_system_info(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    auth: str = "ntlm",
    transport: str = "http",
    cert_verify: bool = False,
) -> dict[str, Any]:
    """获取 Windows 系统信息。"""
    commands = {
        "hostname": "hostname",
        "os_release": "(Get-CimInstance Win32_OperatingSystem).Caption",
        "uptime": "(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime",
        "whoami": "whoami",
    }
    try:
        session = SessionPool.get_session(
            host, port, username, password, auth, transport, cert_verify
        )
        info: dict[str, Any] = {"success": True, "host": host}
        for key, command in commands.items():
            result = run_winrm_cmd(session, command, "ps")
            info[key] = result["stdout"] if result["success"] else "Error"
        return info
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host)


def health_check(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    auth: str = "ntlm",
    transport: str = "http",
    cert_verify: bool = False,
) -> dict[str, Any]:
    """执行 WinRM 健康检查。"""
    try:
        session = SessionPool.get_session(
            host, port, username, password, auth, transport, cert_verify
        )
        result = run_winrm_cmd(session, "echo ok", "cmd")
        if result["success"] and "ok" in result["stdout"]:
            return {"success": True, "host": host, "status": "connected"}
        return {
            "success": False,
            "host": host,
            "status": "failed",
            "detail": result.get("stderr"),
        }
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host, status="failed")


def build_parser(config: dict[str, Any]) -> argparse.ArgumentParser:  # pragma: no cover - CLI wrapper
    """构建 CLI 解析器。"""
    winrm_config = get_config_value(config, "winrm")
    audit_log = str(get_config_value(config, "audit_log"))

    parser = argparse.ArgumentParser(description="Remote Shell - WinRM 命令执行工具")
    sub = parser.add_subparsers(dest="action", help="可用操作")

    def common(parser_obj: argparse.ArgumentParser) -> None:
        parser_obj.add_argument("--host", "-H", required=True, help="目标主机")
        parser_obj.add_argument(
            "--port",
            "-P",
            type=int,
            default=int(winrm_config["port"]),
            help="WinRM 端口",
        )
        parser_obj.add_argument("--user", "-u", required=True, help="用户名")
        parser_obj.add_argument("--password", "-p", help="密码")
        parser_obj.add_argument(
            "--auth",
            default=str(winrm_config["auth"]),
            choices=["ntlm", "kerberos", "basic"],
            help="认证协议",
        )
        parser_obj.add_argument(
            "--transport",
            default=str(winrm_config["transport"]),
            choices=["http", "https"],
            help="传输协议",
        )
        parser_obj.add_argument(
            "--cert-verify",
            action="store_true",
            help="启用远端证书校验(默认忽略)",
        )
        parser_obj.add_argument(
            "--shell-type",
            default=str(winrm_config["shell_type"]),
            choices=["auto", "cmd", "ps", "powershell"],
            help="执行环境",
        )
        parser_obj.add_argument(
            "--auto-confirm",
            action="store_true",
            help="跳过安全拦截并强制执行(必须已获用户确认)",
        )
        parser_obj.add_argument("--audit-log", default=audit_log, help="审计日志路径")

    execute_parser = sub.add_parser("execute", aliases=["exec", "run"], help="执行单条命令")
    common(execute_parser)
    execute_parser.add_argument("--command", "-c", required=True, help="命令")

    batch_parser = sub.add_parser("batch", help="批量执行")
    common(batch_parser)
    batch_parser.add_argument("--commands", "-c", required=True, help="逗号或换行分隔命令")

    script_parser = sub.add_parser("script", help="执行脚本")
    common(script_parser)
    script_parser.add_argument("--script-file", "-f", help="脚本文件")
    script_parser.add_argument("--script", "-s", help="脚本内容")

    sysinfo_parser = sub.add_parser("sysinfo", aliases=["info"], help="系统信息")
    common(sysinfo_parser)

    health_parser = sub.add_parser("health", aliases=["check", "test"], help="健康检查")
    common(health_parser)
    return parser


def main() -> None:  # pragma: no cover - CLI wrapper
    """CLI 入口。"""
    config = load_runtime_config()
    parser = build_parser(config)
    args = parser.parse_args()

    if not args.action:
        parser.print_help()
        sys.exit(0)

    password = args.password
    if not password and args.auth != "kerberos":
        password = get_password_interactive()

    kwargs: dict[str, Any] = {
        "host": args.host,
        "port": args.port,
        "username": args.user,
        "password": password,
        "auth": args.auth,
        "transport": args.transport,
        "cert_verify": args.cert_verify,
    }
    auto_confirm = bool(getattr(args, "auto_confirm", False))
    audit_log = str(getattr(args, "audit_log", get_config_value(config, "audit_log")))

    result: Any
    try:
        if args.action in {"execute", "exec", "run"}:
            result = execute_command(
                **kwargs,
                command=args.command,
                shell=args.shell_type,
                auto_confirm=auto_confirm,
                audit_log=audit_log,
            )
        elif args.action == "batch":
            result = execute_batch(
                **kwargs,
                commands=split_commands(args.commands),
                shell=args.shell_type,
                auto_confirm=auto_confirm,
                audit_log=audit_log,
            )
        elif args.action == "script":
            script = load_script_content(args.script_file, args.script)
            result = execute_script(
                **kwargs,
                script=script,
                shell=args.shell_type,
                auto_confirm=auto_confirm,
                audit_log=audit_log,
            )
        elif args.action in {"sysinfo", "info"}:
            result = get_system_info(**kwargs)
        elif args.action in {"health", "check", "test"}:
            result = health_check(**kwargs)
        else:
            parser.print_help()
            sys.exit(0)
    except SecurityInterceptedError as exc:
        dump_json(exc.to_result())
        sys.exit(0)
    except DependencyUnavailableError as exc:
        result = format_error(exc, logger=LOGGER)
        dump_json(result)
        sys.exit(1)

    dump_json(result)


if __name__ == "__main__":  # pragma: no cover - CLI wrapper
    main()
