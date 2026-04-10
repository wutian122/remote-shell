#!/usr/bin/env python3
"""SSH 命令执行脚本。"""

from __future__ import annotations

import argparse
import asyncio
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
    ssh_connect,
    to_text,
)
from exceptions import ConfigurationError, SecurityInterceptedError
from security_interceptor import enforce_security

LOGGER = get_logger("remote_shell.ssh")


async def execute_command(
    host: str,
    port: int,
    username: str,
    command: str,
    password: str | None = None,
    private_key_path: str | None = None,
    timeout: int = 30,
    retry_count: int = 3,
    auto_confirm: bool = False,
    audit_log: str = "audit_remote.log",
) -> dict[str, Any]:
    """执行单条 SSH 命令。"""
    enforce_security(command, host, username, auto_confirm, audit_log)
    try:
        async with await ssh_connect(
            host,
            port,
            username,
            password,
            private_key_path,
            retry_count=retry_count,
            logger=LOGGER,
        ) as conn:
            result = await conn.run(command, check=False, timeout=float(timeout))
            return {
                "success": True,
                "host": host,
                "command": command,
                "exit_status": int(result.exit_status or 0),
                "stdout": to_text(result.stdout).strip(),
                "stderr": to_text(result.stderr).strip(),
            }
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host, command=command)


async def execute_batch(
    host: str,
    port: int,
    username: str,
    commands: list[str],
    password: str | None = None,
    private_key_path: str | None = None,
    timeout: int = 30,
    retry_count: int = 3,
    auto_confirm: bool = False,
    audit_log: str = "audit_remote.log",
) -> list[dict[str, Any]]:
    """批量执行命令（同一连接内顺序执行）。"""
    results: list[dict[str, Any]] = []
    try:
        async with await ssh_connect(
            host,
            port,
            username,
            password,
            private_key_path,
            retry_count=retry_count,
            logger=LOGGER,
        ) as conn:
            for command in commands:
                enforce_security(command, host, username, auto_confirm, audit_log)
                try:
                    result = await conn.run(command, check=False, timeout=float(timeout))
                    results.append(
                        {
                            "success": True,
                            "command": command,
                            "exit_status": int(result.exit_status or 0),
                            "stdout": to_text(result.stdout).strip(),
                            "stderr": to_text(result.stderr).strip(),
                        }
                    )
                except Exception as exc:
                    results.append(format_error(exc, logger=LOGGER, command=command))
    except Exception as exc:
        return [format_error(exc, logger=LOGGER, host=host)]
    return results


async def execute_script(
    host: str,
    port: int,
    username: str,
    script: str,
    shell: str = "/bin/bash",
    password: str | None = None,
    private_key_path: str | None = None,
    timeout: int = 60,
    retry_count: int = 3,
    auto_confirm: bool = False,
    audit_log: str = "audit_remote.log",
) -> dict[str, Any]:
    """通过 stdin 执行 Shell 脚本。"""
    enforce_security(script, host, username, auto_confirm, audit_log)
    try:
        async with await ssh_connect(
            host,
            port,
            username,
            password,
            private_key_path,
            retry_count=retry_count,
            logger=LOGGER,
        ) as conn:
            result = await conn.run(
                f"{shell} -s",
                input=script,
                check=False,
                timeout=float(timeout),
            )
            return {
                "success": True,
                "host": host,
                "shell": shell,
                "exit_status": int(result.exit_status or 0),
                "stdout": to_text(result.stdout).strip(),
                "stderr": to_text(result.stderr).strip(),
            }
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host)


async def get_system_info(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    private_key_path: str | None = None,
    retry_count: int = 3,
) -> dict[str, Any]:
    """获取远程系统信息。"""
    commands = {
        "hostname": "hostname",
        "kernel": "uname -a",
        "uptime": "uptime",
        "whoami": "whoami",
        "os_release": "cat /etc/os-release 2>/dev/null || echo 'N/A'",
    }
    try:
        async with await ssh_connect(
            host,
            port,
            username,
            password,
            private_key_path,
            retry_count=retry_count,
            logger=LOGGER,
        ) as conn:
            info: dict[str, Any] = {"success": True, "host": host}
            for key, command in commands.items():
                result = await conn.run(command, check=False, timeout=10)
                info[key] = to_text(result.stdout).strip()
            return info
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host)


async def health_check(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    private_key_path: str | None = None,
    retry_count: int = 3,
) -> dict[str, Any]:
    """SSH 连接健康检查。"""
    try:
        async with await ssh_connect(
            host,
            port,
            username,
            password,
            private_key_path,
            retry_count=retry_count,
            logger=LOGGER,
        ) as conn:
            result = await conn.run("echo ok", check=False, timeout=5)
            return {
                "success": True,
                "host": host,
                "status": "connected",
                "response": to_text(result.stdout).strip(),
            }
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host, status="failed")


def build_parser(config: dict[str, Any]) -> argparse.ArgumentParser:  # pragma: no cover - CLI wrapper
    """构建 CLI 解析器。"""
    ssh_config = get_config_value(config, "ssh")
    audit_log = str(get_config_value(config, "audit_log"))

    parser = argparse.ArgumentParser(description="Remote Shell - SSH 命令执行工具")
    sub = parser.add_subparsers(dest="action", help="可用操作")

    def common(parser_obj: argparse.ArgumentParser) -> None:
        parser_obj.add_argument("--host", "-H", required=True, help="目标主机")
        parser_obj.add_argument(
            "--port",
            "-P",
            type=int,
            default=int(ssh_config["port"]),
            help="SSH 端口",
        )
        parser_obj.add_argument("--user", "-u", required=True, help="用户名")
        parser_obj.add_argument("--password", "-p", help="密码")
        parser_obj.add_argument("--key", "-k", help="私钥路径")
        parser_obj.add_argument(
            "--timeout",
            "-t",
            type=int,
            default=int(ssh_config["timeout"]),
            help="超时(秒)",
        )
        parser_obj.add_argument(
            "--retry",
            type=int,
            default=int(ssh_config["retry"]),
            help="重试次数",
        )
        parser_obj.add_argument(
            "--auto-confirm",
            action="store_true",
            help="跳过安全拦截并强制执行(必须已获用户确认)",
        )
        parser_obj.add_argument(
            "--audit-log",
            default=audit_log,
            help="审计日志路径",
        )

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
    script_parser.add_argument(
        "--shell",
        default=str(ssh_config["shell"]),
        help="远端 shell",
    )

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
    if not password and not getattr(args, "key", None):
        password = get_password_interactive()

    kwargs: dict[str, Any] = {
        "host": args.host,
        "port": args.port,
        "username": args.user,
        "password": password,
        "private_key_path": getattr(args, "key", None),
        "timeout": getattr(args, "timeout", int(get_config_value(config, "ssh", "timeout"))),
        "retry_count": args.retry,
        "auto_confirm": getattr(args, "auto_confirm", False),
        "audit_log": getattr(args, "audit_log", str(get_config_value(config, "audit_log"))),
    }

    result: Any
    try:
        if args.action in {"execute", "exec", "run"}:
            result = asyncio.run(execute_command(**kwargs, command=args.command))
        elif args.action == "batch":
            commands = split_commands(args.commands)
            result = asyncio.run(execute_batch(**kwargs, commands=commands))
        elif args.action == "script":
            script_content = load_script_content(args.script_file, args.script)
            result = asyncio.run(
                execute_script(**kwargs, script=script_content, shell=args.shell)
            )
        elif args.action in {"sysinfo", "info"}:
            kwargs.pop("auto_confirm", None)
            kwargs.pop("audit_log", None)
            kwargs.pop("timeout", None)
            result = asyncio.run(get_system_info(**kwargs))
        elif args.action in {"health", "check", "test"}:
            kwargs.pop("auto_confirm", None)
            kwargs.pop("audit_log", None)
            kwargs.pop("timeout", None)
            result = asyncio.run(health_check(**kwargs))
        else:
            parser.print_help()
            sys.exit(0)
    except SecurityInterceptedError as exc:
        dump_json(exc.to_result())
        sys.exit(0)
    except ConfigurationError as exc:
        result = format_error(exc, logger=LOGGER)
    else:
        dump_json(result)
        return

    dump_json(result)
    sys.exit(1)


if __name__ == "__main__":  # pragma: no cover - CLI wrapper
    main()
