#!/usr/bin/env python3
"""Telnet 命令执行脚本。"""

from __future__ import annotations

import argparse
import re
import sys
import time
from datetime import datetime
from typing import Any

from common import (
    configure_stdio,
    dump_json,
    format_error,
    get_config_value,
    get_logger,
    load_runtime_config,
    read_text_file,
    safe_print,
    split_commands,
    to_text,
)
from exceptions import DependencyUnavailableError, SecurityInterceptedError
from security_interceptor import enforce_security

LOGGER = get_logger("remote_shell.telnet")
DEFAULT_PROMPT_PATTERNS = [
    r"/\s*[#\$]\s*$",
    r"^User@[^>]+>\s*$",
    r"^root@[a-zA-Z0-9_-]+[#\$]\s*$",
    r"^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+[:#\$]\s*$",
    r"^\s*>\s*$",
    r"^[#\$]\s*$",
    r"BusyBox\s+v[0-9.]+",
    r"login:\s*$",
    r"Password:\s*$",
]
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def get_pexpect() -> Any:
    """惰性导入 pexpect。"""
    try:
        import pexpect
    except ImportError as exc:  # pragma: no cover - 依赖外部环境
        raise DependencyUnavailableError("缺少 pexpect 库，请执行: pip install pexpect") from exc
    return pexpect


class TelnetHelper:
    """Telnet 连接与命令执行助手。"""

    def __init__(
        self,
        host: str,
        port: int = 23,
        timeout: float = 3.0,
        prompt_pattern: str | None = None,
        debug: bool = False,
        logfile: str | None = None,
        retry_count: int = 3,
        retry_delay: float = 1.0,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.debug = debug
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.conn: Any | None = None
        self.detected_prompt: str | None = None
        self.logfile_handle: Any | None = None
        self.prompt_patterns = [prompt_pattern] if prompt_pattern else list(DEFAULT_PROMPT_PATTERNS)
        self.expect_patterns = [pattern.encode("ascii") for pattern in self.prompt_patterns]

        if logfile:
            try:
                self.logfile_handle = open(
                    logfile,
                    "a",
                    encoding="utf-8",
                    errors="replace",
                    buffering=1,
                )
                self._log("\n" + "=" * 60 + "\n")
                self._log(f"Session started: {datetime.now().isoformat()}\n")
                self._log(f"Target: {host}:{port}\n")
                self._log("=" * 60 + "\n")
            except OSError as exc:
                LOGGER.warning("无法打开日志文件: %s", exc)

    def _debug_print(self, message: str) -> None:
        if self.debug:
            LOGGER.info("[DEBUG] %s", message)

    def _log(self, data: str | bytes) -> None:
        if self.logfile_handle:
            self.logfile_handle.write(to_text(data))
            self.logfile_handle.flush()

    def _merge_output(self, *parts: Any) -> str:
        return "".join(to_text(part) for part in parts if part)

    def connect(self) -> bool:
        """建立 Telnet 连接（带重试）。"""
        pexpect = get_pexpect()
        last_error: Exception | None = None
        for attempt in range(self.retry_count + 1):
            try:
                self._debug_print(f"连接 {self.host}:{self.port}（第 {attempt + 1} 次）")
                self.conn = pexpect.spawn(
                    f"telnet {self.host} {self.port}",
                    timeout=self.timeout,
                    encoding=None,
                )
                time.sleep(0.5)
                self.conn.sendline("")
                time.sleep(0.5)
                try:
                    self.conn.expect(self.expect_patterns, timeout=2.0)
                    prompt_output = self._merge_output(self.conn.before, self.conn.after)
                    self._log(prompt_output)
                    self._detect_prompt(prompt_output)
                except (pexpect.TIMEOUT, pexpect.EOF):
                    pass
                self._debug_print(f"连接成功，提示符: {self.detected_prompt}")
                return True
            except Exception as exc:
                last_error = exc
                if self.conn:
                    try:
                        self.conn.close()
                    except Exception:
                        LOGGER.debug("关闭失败的 Telnet 连接时忽略异常", exc_info=True)
                    self.conn = None
                if attempt < self.retry_count:
                    time.sleep(self.retry_delay)
        LOGGER.exception("Telnet 连接失败", exc_info=last_error)
        return False

    def disconnect(self) -> None:
        """关闭连接。"""
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                LOGGER.debug("关闭 Telnet 连接时忽略异常", exc_info=True)
            self.conn = None
        if self.logfile_handle:
            self._log("\n" + "=" * 60 + "\n")
            self._log(f"Session ended: {datetime.now().isoformat()}\n")
            self._log("=" * 60 + "\n\n")
            self.logfile_handle.close()
            self.logfile_handle = None

    def _detect_prompt(self, text: str) -> None:
        for line in reversed(text.split("\n")):
            candidate = line.strip()
            if not candidate:
                continue
            for pattern in self.prompt_patterns:
                if re.search(pattern, candidate):
                    self.detected_prompt = pattern
                    return

    def _clean_output(self, raw: str, command: str) -> str:
        cleaned = ANSI_ESCAPE_RE.sub("", raw).replace("\r", "")
        result: list[str] = []
        for line in cleaned.split("\n"):
            stripped = line.rstrip()
            if not stripped.strip():
                continue
            if stripped.strip() == command.strip():
                continue
            if any(re.search(pattern, stripped) for pattern in self.prompt_patterns):
                continue
            result.append(stripped)
        return "\n".join(result)

    def send_command(
        self,
        command: str,
        timeout: float | None = None,
        clean: bool = True,
    ) -> tuple[str, bool]:
        """发送单条命令。"""
        if not self.conn:
            return "", False

        pexpect = get_pexpect()
        effective_timeout = timeout if timeout is not None else self.timeout
        try:
            self.conn.sendline(command)
            time.sleep(0.2)
            index = self.conn.expect(
                self.expect_patterns + [pexpect.TIMEOUT, pexpect.EOF],
                timeout=effective_timeout,
            )
            prompt_found = index < len(self.expect_patterns)
            raw = self._merge_output(self.conn.before, self.conn.after if prompt_found else None)
            self._log(raw)
            output = self._clean_output(raw, command) if clean else raw
            return output, prompt_found
        except Exception as exc:
            LOGGER.exception("Telnet 命令执行失败", exc_info=exc)
            return "", False

    def send_commands(
        self,
        commands: list[str],
        delay: float = 0.5,
        clean: bool = True,
    ) -> list[dict[str, Any]]:
        """批量执行命令。"""
        results: list[dict[str, Any]] = []
        for command in commands:
            output, success = self.send_command(command, clean=clean)
            results.append({"command": command, "output": output, "success": success})
            if delay > 0:
                time.sleep(delay)
        return results

    def interactive_mode(self) -> None:
        """交互模式。"""
        safe_print(f"交互模式 - 连接到 {self.host}:{self.port}")
        safe_print("输入 exit 或按 Ctrl-C 退出")
        safe_print("-" * 50)
        try:
            while True:
                try:
                    command = input(">>> ")
                    if command.strip().lower() in {"exit", "quit"}:
                        break
                    if not command.strip():
                        continue
                    output, success = self.send_command(command)
                    safe_print(output)
                    if not success:
                        safe_print("[WARNING] 命令可能超时或失败", file=sys.stderr)
                except EOFError:
                    break
        except KeyboardInterrupt:
            safe_print("\n退出交互模式...")


def build_parser(config: dict[str, Any]) -> argparse.ArgumentParser:  # pragma: no cover - CLI wrapper
    """构建 CLI 解析器。"""
    telnet_config = get_config_value(config, "telnet")
    audit_log = str(get_config_value(config, "audit_log"))

    parser = argparse.ArgumentParser(description="Remote Shell - Telnet 命令执行工具")
    sub = parser.add_subparsers(dest="action", help="可用操作")

    def common(parser_obj: argparse.ArgumentParser) -> None:
        parser_obj.add_argument("--host", "-H", required=True, help="目标主机")
        parser_obj.add_argument(
            "--port",
            "-P",
            type=int,
            default=int(telnet_config["port"]),
            help="Telnet 端口",
        )
        parser_obj.add_argument(
            "--timeout",
            "-t",
            type=float,
            default=float(telnet_config["timeout"]),
            help="超时(秒)",
        )
        parser_obj.add_argument("--prompt", help="自定义提示符正则")
        parser_obj.add_argument(
            "--retry",
            type=int,
            default=int(telnet_config["retry"]),
            help="重试次数",
        )
        parser_obj.add_argument("--logfile", "-l", default=None, help="会话日志文件")
        parser_obj.add_argument("--debug", action="store_true", help="调试模式")
        parser_obj.add_argument("--raw", action="store_true", help="原始输出（不清洗）")
        parser_obj.add_argument(
            "--auto-confirm",
            action="store_true",
            help="跳过安全拦截并强制执行(必须已获用户确认)",
        )
        parser_obj.add_argument("--audit-log", default=audit_log, help="审计日志路径")
        parser_obj.add_argument(
            "--delay",
            type=float,
            default=float(telnet_config["command_delay"]),
            help="批量命令间隔",
        )

    execute_parser = sub.add_parser("execute", aliases=["exec", "run"], help="执行单条命令")
    common(execute_parser)
    execute_parser.add_argument("--command", "-c", required=True, help="命令")

    batch_parser = sub.add_parser("batch", help="批量执行")
    common(batch_parser)
    batch_parser.add_argument("--commands", "-c", required=True, help="逗号或换行分隔命令")

    script_parser = sub.add_parser("script", help="从文件执行命令")
    common(script_parser)
    script_parser.add_argument("--file", "-f", required=True, help="命令文件（每行一条）")

    interactive_parser = sub.add_parser("interactive", aliases=["shell"], help="交互模式")
    common(interactive_parser)

    health_parser = sub.add_parser("health", aliases=["check", "test"], help="端口连通性检查")
    health_parser.add_argument("--host", "-H", required=True, help="目标主机")
    health_parser.add_argument(
        "--port",
        "-P",
        type=int,
        default=int(telnet_config["port"]),
        help="Telnet 端口",
    )
    health_parser.add_argument(
        "--retry",
        type=int,
        default=int(telnet_config["retry"]),
        help="重试次数",
    )
    health_parser.add_argument("--logfile", "-l", default=None, help="会话日志文件")
    health_parser.add_argument("--debug", action="store_true", help="调试模式")
    return parser


def main() -> None:  # pragma: no cover - CLI wrapper
    """CLI 入口。"""
    configure_stdio()

    config = load_runtime_config()
    parser = build_parser(config)
    args = parser.parse_args()

    if not args.action:
        parser.print_help()
        sys.exit(0)

    if args.action in {"health", "check", "test"}:
        helper = TelnetHelper(
            host=args.host,
            port=args.port,
            debug=getattr(args, "debug", False),
            logfile=getattr(args, "logfile", None),
            retry_count=args.retry,
        )
        ok = helper.connect()
        helper.disconnect()
        result = {
            "success": ok,
            "host": args.host,
            "port": args.port,
            "status": "connected" if ok else "failed",
        }
        dump_json(result)
        sys.exit(0 if ok else 1)

    helper = TelnetHelper(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        prompt_pattern=getattr(args, "prompt", None),
        debug=args.debug,
        logfile=args.logfile,
        retry_count=args.retry,
    )

    if not helper.connect():
        dump_json(
            format_error(
                ConnectionError(f"无法连接到 {args.host}:{args.port}"),
                logger=LOGGER,
                host=args.host,
                port=args.port,
            )
        )
        sys.exit(1)

    try:
        if args.action in {"interactive", "shell"}:
            helper.interactive_mode()
            return

        if args.action in {"execute", "exec", "run"}:
            enforce_security(args.command, args.host, "telnet", args.auto_confirm, args.audit_log)
            output, success = helper.send_command(args.command, clean=not args.raw)
            result = {
                "success": success,
                "host": args.host,
                "command": args.command,
                "output": output,
            }
            dump_json(result)
            sys.exit(0 if success else 1)

        if args.action == "batch":
            commands = split_commands(args.commands)
            for command in commands:
                enforce_security(command, args.host, "telnet", args.auto_confirm, args.audit_log)
            results = helper.send_commands(commands, delay=args.delay, clean=not args.raw)
            dump_json(results)
            sys.exit(0 if all(item["success"] for item in results) else 1)

        if args.action == "script":
            commands = [
                line.strip()
                for line in read_text_file(args.file).splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            for command in commands:
                enforce_security(command, args.host, "telnet", args.auto_confirm, args.audit_log)
            results = helper.send_commands(commands, delay=args.delay, clean=not args.raw)
            dump_json(results)
            sys.exit(0 if all(item["success"] for item in results) else 1)

        parser.print_help()
        sys.exit(0)
    except FileNotFoundError:
        dump_json({"success": False, "error": f"文件不存在: {args.file}"})
        sys.exit(1)
    except SecurityInterceptedError as exc:
        dump_json(exc.to_result())
        sys.exit(0)
    except DependencyUnavailableError as exc:
        dump_json(format_error(exc, logger=LOGGER, host=args.host))
        sys.exit(1)
    finally:
        helper.disconnect()


if __name__ == "__main__":  # pragma: no cover - CLI wrapper
    main()
