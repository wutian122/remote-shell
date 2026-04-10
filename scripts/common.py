#!/usr/bin/env python3
"""Remote Shell 公共模块。"""

from __future__ import annotations

import asyncio
import copy
import getpass
import json
import logging
import os
from pathlib import Path
from typing import Any, Callable

from exceptions import (
    ConfigurationError,
    DependencyUnavailableError,
    RemoteConnectionError,
)

try:
    import asyncssh
except ImportError:
    asyncssh = None  # type: ignore[assignment]

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config" / "default.json"
DEFAULT_RUNTIME_CONFIG: dict[str, Any] = {
    "audit_log": "audit_remote.log",
    "ssh": {"port": 22, "timeout": 30, "retry": 3, "shell": "/bin/bash"},
    "sftp": {
        "port": 22,
        "retry": 3,
        "chunk_size": 8192,
        "verify_md5": True,
        "page_size": 100,
    },
    "telnet": {"port": 23, "timeout": 3.0, "retry": 3, "command_delay": 0.5},
    "winrm": {
        "port": 5985,
        "auth": "ntlm",
        "transport": "http",
        "shell_type": "auto",
    },
}
Converter = Callable[[str], Any]

ENV_OVERRIDE_MAP: dict[str, tuple[str, Converter]] = {
    "audit_log": ("REMOTE_SHELL_AUDIT_LOG", str),
    "ssh.port": ("REMOTE_SHELL_SSH_PORT", int),
    "ssh.timeout": ("REMOTE_SHELL_SSH_TIMEOUT", int),
    "ssh.retry": ("REMOTE_SHELL_SSH_RETRY", int),
    "ssh.shell": ("REMOTE_SHELL_SSH_SHELL", str),
    "sftp.port": ("REMOTE_SHELL_SFTP_PORT", int),
    "sftp.retry": ("REMOTE_SHELL_SFTP_RETRY", int),
    "sftp.chunk_size": ("REMOTE_SHELL_SFTP_CHUNK_SIZE", int),
    "sftp.verify_md5": (
        "REMOTE_SHELL_SFTP_VERIFY_MD5",
        lambda value: value.lower() in {"1", "true", "yes", "on"},
    ),
    "sftp.page_size": ("REMOTE_SHELL_SFTP_PAGE_SIZE", int),
    "telnet.port": ("REMOTE_SHELL_TELNET_PORT", int),
    "telnet.timeout": ("REMOTE_SHELL_TELNET_TIMEOUT", float),
    "telnet.retry": ("REMOTE_SHELL_TELNET_RETRY", int),
    "telnet.command_delay": ("REMOTE_SHELL_TELNET_COMMAND_DELAY", float),
    "winrm.port": ("REMOTE_SHELL_WINRM_PORT", int),
    "winrm.auth": ("REMOTE_SHELL_WINRM_AUTH", str),
    "winrm.transport": ("REMOTE_SHELL_WINRM_TRANSPORT", str),
    "winrm.shell_type": ("REMOTE_SHELL_WINRM_SHELL_TYPE", str),
}


def deep_merge_config(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """递归合并配置字典。"""
    merged = copy.deepcopy(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge_config(merged[key], value)
        else:
            merged[key] = value
    return merged


def _set_nested_value(config: dict[str, Any], dotted_path: str, value: Any) -> None:
    keys = dotted_path.split(".")
    current = config
    for key in keys[:-1]:
        current = current.setdefault(key, {})
    current[keys[-1]] = value


def load_runtime_config(config_path: str | None = None) -> dict[str, Any]:
    """读取默认配置并应用环境变量覆盖。"""
    config = copy.deepcopy(DEFAULT_RUNTIME_CONFIG)
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    if path.exists():
        raw_data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw_data, dict):
            raise ConfigurationError(f"配置文件格式无效: {path}")
        config = deep_merge_config(config, raw_data)

    for dotted_path, (env_name, converter) in ENV_OVERRIDE_MAP.items():
        raw_value = os.getenv(env_name)
        if raw_value is None:
            continue
        _set_nested_value(config, dotted_path, converter(raw_value))

    return config


def get_config_value(config: dict[str, Any], *path: str) -> Any:
    """按路径读取配置值。"""
    current: Any = config
    for key in path:
        if not isinstance(current, dict) or key not in current:
            joined = ".".join(path)
            raise ConfigurationError(f"缺少配置项: {joined}")
        current = current[key]
    return current


def get_logger(name: str) -> logging.Logger:
    """获取标准控制台日志记录器。"""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
        )
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(logging.INFO)
    return logger


async def ssh_connect(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    private_key_path: str | None = None,
    retry_count: int = 3,
    retry_delay: float = 1.0,
    logger: logging.Logger | None = None,
) -> Any:
    """建立 SSH 连接（带重试）。"""
    if asyncssh is None:
        raise DependencyUnavailableError("缺少 asyncssh 库，请执行: pip install asyncssh")

    options: dict[str, Any] = {
        "host": host,
        "port": port,
        "username": username,
        "known_hosts": None,
    }
    if private_key_path:
        options["client_keys"] = [private_key_path]
    if password:
        options["password"] = password

    last_error: Exception | None = None
    for attempt in range(retry_count + 1):
        try:
            return await asyncssh.connect(**options)
        except Exception as exc:  # pragma: no cover - 依赖真实网络环境
            last_error = exc
            if logger is not None:
                logger.warning(
                    "SSH 连接失败，准备重试",
                    extra={"host": host, "port": port, "attempt": attempt + 1},
                )
                logger.exception(exc)
            if attempt < retry_count:
                await asyncio.sleep(retry_delay)

    raise RemoteConnectionError(
        f"连接 {host}:{port} 失败，已重试{retry_count}次: {last_error}"
    ) from last_error


def to_text(value: str | bytes | None) -> str:
    """将输出转换为文本。"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def format_error(
    exc: Exception,
    *,
    logger: logging.Logger | None = None,
    error_type: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """统一错误返回并记录堆栈。"""
    if logger is not None:
        logger.exception("操作失败", exc_info=exc)

    result: dict[str, Any] = {
        "success": False,
        "error_type": error_type or type(exc).__name__,
        "error": str(exc),
    }
    result.update(extra)
    return result


def get_password_interactive() -> str:
    """交互式获取密码。"""
    return getpass.getpass("请输入密码: ")


def split_commands(raw_commands: str) -> list[str]:
    """同时支持逗号和换行分隔的命令字符串。"""
    normalized = raw_commands.replace("\r\n", "\n").replace("\r", "\n")
    commands: list[str] = []
    for chunk in normalized.split("\n"):
        parts = chunk.split(",") if "," in chunk else [chunk]
        commands.extend(part.strip() for part in parts if part.strip())
    return commands


def load_script_content(script_file: str | None, inline_script: str | None) -> str:
    """从文件或内联参数中读取脚本内容。"""
    if script_file:
        path = Path(script_file)
        if not path.exists():
            raise ConfigurationError(f"文件不存在: {script_file}")
        return path.read_text(encoding="utf-8")
    if inline_script:
        return inline_script
    raise ConfigurationError("需要提供脚本文件或脚本内容")


def dump_json(data: Any) -> None:
    """统一 JSON 输出。"""
    print(json.dumps(data, ensure_ascii=False, indent=2))
