#!/usr/bin/env python3
"""Remote Shell 自定义异常层级。"""

from __future__ import annotations

from typing import Any


class RemoteShellError(Exception):
    """项目内所有自定义异常的基类。"""


class DependencyUnavailableError(RemoteShellError):
    """运行所需依赖缺失。"""


class ConfigurationError(RemoteShellError):
    """配置错误或参数缺失。"""


class RemoteConnectionError(RemoteShellError):
    """远程连接失败。"""


class CommandExecutionError(RemoteShellError):
    """命令执行失败。"""


class SecurityInterceptedError(RemoteShellError):
    """命中安全策略时抛出的异常。"""

    def __init__(self, command: str, target: str, matched_pattern: str | None) -> None:
        self.command = command
        self.target = target
        self.matched_pattern = matched_pattern
        message = (
            "⚠️ 安全拦截警告：\n"
            f"您即将执行的命令 `{command}` 涉及系统修改或危险操作"
            f" (匹配到: '{matched_pattern or 'unknown'}')。\n"
            "根据当前 remote-shell 安全策略，该命令已被拦截。\n"
            "若要继续执行，请向 Agent 回复 `yes` 或 `同意`。"
        )
        super().__init__(message)

    def to_result(self) -> dict[str, Any]:
        return {
            "success": False,
            "error_type": type(self).__name__,
            "error": str(self),
            "host": self.target,
            "command": self.command,
        }
