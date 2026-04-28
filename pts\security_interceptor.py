#!/usr/bin/env python3
"""安全拦截器模块。"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from exceptions import SecurityInterceptedError

DANGEROUS_PATTERNS = [
    r"\brm\s+",
    r"\bmv\s+",
    r"\bcp\s+",
    r"\btouch\s+",
    r"\bmkdir\s+",
    r"\brmdir\s+",
    r"\bchmod\s+",
    r"\bchown\s+",
    r"\bchgrp\s+",
    r">\s*\/",
    r">>\s*\/",
    r"\bRemove-Item\b",
    r"\bMove-Item\b",
    r"\bCopy-Item\b",
    r"\bNew-Item\b",
    r"\bSet-Content\b",
    r"\bAdd-Content\b",
    r"\bClear-Content\b",
    r"\bdel\s+",
    r"\bren\s+",
    r"\bkill\b",
    r"\bpkill\b",
    r"\bkillall\b",
    r"\bsystemctl\s+(stop|restart|disable|mask)",
    r"\bservice\s+.*? (stop|restart)",
    r"\bStop-Process\b",
    r"\bStop-Service\b",
    r"\bRestart-Service\b",
    r"\bSet-Service\b",
    r"\bSuspend-Service\b",
    r"\bapt\s+(install|remove|purge|autoremove|upgrade)",
    r"\bapt-get\s+(install|remove|purge|autoremove|upgrade)",
    r"\byum\s+(install|remove|erase|update)",
    r"\bdnf\s+(install|remove|erase|update)",
    r"\bpip\s+(install|uninstall)",
    r"\bnpm\s+(install|uninstall|update)",
    r"\bchoco\s+(install|uninstall|upgrade)",
    r"\bInstall-Package\b",
    r"\bUninstall-Package\b",
    r"\buseradd\b",
    r"\buserdel\b",
    r"\busermod\b",
    r"\bpasswd\b",
    r"\bnet\s+user\b",
    r"\bnet\s+localgroup\b",
    r"\bAdd-LocalGroupMember\b",
    r"\bNew-LocalUser\b",
    r"\bRemove-LocalUser\b",
    r"\breg\s+(add|delete|import|restore)",
    r"\bSet-ItemProperty\b",
    r"\bNew-ItemProperty\b",
    r"\bRemove-ItemProperty\b",
    r"\bwget\b",
    r"\bcurl\b",
    r"\bInvoke-WebRequest\b",
    r"\biwr\b",
    r"\bInvoke-RestMethod\b",
    r"\birm\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bhalt\b",
    r"\bpoweroff\b",
    r"\bRestart-Computer\b",
    r"\bStop-Computer\b",
]
COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in DANGEROUS_PATTERNS]


def setup_audit_logger(log_file: str = "audit_remote.log") -> logging.Logger:
    """初始化审计日志记录器。"""
    resolved = Path(log_file).resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    logger_name = f"RemoteAudit:{resolved}"
    logger = logging.getLogger(logger_name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        logger.propagate = False
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        file_handler = logging.FileHandler(resolved, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger


def log_audit(
    logger: logging.Logger,
    user: str,
    target: str,
    command: str,
    action: str,
    auth_type: str = "N/A",
) -> None:
    """记录单条审计日志。"""
    message = (
        f"User: {user} | Target: {target} | Action: {action} | "
        f"Auth: {auth_type} | Cmd: {command}"
    )
    logger.info(message)


def audit_action(
    *,
    user: str,
    target: str,
    action: str,
    details: str,
    audit_log_path: str = "audit_remote.log",
    auth_type: str = "N/A",
) -> None:
    """记录非命令类操作。"""
    logger = setup_audit_logger(audit_log_path)
    log_audit(logger, user, target, details, action, auth_type)


def check_command_safety(command: str) -> tuple[bool, str | None]:
    """检查命令是否命中危险规则。"""
    for pattern in COMPILED_PATTERNS:
        match = pattern.search(command)
        if match:
            return False, match.group(0)
    return True, None


def enforce_security(
    command: str,
    target: str,
    user: str,
    auto_confirm: bool = False,
    audit_log_path: str = "audit_remote.log",
) -> None:
    """执行安全强制策略。"""
    logger = setup_audit_logger(audit_log_path)
    is_safe, matched = check_command_safety(command)

    if is_safe:
        log_audit(logger, user, target, command, "ALLOW", "Auto(Safe)")
        return

    if auto_confirm:
        log_audit(logger, user, target, command, "ALLOW_DANGEROUS", "Manual(Confirmed)")
        return

    log_audit(logger, user, target, command, "DENY", "Auto(Intercepted)")
    raise SecurityInterceptedError(command=command, target=target, matched_pattern=matched)
