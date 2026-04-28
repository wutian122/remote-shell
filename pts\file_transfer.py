#!/usr/bin/env python3
"""SFTP 文件传输脚本。"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import shlex
import stat
import sys
from pathlib import Path
from typing import Any

from common import (
    configure_stdio,
    dump_json,
    format_error,
    get_config_value,
    get_logger,
    get_password_interactive,
    load_runtime_config,
    ssh_connect,
    to_text,
)
from exceptions import ConfigurationError
from security_interceptor import audit_action

LOGGER = get_logger("remote_shell.sftp")


def calculate_md5(file_path: str) -> str:
    """计算本地文件 MD5。"""
    md5 = hashlib.md5()
    with open(file_path, "rb") as file_obj:
        while True:
            chunk = file_obj.read(8192)
            if not chunk:
                break
            md5.update(chunk)
    return md5.hexdigest()


async def resolve_remote_path(conn: Any, sftp: Any, remote_path: str) -> str:
    """将远程路径解析为绝对路径，统一 ~ 展开和相对路径处理。"""
    if remote_path.startswith("/"):
        return remote_path
    if remote_path.startswith("~"):
        try:
            resolved = await sftp.realpath(remote_path)
            return str(resolved)
        except Exception:
            result = await conn.run("echo $HOME", check=False)
            if result.exit_status == 0 and result.stdout:
                home = to_text(result.stdout).strip()
                return remote_path.replace("~", home, 1)
            return remote_path
    try:
        cwd = await sftp.getcwd()
        if not cwd:
            cwd = str(await sftp.realpath("."))
    except Exception:
        cwd = "."
    return f"{cwd.rstrip('/')}/{remote_path}"


async def get_remote_md5(conn: Any, remote_path: str) -> str | None:
    """读取远程文件 MD5。"""
    result = await conn.run(f"md5sum {shlex.quote(remote_path)} 2>/dev/null", check=False)
    if result.exit_status == 0:
        parts = to_text(result.stdout).strip().split()
        if parts and len(parts[0]) == 32:
            return parts[0].lower()
    return None


async def upload_file(
    host: str,
    port: int,
    username: str,
    local_path: str,
    remote_path: str,
    password: str | None = None,
    private_key_path: str | None = None,
    verify_md5: bool = True,
    chunk_size: int = 8192,
    retry_count: int = 3,
    auto_confirm: bool = False,
    audit_log: str = "audit_remote.log",
) -> dict[str, Any]:
    """上传文件。"""
    # auto_confirm 保留用于兼容 Skill 接口统一参数；文件传输不等同 shell 命令执行，不触发命令级安全拦截，审计日志已覆盖
    del auto_confirm
    local = Path(local_path)
    if not local.exists():
        return {"success": False, "error": f"本地文件不存在: {local_path}"}

    audit_action(
        user=username,
        target=host,
        action="UPLOAD",
        details=f"{local_path} -> {remote_path}",
        audit_log_path=audit_log,
    )
    total_bytes = local.stat().st_size
    md5_local = calculate_md5(local_path) if verify_md5 else None

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
            # 解析远程路径：展开 ~ 和相对路径
            async with conn.start_sftp_client() as sftp:
                remote_path = await resolve_remote_path(conn, sftp, remote_path)
            with local.open("rb") as file_obj:
                data = file_obj.read()
            encoded = base64.b64encode(data).decode("ascii")
            chunk_size_b64 = 48 * 1024
            offset = 0
            first = True
            while offset < len(encoded):
                chunk = encoded[offset:offset + chunk_size_b64]
                offset += chunk_size_b64
                if first:
                    redirect = ">"
                    first = False
                else:
                    redirect = ">>"
                cmd = f"echo '{chunk}' | base64 -d {redirect} {shlex.quote(remote_path)}"
                result = await conn.run(cmd, check=False)
                if result.exit_status != 0:
                    return {"success": False, "error": f"写入失败: {to_text(result.stderr).strip()}", "host": host}
            md5_remote = await get_remote_md5(conn, remote_path) if verify_md5 else None
            md5_match = (md5_remote == md5_local) if (md5_remote and md5_local) else None
        return {
            "success": True,
            "host": host,
            "local_path": str(local),
            "remote_path": remote_path,
            "bytes_transferred": total_bytes,
            "total_bytes": total_bytes,
            "md5_local": md5_local,
            "md5_remote": md5_remote,
            "md5_match": md5_match,
        }
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host)


async def download_file(
    host: str,
    port: int,
    username: str,
    remote_path: str,
    local_path: str,
    password: str | None = None,
    private_key_path: str | None = None,
    verify_md5: bool = True,
    chunk_size: int = 8192,
    retry_count: int = 3,
    auto_confirm: bool = False,
    audit_log: str = "audit_remote.log",
) -> dict[str, Any]:
    """下载文件。"""
    # auto_confirm 保留用于兼容 Skill 接口统一参数；文件传输不等同 shell 命令执行，不触发命令级安全拦截，审计日志已覆盖
    del auto_confirm
    local = Path(local_path)
    local.parent.mkdir(parents=True, exist_ok=True)
    audit_action(
        user=username,
        target=host,
        action="DOWNLOAD",
        details=f"{remote_path} -> {local_path}",
        audit_log_path=audit_log,
    )

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
            async with conn.start_sftp_client() as sftp:
                remote_path = await resolve_remote_path(conn, sftp, remote_path)
                attrs = await sftp.stat(remote_path)
                total_bytes = attrs.size or 0
                transferred = 0
                md5 = hashlib.md5()
                with local.open("wb") as file_obj:
                    async with await sftp.open(remote_path, "rb") as remote_file:
                        while True:
                            chunk = await remote_file.read(chunk_size)
                            if not chunk:
                                break
                            if isinstance(chunk, str):
                                chunk = chunk.encode()
                            if verify_md5:
                                md5.update(chunk)
                            file_obj.write(chunk)
                            transferred += len(chunk)
            md5_local = md5.hexdigest() if verify_md5 else None
            md5_remote = await get_remote_md5(conn, remote_path) if verify_md5 else None
            md5_match = (md5_local == md5_remote) if (md5_local and md5_remote) else None
        return {
            "success": True,
            "host": host,
            "remote_path": remote_path,
            "local_path": str(local),
            "bytes_transferred": transferred,
            "total_bytes": total_bytes,
            "md5_local": md5_local,
            "md5_remote": md5_remote,
            "md5_match": md5_match,
        }
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host)


async def get_file_info(
    host: str,
    port: int,
    username: str,
    path: str,
    password: str | None = None,
    private_key_path: str | None = None,
    retry_count: int = 3,
) -> dict[str, Any]:
    """获取远端文件信息。"""
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
            async with conn.start_sftp_client() as sftp:
                path = await resolve_remote_path(conn, sftp, path)
                attrs = await sftp.stat(path)
                return {
                    "success": True,
                    "host": host,
                    "path": path,
                    "size": attrs.size or 0,
                    "permissions": attrs.permissions or 0,
                    "mtime": attrs.mtime or 0,
                    "atime": attrs.atime or 0,
                }
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host, path=path)


async def list_directory(
    host: str,
    port: int,
    username: str,
    path: str,
    password: str | None = None,
    private_key_path: str | None = None,
    page: int = 1,
    page_size: int = 100,
    retry_count: int = 3,
) -> dict[str, Any]:
    """列出远端目录。"""
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
            async with conn.start_sftp_client() as sftp:
                path = await resolve_remote_path(conn, sftp, path)
                entries = []
                async for entry in sftp.scandir(path):
                    permissions = entry.attrs.permissions if entry.attrs else 0
                    is_dir = stat.S_ISDIR(permissions or 0)
                    entries.append(
                        {
                            "name": entry.filename,
                            "is_dir": bool(is_dir),
                            "size": entry.attrs.size if entry.attrs and entry.attrs.size else 0,
                            "mtime": entry.attrs.mtime if entry.attrs and entry.attrs.mtime else 0,
                        }
                    )
        total = len(entries)
        start = (page - 1) * page_size
        return {
            "success": True,
            "host": host,
            "path": path,
            "entries": entries[start : start + page_size],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size,
        }
    except Exception as exc:
        return format_error(exc, logger=LOGGER, host=host, path=path)


def build_parser(config: dict[str, Any]) -> argparse.ArgumentParser:  # pragma: no cover - CLI wrapper
    """构建 CLI 解析器。"""
    sftp_config = get_config_value(config, "sftp")
    audit_log = str(get_config_value(config, "audit_log"))

    parser = argparse.ArgumentParser(description="Remote Shell - SFTP 文件传输工具")
    sub = parser.add_subparsers(dest="action", help="可用操作")

    def common(parser_obj: argparse.ArgumentParser) -> None:
        parser_obj.add_argument("--host", "-H", required=True, help="目标主机")
        parser_obj.add_argument(
            "--port",
            "-P",
            type=int,
            default=int(sftp_config["port"]),
            help="SFTP 端口",
        )
        parser_obj.add_argument("--user", "-u", required=True, help="用户名")
        parser_obj.add_argument("--password", "-p", help="密码")
        parser_obj.add_argument("--key", "-k", help="私钥路径")
        parser_obj.add_argument(
            "--retry",
            type=int,
            default=int(sftp_config["retry"]),
            help="重试次数",
        )
        parser_obj.add_argument(
            "--auto-confirm",
            action="store_true",
            help="为兼容 Skill 接口保留的参数",
        )
        parser_obj.add_argument("--audit-log", default=audit_log, help="审计日志路径")

    upload_parser = sub.add_parser("upload", aliases=["put"], help="上传文件")
    common(upload_parser)
    upload_parser.add_argument("--local", "-l", required=True, help="本地文件")
    upload_parser.add_argument("--remote", "-r", required=True, help="远端路径")
    upload_parser.add_argument("--no-md5", action="store_true", help="禁用 MD5 校验")

    download_parser = sub.add_parser("download", aliases=["get"], help="下载文件")
    common(download_parser)
    download_parser.add_argument("--remote", "-r", required=True, help="远端文件")
    download_parser.add_argument("--local", "-l", required=True, help="本地路径")
    download_parser.add_argument("--no-md5", action="store_true", help="禁用 MD5 校验")

    info_parser = sub.add_parser("info", help="文件信息")
    common(info_parser)
    info_parser.add_argument("--path", required=True, help="目标路径")

    list_parser = sub.add_parser("ls", aliases=["list", "dir"], help="目录列表")
    common(list_parser)
    list_parser.add_argument("--path", required=True, help="目标目录")
    list_parser.add_argument("--page", type=int, default=1, help="页码")
    list_parser.add_argument(
        "--page-size",
        type=int,
        default=int(sftp_config["page_size"]),
        help="每页条数",
    )
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

    password = args.password
    if not password and not getattr(args, "key", None):
        password = get_password_interactive()

    kwargs: dict[str, Any] = {
        "host": args.host,
        "port": args.port,
        "username": args.user,
        "password": password,
        "private_key_path": getattr(args, "key", None),
        "retry_count": args.retry,
        "auto_confirm": getattr(args, "auto_confirm", False),
        "audit_log": getattr(args, "audit_log", str(get_config_value(config, "audit_log"))),
    }

    try:
        if args.action in {"upload", "put"}:
            result = asyncio.run(
                upload_file(
                    **kwargs,
                    local_path=args.local,
                    remote_path=args.remote,
                    verify_md5=not args.no_md5,
                    chunk_size=int(get_config_value(config, "sftp", "chunk_size")),
                )
            )
        elif args.action in {"download", "get"}:
            result = asyncio.run(
                download_file(
                    **kwargs,
                    remote_path=args.remote,
                    local_path=args.local,
                    verify_md5=not args.no_md5,
                    chunk_size=int(get_config_value(config, "sftp", "chunk_size")),
                )
            )
        elif args.action == "info":
            kwargs.pop("auto_confirm", None)
            kwargs.pop("audit_log", None)
            result = asyncio.run(get_file_info(**kwargs, path=args.path))
        elif args.action in {"ls", "list", "dir"}:
            kwargs.pop("auto_confirm", None)
            kwargs.pop("audit_log", None)
            result = asyncio.run(
                list_directory(
                    **kwargs,
                    path=args.path,
                    page=args.page,
                    page_size=args.page_size,
                )
            )
        else:
            parser.print_help()
            sys.exit(0)
    except ConfigurationError as exc:
        result = format_error(exc, logger=LOGGER)
        dump_json(result)
        sys.exit(1)

    dump_json(result)


if __name__ == "__main__":  # pragma: no cover - CLI wrapper
    main()
