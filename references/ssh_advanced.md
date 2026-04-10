# SSH 高级用法与故障排查

## 认证方式

### 密码认证
```bash
python scripts/ssh_execute.py execute -H 192.168.1.100 -u root -p "123456" -c "whoami"
```

### 私钥认证
```bash
python scripts/ssh_execute.py execute -H 192.168.1.100 -u root -k ~/.ssh/id_rsa -c "whoami"
```

### 交互式输入
不提供 `--password` 和 `--key` 时自动提示输入密码。

## 输出格式详解

### 命令执行成功
```json
{
  "success": true,
  "host": "192.168.1.100",
  "command": "ls -la",
  "exit_status": 0,
  "stdout": "total 4\ndrwxr-xr-x 2 root root 4096 ...",
  "stderr": ""
}
```

### 文件传输成功
```json
{
  "success": true,
  "host": "192.168.1.100",
  "local_path": "/tmp/test.txt",
  "remote_path": "/tmp/test.txt",
  "bytes_transferred": 1024,
  "total_bytes": 1024,
  "md5_local": "abc123...",
  "md5_remote": "abc123...",
  "md5_match": true
}
```

### 失败返回（含异常类型）
```json
{
  "success": false,
  "error_type": "TimeoutError",
  "error": "命令执行超时",
  "host": "192.168.1.100"
}
```

常见 `error_type` 值：
- `ConnectionError` — 连接失败/重试耗尽
- `TimeoutError` — 命令超时
- `PermissionError` — 认证失败
- `FileNotFoundError` — 远程文件不存在

## 最佳实践

### 安全
1. 避免命令行传递密码，优先使用私钥或交互式输入
2. 限制 SSH 用户权限（最小权限原则）
3. 使用 `--key` 模式配合 ssh-agent

### 性能
1. `batch` 命令在同一连接内执行，减少握手开销
2. 大文件传输可调整 `chunk_size`
3. 网络不稳定时增加 `--retry` 值

## 故障排查

| 问题 | 排查方法 |
|------|----------|
| 连接失败 | 检查 SSH 服务、防火墙、端口 |
| 认证失败 | 确认用户名/密码/密钥路径正确 |
| 命令超时 | 增大 `--timeout`，检查命令是否需要交互输入 |
| 文件传输失败 | 检查路径权限、磁盘空间 |
| MD5 不匹配 | 检查传输过程是否被中断 |
