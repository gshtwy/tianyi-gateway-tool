# 原理说明

## 通道

烽火 HG5585F 在 8080 端口开了一个无需登录的 fh_tool 加密 RPC 接口（`/fh_tool/api`）。知道光猫 MAC，就能派生加密密钥，直接调用只读函数读取信息。本工具还可选择调用 TelnetEnable 开启或关闭 Telnet。

注意：这不是老款烽火的 `telnetenable.cgi` 通道，那条路在本机型上不可用。

## 密钥派生与加密

1. 对 MAC 字符串做 SHA256，得到 64 位十六进制摘要
2. 按固定步长从摘要中抽字：以 `2*i+2` 抽 16 个字符作 AES key，以 `3*i+3` 抽 16 个字符作 IV
3. 请求体为紧凑 JSON（如 `{"index":"1","func":"GetAdminAccount"}`），PKCS7 补位后做 AES-128-CBC 加密，再 Base64 编码以文本形式 POST
4. 响应按同一套 key / IV 解密回 JSON

这套派生规则是固件写死的，MAC 错一位都解不开。这也是本工具不写死 MAC、拿不到有效 MAC 就退出的原因。

## MAC 的获取

优先调用免认证接口 `web_get_brmad`（`/cgi-bin/ajax?ajaxmethod=web_get_brmad`）读回设备 MAC；读不到时让用户手动输入机身贴纸 MAC，清洗为 12 位十六进制并校验。

## 调用的函数

| 函数 | 作用 | 类型 |
| --- | --- | --- |
| GetDevInfo | 设备信息（型号、版本、序列号等） | 只读 |
| GetAdminAccount | 超级管理员账号 / 密码 | 只读 |
| GetTelnetInfo | Telnet 信息 | 只读 |
| TelnetEnable (telnet=1 / 0) | 开启 / 关闭 Telnet | 写入，仅在用户明确选择时调用 |

## Telnet 密码派生

- Telnet 账号固定为 `telnetadmin`
- Telnet 密码：固定前缀 `FH-nE7jA%5m` + 本机 MAC 后 6 位（实测机型如此；个别机型为不带后缀的固定值）
- su 提权密码：`Fh@` + 本机 MAC 后 6 位

脚本用变量取 MAC 后 6 位现算，不写死任何一台机器的值。

## 跨系统实现

旧实现用系统 openssl 命令做 AES，Windows 默认没有 openssl。定版内置纯 Python AES 实现（已用 NIST 标准向量验证，并与 openssl 输出逐字节比对一致），从此只依赖 Python 标准库，三个系统行为一致。
