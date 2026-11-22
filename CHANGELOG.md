# Changelog

## v1.0.0 - 2026-11-22

首个公开版本（定版）。

- 读取设备信息与超级管理员账号密码（GetDevInfo / GetAdminAccount）
- Telnet 可选操作：1 开启 / 2 关闭 / 3 不动，也可用 --enable-telnet / --disable-telnet 参数
- 光猫 IP 运行时手动输入（回车默认 192.168.1.1），支持 --ip 参数
- MAC 自动从光猫网页接口读回，读不到时手动输入机身贴纸 MAC，无有效 MAC 时退出，不使用任何写死的 MAC
- 局域网检查：私有地址检查、本机出口 IP 与网段比对、8080 端口连通性；端口可达优先，跨网段可达只提示不警告
- 内置纯 Python AES-128-CBC（已用 NIST 标准向量验证），不依赖系统 openssl，Windows / macOS / Linux 通用
- 离线自检模式 --self-test
- 已知限制：关闭 Telnet 为 TelnetEnable telnet=0 对称调用，已在实测机型上验证开启；关闭后请自行确认 23 端口已不可达
