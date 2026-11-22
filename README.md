# 天翼网关超级管理员密码读取工具

[![self-test](https://github.com/gshtwy/tianyi-gateway-tool/actions/workflows/self-test.yml/badge.svg)](https://github.com/gshtwy/tianyi-gateway-tool/actions/workflows/self-test.yml)

单文件、零依赖的 Python 工具：读取自家天翼网关（烽火 HG5585F）的超级管理员账号密码，并可选择开启或关闭 Telnet。

- 单一 `.py` 文件，下载即用
- 纯 Python 标准库 + 内置 AES，不需要 pip 安装任何东西
- Windows / macOS / Linux 同一份文件，Python 3.7 ~ 3.13
- 不写死 IP、不写死 MAC：IP 运行时输入，MAC 从光猫自动读取，读不到可手动输入机身贴纸 MAC

## 兼容范围

| 状态 | 型号 / 固件 |
| --- | --- |
| 已实测 | 烽火 HG5585F（电信版），硬件 V4.2.0 / 软件 V4.20.M5000 |
| 理论可试 | 同平台、同 fh_tool 接口的其它烽火天翼网关（未验证，欢迎在 Issue 反馈实测结果） |
| 不适用 | 华为、中兴等其它厂商代工的天翼网关（接口不同，本工具无效） |

## 快速开始

1. 在本仓库的 Releases 里下载 `get_superpwd.py`（或直接下载仓库里的同名文件）
2. 电脑连着光猫所在的网络，打开终端运行：
   - macOS / Linux：`python3 get_superpwd.py`
   - Windows：`py get_superpwd.py`
3. 按提示输入光猫 IP（直接回车默认 192.168.1.1），其余步骤全自动：局域网检查 → 读 MAC → 读设备信息 → 读超级管理员密码 → 选择 Telnet 操作（1 开启 / 2 关闭 / 3 不动，回车默认不动）

离线自检（不连接光猫，只验证本机 Python 环境）：

```
python3 get_superpwd.py --self-test
```

看到 `SELF-TEST OK` 说明本机环境没问题。

## Telnet 说明

- 开启后账号：`telnetadmin`
- 密码由脚本按本机 MAC 自动算出并打印：固定前缀 + MAC 后 6 位；`su` 提权密码同理。换一台光猫密码自动跟着变，不要照抄别人的。
- Telnet 登录连错 3 次会锁定约 300 秒，不要反复猜密码。
- Telnet 是明文协议，只在局域网内使用，不要映射到公网；不用时建议用本工具关闭。

## 原理

见 [docs/principle.md](docs/principle.md)。常见问题见 [docs/faq.md](docs/faq.md)。

## 免责声明

- 本工具仅用于管理你本人拥有或被授权管理的设备，使用风险自担。
- 读取到的超级管理员密码属于敏感信息，请勿在 Issue、截图或聊天中公开发送；反馈问题时 MAC 只发前 6 位、密码一律不要发、截图先打码。
- 本工具在本地运行，只与你输入的光猫地址通信，不向任何其它地址发送数据。

## License

MIT
