#!/usr/bin/env python3
"""
WMPF/WeChatAppEx 偏移配置生成器
================================
微信更新 WMPF 后，运行本脚本自动推导并生成 First.app 的新配置文件：

    python3 gen_wmpf_config.py            # 干跑：只打印推导结果与证据
    python3 gen_wmpf_config.py --write    # 写入 First 配置目录（自动备份旧文件）

推导原理（全部来自 7.25755 已验证的实战，见同目录 wmpf_handoff.md）：
1. 从 WeChatAppEx.app 的 Info.plist 读版本号（如 7.25755 -> 25755）
2. lipo 抽 WeChatAppEx Framework 的 arm64 slice（__TEXT vmaddr=0 => 偏移=frida module 偏移）
3. 找 pretty 字符串 "applet::AppletIndexContainer::OnLoadStart(bool" 的 ADRP+ADD 引用
4. 在其附近找 cmp #1101(0x44d) 守卫块（scene 魔数，近乎唯一）
5. 从守卫块反解全部偏移：
   - 链三跳:  ldr x8,[this+56] -> ldr x9,[x8+1520] -> ldr x9,[x9+16]
   - scene:   ldr w,[x9+456];  cmp #1101
   - mode:    ldr w,[x9+724];  cmp #1
   - URL 对象: ldrsb x,[x9+SSO字节];  对象起点 = SSO字节 - 23   (Chromium libc++
     alternate 布局; ⚠️ 424 的教训: 别把对象内部字段当起点)
6. 从 pretty 引用点回溯函数序言 -> LoadStartHookOffset
7. CDPFilterHookOffset = null（25755 实测：原生过滤流程可用; 0x934908c 是 JSON
   解析函数的教训——机械推导必须语义验证）

注意：本脚本只做静态推导。若某版本布局大改导致推导失败，会明确报错而不是给错值。
"""

import json
import os
import re
import struct
import subprocess
import sys
import tempfile

WECHAT_APPEX_PLIST = "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Info.plist"
FRAMEWORK = ("/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/"
             "Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework")
FIRST_CFG_DIR = "/Applications/First.app/Contents/Resources/frida/config/mac"
FIRST_HOOK_JS = "/Applications/First.app/Contents/Resources/frida/hook.js"
APPEX_MAIN_EXE = "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/MacOS/WeChatAppEx"

PRETTY_NEEDLE = b"applet::AppletIndexContainer::OnLoadStart(bool"


def die(msg):
    print(f"[✗] {msg}")
    sys.exit(1)


def info(msg):
    print(f"[i] {msg}")


def ok(msg):
    print(f"[✓] {msg}")


# ---------- 1. 版本号 ----------

def read_version():
    out = subprocess.run(["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleVersion",
                          WECHAT_APPEX_PLIST], capture_output=True, text=True)
    if out.returncode != 0:
        die(f"读版本失败: {out.stderr.strip()}")
    raw = out.stdout.strip()          # 形如 "7.25755"
    m = re.search(r"(\d+)$", raw)
    if not m:
        die(f"版本号格式异常: {raw}")
    return int(m.group(1)), raw


# ---------- 2. 抽 slice + 解析 __text ----------

def extract_arm64():
    tmp = tempfile.mktemp(prefix="wmpf_arm64_")
    r = subprocess.run(["lipo", "-thin", "arm64", "-output", tmp, FRAMEWORK],
                       capture_output=True)
    if r.returncode != 0:
        die(f"lipo 失败: {r.stderr.decode()}")
    return tmp


def parse_text_bounds(path):
    with open(path, "rb") as f:
        mh = f.read(32)
        ncmds = struct.unpack_from("<I", mh, 16)[0]
        off = 32
        for _ in range(ncmds):
            f.seek(off)
            hdr = f.read(8)
            cmd, cmdsize = struct.unpack("<II", hdr)
            if cmd == 0x19:  # LC_SEGMENT_64
                body = f.read(cmdsize - 8)
                segname = body[0:16].split(b"\0")[0].decode()
                if segname == "__TEXT":
                    # body 内偏移: segname@0 vmaddr@16 ... nsects@56, sections@64
                    nsects = struct.unpack_from("<I", body, 56)[0]
                    p = 64
                    for _s in range(nsects):
                        sect = body[p:p + 80]
                        sectname = sect[0:16].split(b"\0")[0].decode()
                        if sectname == "__text":
                            addr, size = struct.unpack_from("<QQ", sect, 32)
                            return addr, size
                        p += 80
            off += cmdsize
    die("未找到 __text 节")


# ---------- 3. 指令解码 ----------

def adrp_target(w, pc):
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    return (pc & ~0xFFF) + (imm << 12)


def is_add_imm(w):
    """ADD (imm, 64-bit): 返回 (rd, rn, imm) 或 None"""
    if (w & 0x9F000000) != 0x91000000:
        return None
    return (w & 0x1F, (w >> 5) & 0x1F,
            ((w >> 10) & 0xFFF) << (12 if (w >> 22) & 1 else 0))


def find_xrefs_multi(words, text_addr, target_set):
    """单趟扫描: 返回 {target_off: [xref_pc,...]}（ADRP+ADD 完成 target）"""
    pages = {}
    for t in target_set:
        pages.setdefault(t & ~0xFFF, []).append(t)
    res = {t: [] for t in target_set}
    n = len(words)
    for i in range(n):
        w = words[i]
        if (w & 0x9F000000) != 0x90000000:
            continue
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        pc = text_addr + i * 4
        page = (pc & ~0xFFF) + (imm << 12)
        cands = pages.get(page)
        if not cands:
            continue
        rd = w & 0x1F
        for j in range(i + 1, min(i + 11, n)):
            w2 = words[j]
            a = is_add_imm(w2)
            if a and a[1] == rd:
                addr = page + a[2]
                if addr in res:
                    res[addr].append(pc)
                break
            if (w2 & 0x9F000000) == 0x90000000 and (w2 & 0x1F) == rd:
                break
    return res


def find_1101_cmps(words, text_addr, lo, hi):
    """cmp wN, #0x44d -> [(pc, Rn)]"""
    out = []
    for i in range(max(0, (lo - text_addr) // 4), min(len(words), (hi - text_addr) // 4)):
        w = words[i]
        if (w >> 24) == 0x71 and (w & 0x1F) == 0x1F and ((w >> 10) & 0xFFF) == 0x44D:
            out.append((text_addr + i * 4, (w >> 5) & 0x1F))
    return out


def ldr32_imm(w):
    if (w & 0xFFC00000) != 0xB9400000:
        return None
    return (w & 0x1F, (w >> 5) & 0x1F, ((w >> 10) & 0xFFF) * 4)


def ldr64_imm(w):
    if (w & 0xFFC00000) != 0xF9400000:
        return None
    return (w & 0x1F, (w >> 5) & 0x1F, ((w >> 10) & 0xFFF) * 8)


def ldrsb64(w):
    """LDRSB Xt,[Xn,#imm] (unscaled): 返回 (rt, rn, imm)"""
    if (w & 0xFFC00000) != 0x39800000:
        return None
    return (w & 0x1F, (w >> 5) & 0x1F, (w >> 10) & 0xFFF)


def is_stp_x29_sp(w):
    return ((w >> 24) & 0xFF) == 0xA9 and (w & 0x1F) == 0x1D and ((w >> 5) & 0x1F) == 0x1F


def is_add_x29_sp(w):
    return (w >> 24) == 0x91 and (w & 0x1F) == 0x1D and ((w >> 5) & 0x1F) == 0x1F


def is_sub_sp(w):
    if (w >> 24) != 0xD1:
        return None
    if (w & 0x1F) != 0x1F or ((w >> 5) & 0x1F) != 0x1F:
        return None
    return ((w >> 10) & 0xFFF) << (12 if (w >> 22) & 1 else 0)


def is_mov_reg(w):
    """MOV Xd, Xm (ORR alias): 返回 (dst, src)"""
    if (w & 0xFFE0FFE0) != 0xAA0003E0:
        return None
    if ((w >> 5) & 0x1F) != 0x1F:   # Rn 必须是 XZR
        return None
    return (w & 0x1F, (w >> 16) & 0x1F)


# ---------- 4. 守卫块反解 ----------

def parse_guard_block(words, text_addr, cmp_pc, cmp_rn):
    """从 cmp #1101 所在位置反解全部偏移"""
    base = (cmp_pc - text_addr) // 4

    # scene: 往回找 ldr wRt,[xRn,#imm] 且 Rt==cmp_rn
    scene_off = scene_k = None
    objreg = None
    for k in range(base - 1, base - 8, -1):
        l = ldr32_imm(words[k])
        if l and l[0] == cmp_rn:
            scene_off, objreg, scene_k = l[2], l[1], k
            break
    if scene_off is None:
        return None

    # mode: 再往回找另一对 (ldr32; cmp #1)
    mode_off = mode_k = None
    for k in range(scene_k - 1, max(0, base - 30), -1):
        l = ldr32_imm(words[k])
        if l and l[1] == objreg:
            w2 = words[k + 1]
            if (w2 >> 24) == 0x71 and (w2 & 0x1F) == 0x1F and ((w2 >> 10) & 0xFFF) == 1 \
                    and ((w2 >> 5) & 0x1F) == l[0]:
                mode_off, mode_k = l[2], k
                break
    if mode_off is None:
        return None

    # 链三跳: 从 mode 的基寄存器往上回溯 ldr64 Rt 链
    hops = []
    reg = objreg
    k = mode_k - 1
    floor = max(0, mode_k - 40)
    while len(hops) < 4 and k > floor:
        found = reg_k = None
        while k > floor:
            l = ldr64_imm(words[k])
            if l and l[0] == reg:
                found, reg_k = l, k
                break
            k -= 1
        if not found:
            break
        hops.append(found[2])
        reg = found[1]
        k = reg_k - 1
    if len(hops) < 3:
        return None
    hops.reverse()   # [hop1(56), hop2(1520), hop3(16)]

    # URL: cmp 之后找 ldrsb x?,[xRn,#imm] (Rn==objreg); 对象起点=SSO字节-23
    url_off = None
    for k in range(base + 1, base + 12):
        l = ldrsb64(words[k])
        if l and l[1] == objreg:
            sso = l[2]
            if 23 <= sso < 0x400:
                url_off = sso - 23
            break
    if url_off is None:
        return None

    return {"hops": hops, "scene": scene_off, "mode": mode_off, "url": url_off,
            "guard_pc": cmp_pc}


# ---------- 5. 函数起点回溯 ----------

def find_func_start(words, text_addr, from_pc, max_back=0x400):
    """从内部地址回溯函数序言: sub sp,sp / stp x29,x30 / add x29,sp / mov xN,x0/x1"""
    hi = (from_pc - text_addr) // 4
    lo = max(0, hi - max_back // 4)
    best = None
    for k in range(lo, hi):
        if is_sub_sp(words[k]) is None:
            continue
        for j in range(k + 1, min(k + 9, hi)):
            if is_stp_x29_sp(words[j]):
                for j2 in range(j + 1, min(j + 3, hi)):
                    if is_add_x29_sp(words[j2]):
                        for j3 in range(j2 + 1, min(j2 + 7, hi)):
                            mv = is_mov_reg(words[j3])
                            if mv and mv[1] in (0, 1, 2):
                                best = text_addr + k * 4
                        break
                break
    return best


# ---------- 主流程 ----------

def main():
    write = "--write" in sys.argv

    version, raw = read_version()
    ok(f"WMPF 版本: {raw} (配置编号 {version})")

    slice_path = extract_arm64()
    text_addr, text_size = parse_text_bounds(slice_path)
    info(f"__text @ {hex(text_addr)} size {hex(text_size)}")

    with open(slice_path, "rb") as f:
        data = f.read()
    words = struct.unpack(f"<{text_size // 4}I", data[text_addr:text_addr + text_size])

    # pretty 字符串窗口（含前缀变体），单趟扫描全部引用
    pos = data.find(PRETTY_NEEDLE)
    if pos < 0:
        die("找不到 AppletIndexContainer::OnLoadStart pretty 字符串（布局大改，需人工分析）")
    win = set(range(max(0, pos - 48), pos + len(PRETTY_NEEDLE) + 8))
    res = find_xrefs_multi(words, text_addr, win)
    xrefs = sorted(set(p for lst in res.values() for p in lst))
    if not xrefs:
        die("pretty 字符串无 ADRP+ADD 引用")
    ok(f"OnLoadStart pretty 引用点: {[hex(x) for x in xrefs]}")

    # 引用点附近找 1101 守卫块并反解
    guard = None
    for x in xrefs:
        for cmp_pc, rn in find_1101_cmps(words, text_addr, x - 0x1000, x + 0x1000):
            g = parse_guard_block(words, text_addr, cmp_pc, rn)
            if g:
                g["xref"] = x
                guard = g
                break
        if guard:
            break
    if not guard:
        die("未找到 cmp #1101 守卫块或反解失败（布局大改，需人工分析）")

    hop1, hop2, hop3 = guard["hops"][0], guard["hops"][1], guard["hops"][2]
    ok(f"链: this+{hop1} -> +{hop2} -> +{hop3}   (守卫块 @ {hex(guard['guard_pc'])})")
    ok(f"scene  @ +{guard['scene']}  (cmp #1101)")
    ok(f"mode   @ +{guard['mode']}   (cmp #1)")
    ok(f"URL对象 @ +{guard['url']}   (SSO字节-23)")

    if hop3 != 16:
        info(f"⚠️ 第三跳 {hop3} ≠ 16：First hook.js 硬编码 +16 需要同步修改！")

    func_start = find_func_start(words, text_addr, guard["xref"])
    if not func_start:
        die("函数起点回溯失败（序言模式不匹配，需人工确认）")
    if not (func_start < guard["xref"] < func_start + 0x800):
        die(f"函数起点 {hex(func_start)} 与引用点 {hex(guard['xref'])} 距离异常")
    ok(f"OnLoadStart 函数起点: {hex(func_start)}")

    config = {
        "Version": version,
        "Arch": {
            "arm64": {
                "LoadStartHookOffset": hex(func_start),
                "LoadStartHookOffset2": hex(func_start),
                "StructOffset": hop2,
                "FirstHopOffset": hop1,
                "SceneOffset": guard["scene"],
                "WebSocketURLStringOffset": guard["url"],
                "RemoteDebugModeOffset": guard["mode"],
                "CDPFilterHookOffset": None,
            }
        },
    }

    print()
    print(json.dumps(config, indent=4))

    # 环境检查
    print()
    if os.path.exists(FIRST_HOOK_JS):
        hook = open(FIRST_HOOK_JS).read()
        if "FirstHopOffset" in hook:
            ok("First hook.js 补丁在位")
        else:
            info("⚠️ First hook.js 缺少 FirstHopOffset 补丁（First 升级过？需按归档 hook.patch 重打）")
    r = subprocess.run(["codesign", "-d", "-v", APPEX_MAIN_EXE], capture_output=True, text=True)
    if "flags=0x2(adhoc)" in (r.stderr + r.stdout):
        ok("WeChatAppEx 主程序 adhoc 签名在位")
    else:
        info("⚠️ 主程序非 adhoc 签名（微信整包更新过）→ 退出微信后重跑 codesign，否则 frida 无法 attach")

    if write:
        dst = os.path.join(FIRST_CFG_DIR, f"addresses.{version}.json")
        if os.path.exists(dst):
            bak = dst + ".bak"
            os.rename(dst, bak)
            info(f"已备份旧配置 -> {bak}")
        with open(dst, "w") as fp:
            json.dump(config, fp, indent=4)
        ok(f"已写入 {dst}")
        print("""
下一步：
1. 完全退出并重开 First（重读 hook.js）
2. 启动调试器注入
3. 打开小程序 -> 期待 [server] miniapp client connected
4. devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000
""")
    else:
        info("干跑模式（未写入）。加 --write 写入 First 配置目录。")

    os.unlink(slice_path)


if __name__ == "__main__":
    main()
