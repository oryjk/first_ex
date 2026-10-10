"""Conservative arm64 pattern analysis. Unsupported compiler/layout changes fail closed."""
import mmap
import re
import struct
import subprocess
import sys
from pathlib import Path

PRETTY_NEEDLE = b'applet::AppletIndexContainer::OnLoadStart(bool'


class MachOImage:
    def __init__(self, path):
        with open(path, 'rb') as fp:
            self.data = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
        if len(self.data) < 32 or struct.unpack_from('<I', self.data)[0] != 0xFEEDFACF or struct.unpack_from('<I', self.data, 4)[0] != 0x100000C:
            self.data.close()
            raise ValueError('输入必须是 little-endian arm64 Mach-O slice')
        self.sections, self.segments = {}, []
        ncmds, sizeofcmds = struct.unpack_from('<II', self.data, 16)
        end, pos = 32 + sizeofcmds, 32
        if end > len(self.data):
            raise ValueError('Mach-O load commands 越界')
        for _ in range(ncmds):
            if pos + 8 > end:
                raise ValueError('截断的 Mach-O load command')
            cmd, size = struct.unpack_from('<II', self.data, pos)
            if size < 8 or pos + size > end:
                raise ValueError('非法 Mach-O cmdsize')
            if cmd == 0x19:
                if size < 72:
                    raise ValueError('截断的 LC_SEGMENT_64')
                name = self.data[pos + 8:pos + 24].split(b'\0')[0].decode('ascii')
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<4Q', self.data, pos + 24)
                nsects = struct.unpack_from('<I', self.data, pos + 64)[0]
                if size < 72 + nsects * 80 or fileoff + filesize > len(self.data):
                    raise ValueError('Mach-O segment 越界')
                self.segments.append((name, vmaddr, vmsize, fileoff, filesize))
                for i in range(nsects):
                    s = pos + 72 + i * 80
                    section = self.data[s:s + 16].split(b'\0')[0].decode('ascii')
                    addr, length = struct.unpack_from('<QQ', self.data, s + 32)
                    offset = struct.unpack_from('<I', self.data, s + 48)[0]
                    self.sections[(name, section)] = (addr, length, offset)
            pos += size
        text_segments = [s for s in self.segments if s[0] == '__TEXT']
        if len(text_segments) != 1 or ('__TEXT', '__text') not in self.sections:
            raise ValueError('缺少唯一 __TEXT / __text')
        self.module_base = text_segments[0][1]
        self.text_addr, self.text_size, off = self.sections[('__TEXT', '__text')]
        if off + self.text_size > len(self.data) or self.text_size % 4 or sys.byteorder != 'little':
            raise ValueError('不支持的 __text 长度或宿主端序')
        self.text_words = memoryview(self.data)[off:off + self.text_size].cast('I')

    def module_offset(self, address):
        return address - self.module_base

    def file_to_vm(self, offset):
        matches = [vm + offset - fo for _, vm, _, fo, fs in self.segments if fo <= offset < fo + fs]
        if len(matches) != 1:
            raise ValueError('文件偏移没有唯一的 segment 映射')
        return matches[0]

    def pretty_targets(self):
        section = self.sections.get(('__TEXT', '__cstring'))
        if not section:
            raise ValueError('缺少 __cstring，需人工分析')
        _, size, off = section
        end, pos, targets = off + size, off, set()
        while True:
            hit = self.data.find(PRETTY_NEEDLE, pos, end)
            if hit < 0:
                break
            start = self.data.rfind(b'\0', off, hit) + 1
            if start < off:
                start = off
            stop = self.data.find(b'\0', hit, end)
            if stop < 0 or stop - start > 2048:
                raise ValueError('异常 pretty 字符串边界')
            # Only the exact C string start, never arbitrary nearby bytes.
            targets.add(self.file_to_vm(start))
            pos = hit + len(PRETTY_NEEDLE)
        if not targets:
            raise ValueError('找不到 OnLoadStart pretty 字符串；需人工分析')
        return targets

    def close(self):
        self.text_words.release()
        self.data.close()


def adrp_target(word, pc):
    if (word & 0x9F000000) != 0x90000000:
        return None
    imm = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 3)
    if imm & 0x100000:
        imm -= 0x200000
    return (pc & ~0xFFF) + (imm << 12)


def is_add_imm(word):
    # sf=1, op=0, S=0; unlike the old mask, SUB/ADDS cannot match.
    if (word & 0xFF800000) != 0x91000000:
        return None
    return word & 31, (word >> 5) & 31, ((word >> 10) & 0xFFF) << (12 if (word >> 22) & 1 else 0)


def find_xrefs_multi(words, text_addr, target_set):
    res = {target: [] for target in target_set}
    pages = {target & ~0xFFF for target in target_set}
    for i in range(len(words) - 1):
        word = words[i]
        if (word & 0x9F000000) != 0x90000000:
            continue
        pc = text_addr + i * 4
        page = adrp_target(word, pc)
        if page not in pages:
            continue
        # Deliberately support adjacent ADRP+ADD only. Scheduling changes are
        # unsupported, rather than trusting stale register contents.
        add = is_add_imm(words[i + 1])
        if add and add[1] == word & 31 and page + add[2] in res:
            res[page + add[2]].append(pc)
    return res


def ldr32_imm(w):
    return (w & 31, (w >> 5) & 31, ((w >> 10) & 0xFFF) * 4) if w & 0xFFC00000 == 0xB9400000 else None


def ldr64_imm(w):
    return (w & 31, (w >> 5) & 31, ((w >> 10) & 0xFFF) * 8) if w & 0xFFC00000 == 0xF9400000 else None


def ldrsb64(w):
    # LDRSB Xt, [Xn, #unsigned byte offset], not LDURSB/unscaled.
    return (w & 31, (w >> 5) & 31, (w >> 10) & 0xFFF) if w & 0xFFC00000 == 0x39800000 else None


def cmp32(w, imm):
    return (w >> 5) & 31 if w & 0xFFC0001F == 0x7100001F and (w >> 10) & 0xFFF == imm else None


def signed(n, bits):
    return n - (1 << bits) if n & (1 << (bits - 1)) else n


def cond_target(w, pc):
    return pc + signed((w >> 5) & 0x7FFFF, 19) * 4


def parse_guard_block(words, text_addr, cmp_pc, cmp_rn):
    base = (cmp_pc - text_addr) // 4
    start = base - 9
    if start < 0 or base + 5 >= len(words):
        return None
    w = words[start:base + 6]
    first, second, third = (ldr64_imm(w[i]) for i in (1, 2, 3))
    mode, scene, marker, size_load = ldr32_imm(w[5]), ldr32_imm(w[8]), ldrsb64(w[11]), ldr64_imm(w[13])
    if not all((first, second, third, mode, scene, marker, size_load)):
        return None
    if any(r == 31 for item in (first, second, third, mode, scene, marker, size_load) for r in item[:2]):
        return None
    if not (w[0] & 0xFF000000 == 0x34000000 and first[0] == second[1] and second[0] == third[1]):
        return None
    obj = third[0]
    if mode[1] != obj or scene[1] != obj or marker[1] != obj or scene[0] != cmp_rn:
        return None
    if cmp32(w[6], 1) != mode[0] or cmp32(w[9], 1101) != scene[0]:
        return None
    if w[4] & 0xFF000000 != 0xB4000000 or w[4] & 31 != obj:
        return None
    if any(w[i] & 0xFF00001F != 0x54000001 for i in (7, 10)):
        return None
    # Confirm alternate libc++ marker +23, long-string size +8 and bit 63.
    url = marker[2] - 23
    if url < 0 or size_load != (marker[0], obj, url + 8):
        return None
    bit = ((w[12] >> 31) << 5) | ((w[12] >> 19) & 31)
    if w[12] & 0x7F000000 != 0x36000000 or bit != 63 or w[12] & 31 != marker[0]:
        return None
    if w[14] & 0xFF000000 != 0xB4000000 or w[14] & 31 != marker[0]:
        return None
    exits = {cond_target(w[i], text_addr + (start + i) * 4) for i in (0, 4, 7, 10, 14)}
    if len(exits) != 1:
        return None
    if third[2] != 16:
        raise ValueError(f'第三跳为 {third[2]}，当前 hook.js 固定 +16；停止生成，需先适配脚本')
    return {'hops': [first[2], second[2], third[2]], 'scene': scene[2], 'mode': mode[2], 'url': url,
            'guard_pc': cmp_pc, 'first_load_pc': text_addr + (start + 1) * 4,
            'boolean_pc': text_addr + start * 4, 'this_register': first[1], 'debug_register': w[0] & 31}


def is_stp_x29_sp(w):
    return w >> 24 == 0xA9 and w & 31 == 29 and (w >> 10) & 31 == 30 and (w >> 5) & 31 == 31


def prologue_candidates(words, text_addr, xref):
    hi = (xref - text_addr) // 4
    result = []
    for k in range(max(0, hi - 0x800 // 4), hi):
        if words[k] & 0xFF8003FF != 0xD10003FF:
            continue
        for j in range(k + 1, min(k + 9, hi)):
            if is_stp_x29_sp(words[j]):
                if any(is_add_imm(words[q]) and (words[q] & 0x3FF) == 0x3FD for q in range(j + 1, min(j + 3, hi))):
                    result.append(text_addr + k * 4)
                break
    return result


def disassemble(path, start, stop):
    tool = subprocess.run(['xcrun', '--find', 'llvm-objdump'], check=True, text=True, capture_output=True).stdout.strip()
    result = subprocess.run([tool, '-d', f'--start-address={hex(start)}', f'--stop-address={hex(stop)}', str(path)], check=True, text=True, capture_output=True)
    instructions = {}
    for line in result.stdout.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(\S+)\s*(.*)', line)
        if m:
            instructions[int(m[1], 16)] = (m[2].lower(), m[3].split(';')[0].strip())
    if start not in instructions:
        raise ValueError('LLVM 未返回候选入口指令')
    return instructions


def successors(instructions, pc):
    mnemonic, ops = instructions[pc]
    next_pc = pc + 4
    if mnemonic in ('ret', 'retaa', 'retab', 'br', 'braa', 'brab'):
        return []
    if mnemonic == 'b' or mnemonic.startswith('b.') or mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
        target = re.search(r'(?:^|,\s*)(0x[0-9a-f]+)', ops)
        if not target:
            raise ValueError('无法解码分支目标')
        dest = int(target[1], 16)
        return [p for p in ([dest] if mnemonic == 'b' else [dest, next_pc]) if p in instructions]
    return [next_pc] if next_pc in instructions else []


def transfer(state, mnemonic, operands):
    result = list(state)
    regs = re.findall(r'\b([xw])(\d+|zr)\b', operands)
    if mnemonic in ('bl', 'blr', 'blraa', 'blrab'):
        result[:19] = [None] * 19
        result[30] = None
    elif mnemonic == 'mov' and len(regs) == 2 and regs[0][1] != 'zr':
        dst, src = int(regs[0][1]), regs[1][1]
        origin = state[int(src)] if src != 'zr' else None
        result[dst] = origin if (regs[0][0] == regs[1][0] == 'x' or origin == 'debug') else None
    elif mnemonic.startswith('b.') or mnemonic in ('b', 'br', 'ret', 'retab', 'retaa', 'cbz', 'cbnz', 'tbz', 'tbnz', 'cmp', 'cmn', 'tst', 'ccmp', 'ccmn', 'nop', 'fcmp', 'fccmp'):
        pass
    elif mnemonic.startswith(('stxr', 'stlxr', 'stxp', 'stlxp')):
        if regs and regs[0][1] != 'zr':
            result[int(regs[0][1])] = None
    elif mnemonic.startswith('st'):
        pass
    elif mnemonic.startswith('swp'):
        if len(regs) > 1 and regs[1][1] != 'zr':
            result[int(regs[1][1])] = None
    else:
        # Unknown result-producing operations invalidate their destination;
        # loads of pairs invalidate both. Only MOV preserves argument identity.
        count = 2 if mnemonic.startswith('ldp') else 1
        for _, r in regs[:count]:
            if r != 'zr':
                result[int(r)] = None
    if '!' in operands or re.search(r'\],\s*#', operands):
        base = re.search(r'\[x(\d+)', operands)
        if base:
            result[int(base[1])] = None
    return tuple(result)


def argument_states(instructions, entry):
    initial = [None] * 31
    initial[0], initial[1] = 'this', 'debug'
    states, pending = {entry: tuple(initial)}, [entry]
    while pending:
        pc = pending.pop()
        out = transfer(states[pc], *instructions[pc])
        for nxt in successors(instructions, pc):
            old = states.get(nxt)
            merged = out if old is None else tuple(a if a == b else None for a, b in zip(old, out))
            if merged != old:
                states[nxt] = merged
                pending.append(nxt)
    return states


def scan_image(path):
    image = MachOImage(path)
    try:
        words, address = image.text_words, image.text_addr
        targets = image.pretty_targets()
        refs = find_xrefs_multi(words, address, targets)
        candidates = {}
        evidence = {'pretty_strings': [hex(t) for t in sorted(targets)], 'xrefs': sorted(hex(x) for xs in refs.values() for x in xs),
                    'boundary_method': 'bounded prologue + reachable CFG + argument identity; not a symbol table'}
        for xref in sorted({x for xs in refs.values() for x in xs}):
            for start in prologue_candidates(words, address, xref):
                stop = min(start + 0x4000, address + image.text_size)
                ins = disassemble(path, start, stop)
                states = argument_states(ins, start)
                if xref not in states:
                    continue
                for pc in sorted(states):
                    if pc < address or pc >= address + image.text_size:
                        continue
                    i = (pc - address) // 4
                    rn = cmp32(words[i], 1101)
                    if rn is None:
                        continue
                    g = parse_guard_block(words, address, pc, rn)
                    if not g:
                        continue
                    root = states.get(g['first_load_pc'])
                    boolean = states.get(g['boolean_pc'])
                    if not root or not boolean or root[g['this_register']] != 'this' or boolean[g['debug_register']] != 'debug':
                        continue
                    signature = (start, pc)
                    candidates[signature] = {**g, 'function_start': start, 'xref': xref}
        if len(candidates) != 1:
            raise ValueError(f'必须只有一个通过控制流/ABI 校验的候选，实际 {len(candidates)} 个；停止生成，需人工分析。引用: {evidence["xrefs"]}')
        guard = next(iter(candidates.values()))
        config = {'LoadStartHookOffset': hex(image.module_offset(guard['function_start'])),
                  'LoadStartHookOffset2': hex(image.module_offset(guard['function_start'])),
                  'StructOffset': guard['hops'][1], 'FirstHopOffset': guard['hops'][0],
                  'SceneOffset': guard['scene'], 'WebSocketURLStringOffset': guard['url'],
                  'RemoteDebugModeOffset': guard['mode']}
        evidence.update({'module_vmaddr': hex(image.module_base), 'guard': guard,
                         'limitations': ['arm64 only', 'adjacent ADRP+ADD only', 'three-hop guard signature only',
                                         'libc++ alternate string layout only', 'prologue search 0x800 bytes / CFG window 0x4000 bytes',
                                         'static analysis does not prove CDP runtime behavior']})
        return config, evidence
    finally:
        image.close()
