import re
from typing import Iterable, List, Optional, Tuple

try:
    from capstone import Cs, CS_ARCH_AARCH64, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM, CS_OP_REG
    from capstone.x86_const import X86_REG_RIP
except ImportError:  # pragma: no cover - CLI dependency bootstrap handles this
    Cs = None

from .macho import MachOImage


class Disassembler:
    def __init__(self, image: MachOImage):
        self.image = image
        if Cs is None:
            raise RuntimeError("capstone is required")
        if image.arch == "arm64":
            self.md = Cs(CS_ARCH_AARCH64, 0)
        elif image.arch == "x64":
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            raise ValueError(f"unsupported arch: {image.arch}")
        self.md.detail = True
        self.md.skipdata = True

    def instructions(self, start: int, size: int):
        try:
            data = self.image.read_va(start, size)
        except ValueError:
            return []
        return list(self.md.disasm(data, start))

    def text_instructions(self):
        sec, data = self.image.section_bytes("__TEXT", "__text")
        return self.md.disasm(data, sec.address)

    def looks_like_function_entry(self, address: int) -> bool:
        ins = self.instructions(address, 32)
        meaningful = [i for i in ins if i.mnemonic not in ("nop", "endbr64")]
        if not meaningful:
            return False
        if self.image.arch == "arm64":
            first = meaningful[0]
            if first.mnemonic == "stp" and "x29, x30" in first.op_str and "!" in first.op_str:
                return True
            if first.mnemonic == "sub" and first.op_str.startswith("sp, sp, #"):
                return any(i.mnemonic == "stp" and ("x29" in i.op_str or "x30" in i.op_str) for i in meaningful[1:5])
            return False
        first_two = meaningful[:3]
        if len(first_two) >= 2 and first_two[0].mnemonic == "push" and first_two[0].op_str == "rbp" and first_two[1].mnemonic == "mov" and first_two[1].op_str == "rbp, rsp":
            return True
        if meaningful[0].mnemonic in ("push", "sub"):
            return True
        return False

    def direct_calls(self, start: int, size: int) -> List[Tuple[int, int]]:
        out: List[Tuple[int, int]] = []
        for i in self.instructions(start, size):
            if self.image.arch == "arm64" and i.mnemonic == "bl" and i.operands and i.operands[0].type == CS_OP_IMM:
                out.append((i.address, int(i.operands[0].imm)))
            elif self.image.arch == "x64" and i.mnemonic == "call" and i.operands and i.operands[0].type == CS_OP_IMM:
                out.append((i.address, int(i.operands[0].imm)))
        return out

    def find_string_references(self, string_address: int) -> List[int]:
        if self.image.arch == "arm64":
            return self._find_arm64_refs(string_address)
        return self._find_x64_refs(string_address)

    def find_previous_function_entry(self, address: int, max_back: int = 0x1000) -> Optional[int]:
        if self.image.arch == "x64":
            text, data = self.image.section_bytes("__TEXT", "__text")
            try:
                off = address - text.address
            except Exception:
                return None
            if off < 0 or off > len(data):
                return None
            lo = max(0, off - max_back)
            rel = data[lo:off].rfind(b"\x55\x48\x89\xe5")
            if rel >= 0:
                return text.address + lo + rel
            rel = data[lo:off].rfind(b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5")
            if rel >= 0:
                return text.address + lo + rel
            return None
        step = 4 if self.image.arch == "arm64" else 1
        start = max(self.image.section("__TEXT", "__text").address, address - max_back)
        candidates: List[int] = []
        cur = start
        while cur < address:
            if self.image.arch == "arm64":
                try:
                    word = int.from_bytes(self.image.read_va(cur, 4), "little")
                except ValueError:
                    cur += step
                    continue
                likely = (word & 0xFFC003FF) == 0xD10003FF or (word & 0xFFFFFC00) == 0xA9BF7C00
                if not likely:
                    cur += step
                    continue
            if self.looks_like_function_entry(cur):
                candidates.append(cur)
                cur += max(step, 4 if self.image.arch == "arm64" else 1)
            else:
                cur += step
        return candidates[-1] if candidates else None

    def _find_x64_refs(self, target: int) -> List[int]:
        out = set()
        text, data = self.image.section_bytes("__TEXT", "__text")
        rex_pat = re.compile(rb"\x48[\x8d\x8b\x89\x3b\x8a][\x05\x0d\x15\x1d\x25\x2d\x35\x3d](?s:....)")
        for m in rex_pat.finditer(data):
            pos = m.start()
            disp = int.from_bytes(data[pos + 3 : pos + 7], "little", signed=True)
            if text.address + pos + 7 + disp == target:
                out.add(text.address + pos)
        pat32 = re.compile(rb"[\x8b\x8d\x3b\x39\xc7\x83\x81][\x05\x0d\x15\x1d\x25\x2d\x35\x3d](?s:....)")
        for m in pat32.finditer(data):
            pos = m.start()
            disp = int.from_bytes(data[pos + 2 : pos + 6], "little", signed=True)
            if text.address + pos + 6 + disp == target:
                out.add(text.address + pos)
        return sorted(out)

    def _find_arm64_refs(self, target: int) -> List[int]:
        out: List[int] = []
        text, data = self.image.section_bytes("__TEXT", "__text")
        target_page = target & ~0xFFF
        # Fast hand-decoder for the ADRP + ADD/LDR forms used for cstring references.
        for off in range(0, max(0, len(data) - 48), 4):
            word = int.from_bytes(data[off : off + 4], "little")
            if word & 0x9F000000 != 0x90000000:
                continue
            pc = text.address + off
            reg, page = _decode_adrp(word, pc)
            if page != target_page:
                continue
            for joff in range(off + 4, min(off + 48, len(data) - 4), 4):
                w = int.from_bytes(data[joff : joff + 4], "little")
                val = _decode_add_or_ldr_address(w, reg, page)
                if val == target:
                    out.append(pc)
                    break
                if _writes_arm_reg(w, reg) and val is None:
                    break
        return out


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _decode_adrp(word: int, pc: int) -> Tuple[int, int]:
    reg = word & 0x1F
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    imm = _sign_extend((immhi << 2) | immlo, 21) << 12
    page = (pc & ~0xFFF) + imm
    return reg, page


def _decode_add_or_ldr_address(word: int, reg: int, page: int) -> Optional[int]:
    rd = word & 0x1F
    rn = (word >> 5) & 0x1F
    if rn != reg:
        return None
    # ADD (immediate), 64-bit, no flags: add xd, xn, #imm12{, lsl #12}
    if (word & 0x7F000000) == 0x11000000:
        shift = (word >> 22) & 0x3
        imm = (word >> 10) & 0xFFF
        if shift == 1:
            imm <<= 12
        elif shift != 0:
            return None
        return page + imm
    # Unsigned immediate LDR forms. scale is encoded in bits 31:30 for these load/store classes.
    if (word & 0x3B000000) == 0x39000000 or (word & 0x3B000000) == 0x39000000:
        size = (word >> 30) & 0x3
        imm12 = (word >> 10) & 0xFFF
        return page + (imm12 << size)
    return None


def _writes_arm_reg(word: int, reg: int) -> bool:
    return (word & 0x1F) == reg
