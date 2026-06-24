from typing import Dict, Iterable, List, Optional, Tuple

from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from capstone.x86_const import X86_REG_RDI

from .disasm import Disassembler
from .macho import MachOImage
from .models import Recognition, SceneRecognition


class RecognitionError(RuntimeError):
    pass


def _is_mem(op) -> bool:
    return getattr(op, "type", None) in (CS_OP_MEM, 3)


def _is_imm(op) -> bool:
    return getattr(op, "type", None) in (CS_OP_IMM, 2)


def recognize_load_start(image: MachOImage) -> Recognition:
    d = Disassembler(image)
    anchors = _find_cstrings(
        image,
        [
            b"AppletIndexContainer::OnLoadStart",
            b"OnLoadStart",
        ],
    )
    evidence = []
    candidates = []
    for label, addrs in anchors.items():
        for saddr in addrs:
            refs = d.find_string_references(saddr)
            for ref in refs:
                entry = d.find_previous_function_entry(ref, 0x3000)
                if entry is not None:
                    candidates.append(entry)
                    evidence.append(f"{label.rstrip(chr(0))} at 0x{saddr:X} referenced near 0x{ref:X}; function 0x{entry:X}")
    # Prefer functions whose first block directly contains the string xref and are plausible entries.
    uniq = sorted(set(candidates))
    if not uniq:
        raise RecognitionError("LoadStart: no candidate from OnLoadStart strings")
    if len(uniq) > 1:
        # Some builds have wrapper/local helper refs. Choose the smallest candidate only when refs cluster in same function.
        scored = []
        for c in uniq:
            score = sum(1 for line in evidence if f"function 0x{c:X}" in line)
            if d.looks_like_function_entry(c):
                score += 10
            scored.append((score, c))
        scored.sort(reverse=True)
        # Full C++ signature anchor is decisive; generic OnLoadStart log text can have several refs.
        signature = [c for c in uniq if any("AppletIndexContainer::OnLoadStart" in line and f"function 0x{c:X}" in line for line in evidence)]
        if len(signature) == 1:
            address = signature[0]
        elif len(scored) > 1 and scored[0][0] == scored[1][0]:
            raise RecognitionError(f"LoadStart ambiguous: {[hex(x) for x in uniq]}")
        else:
            address = scored[0][1]
    else:
        address = uniq[0]
    return Recognition(address, "high", evidence + ["OnLoadStart string-reference function entry selected"])


def recognize_scene_hook(image: MachOImage) -> SceneRecognition:
    d = Disassembler(image)
    if image.arch == "arm64":
        return _recognize_scene_arm64(image, d)
    return _recognize_scene_x64(image, d)


def recognize_cdp_filter(image: MachOImage) -> Recognition:
    d = Disassembler(image)
    anchors = _find_cstrings(image, [b"SendToClientFilter\0", b"sendToClientFilter\0"])
    funcs = []
    evidence = []
    for label, addrs in anchors.items():
        for saddr in addrs:
            for ref in d.find_string_references(saddr):
                entry = d.find_previous_function_entry(ref, 0x5000)
                if entry is not None:
                    funcs.append(entry)
                    evidence.append(f"{label.rstrip(chr(0))} at 0x{saddr:X} referenced near 0x{ref:X}; source function 0x{entry:X}")
    funcs = sorted(set(funcs))
    matches = []
    for func in funcs:
        for call_addr, target in d.direct_calls(func, 0x7000):
            if d.looks_like_function_entry(target) and _call_followed_by_ret_plus8_cmp_6(d, call_addr, 0x80):
                matches.append((call_addr, target))
                evidence.append(f"direct call 0x{call_addr:X}->0x{target:X}; return +8 compared with 6")
    if matches:
        matches.sort()
        return Recognition(matches[0][1], "high", evidence + ["first SendToClientFilter direct call whose return +8 is compared with 6"])
    candidates = []
    if not matches:
        # fallback: scan all text for direct calls followed by return +8 == 6 in functions that mention Filter/SourceMap-like cstrings
        candidates = _scan_cdp_pattern(d, evidence)
    if len(candidates) != 1:
        raise RecognitionError(f"CDP ambiguous/unresolved: {[hex(c) for c in candidates]}")
    return Recognition(candidates[0], "high", evidence + ["+8 field compared with 6 after CDP filter call"])


def recognize_resource_cache_policy(image: MachOImage) -> Optional[Recognition]:
    # Deliberately conservative: only return a high-confidence result when a full anchor chain is implemented.
    return None


def _find_cstrings(image: MachOImage, needles: Iterable[bytes]) -> Dict[str, List[int]]:
    sections = [s for s in image.sections if s.segment == "__TEXT" and s.name in ("__cstring", "__const")]
    out: Dict[str, List[int]] = {}
    for needle in needles:
        starts: List[int] = []
        for sec in sections:
            blob = image.data[sec.file_offset : sec.file_offset + sec.size]
            pos = blob.find(needle)
            while pos >= 0:
                start = blob.rfind(b"\0", 0, pos) + 1
                starts.append(sec.address + start)
                pos = blob.find(needle, pos + 1)
        if starts:
            out[needle.decode("utf-8", "replace")] = sorted(set(starts))
    return out


def _recognize_scene_arm64(image: MachOImage, d: Disassembler) -> SceneRecognition:
    candidates = []
    evidence = []
    for entry, anchor_line in _scene_anchor_entries(image, d):
        if not _arm_function_loads_x0_plus_8(d, entry):
            continue
        calls = d.direct_calls(entry, 0x180)
        for idx in range(0, len(calls) - 1):
            first = calls[idx][1]
            second = calls[idx + 1][1]
            st = _arm_accessor_struct_offset(d, first)
            sc = _arm_accessor_scene_offset(d, second)
            if st is not None and sc is not None:
                candidates.append((entry, st, sc))
                evidence.append(
                    f"{anchor_line}; ARM scene caller 0x{entry:X}: [x0+8], accessor +{st}, scene +{sc}, cmp 1101"
                )
    candidates = sorted(set(candidates))
    if len(candidates) == 1:
        pc, st, sc = candidates[0]
        return SceneRecognition(pc, st, sc, evidence)

    # Conservative fallback for builds whose WebSocket string references are not recognized.
    candidates = []
    text, data = image.section_bytes("__TEXT", "__text")
    for off in range(0, len(data) - 4, 4):
        pc = text.address + off
        word = int.from_bytes(data[off : off + 4], "little")
        # ldr Xt, [x0,#8]
        if (word & 0xFFC00000) != 0xF9400000 or ((word >> 5) & 31) != 0 or ((word >> 10) & 0xFFF) != 1:
            continue
        entry = d.find_previous_function_entry(pc + 4, 0x80)
        if entry is None or pc - entry > 0x40:
            continue
        ins = d.instructions(entry, 0x120)
        if not ins:
            continue
        calls = d.direct_calls(entry, 0x80)
        for idx in range(0, len(calls) - 1):
            first = calls[idx][1]
            second = calls[idx + 1][1]
            st = _arm_accessor_struct_offset(d, first)
            sc = _arm_accessor_scene_offset(d, second)
            if st is not None and sc is not None:
                candidates.append((entry, st, sc))
                evidence.append(f"ARM scene caller 0x{entry:X}: [x0+8], accessor +{st}, scene +{sc}, cmp 1101")
    candidates = sorted(set(candidates))
    if len(candidates) != 1:
        raise RecognitionError(f"scene hook ambiguous/unresolved: {candidates[:8]}")
    pc, st, sc = candidates[0]
    return SceneRecognition(pc, st, sc, evidence)


def _recognize_scene_x64(image: MachOImage, d: Disassembler) -> SceneRecognition:
    candidates = []
    evidence = []
    for entry, anchor_line in _scene_anchor_entries(image, d):
        if not _x64_function_loads_rdi_plus_8(d, entry):
            continue
        calls = d.direct_calls(entry, 0x180)
        for idx in range(0, len(calls) - 1):
            st = _x64_accessor_struct_offset(d, calls[idx][1])
            sc = _x64_accessor_scene_offset(d, calls[idx + 1][1])
            if st is not None and sc is not None:
                candidates.append((entry, st, sc))
                evidence.append(
                    f"{anchor_line}; x64 scene caller 0x{entry:X}: [rdi+8], accessor +{st}, scene +{sc}, cmp 1101"
                )
    candidates = sorted(set(candidates))
    if len(candidates) == 1:
        pc, st, sc = candidates[0]
        return SceneRecognition(pc, st, sc, evidence)

    # Conservative fallback for builds whose WebSocket string references are not recognized.
    candidates = []
    text, data = image.section_bytes("__TEXT", "__text")
    pattern = b"\x48\x8b\x7f\x08"  # mov rdi, qword ptr [rdi+8]
    pos = data.find(pattern)
    while pos >= 0:
        pc = text.address + pos
        entry = _x64_previous_prologue(text.address, data, pos, 0x80)
        if entry is not None and pc - entry <= 0x50:
            calls = d.direct_calls(entry, 0x80)
            for idx in range(0, len(calls) - 1):
                st = _x64_accessor_struct_offset(d, calls[idx][1])
                sc = _x64_accessor_scene_offset(d, calls[idx + 1][1])
                if st is not None and sc is not None:
                    candidates.append((entry, st, sc))
                    evidence.append(f"x64 scene caller 0x{entry:X}: [rdi+8], accessor +{st}, scene +{sc}, cmp 1101")
        pos = data.find(pattern, pos + 1)
    candidates = sorted(set(candidates))
    if len(candidates) != 1:
        raise RecognitionError(f"scene hook ambiguous/unresolved: {candidates[:8]}")
    pc, st, sc = candidates[0]
    return SceneRecognition(pc, st, sc, evidence)


def _scene_anchor_entries(image: MachOImage, d: Disassembler) -> List[Tuple[int, str]]:
    anchors = _find_cstrings(image, [b"ws://localhost:9421", b"devtools_web_socket_server.cc"])
    entries: Dict[int, str] = {}
    for label, addrs in anchors.items():
        for saddr in addrs:
            refs = d.find_string_references(saddr)
            for ref in refs:
                entry = d.find_previous_function_entry(ref, 0x6000)
                if entry is not None:
                    entries.setdefault(
                        entry,
                        f"WebSocket marker {label.rstrip(chr(0))} at 0x{saddr:X} referenced near 0x{ref:X}",
                    )
    return sorted(entries.items())


def _arm_function_loads_x0_plus_8(d: Disassembler, entry: int) -> bool:
    for i in d.instructions(entry, 0x80):
        if i.mnemonic == "bl":
            return False
        if i.mnemonic == "ldr" and len(i.operands) >= 2 and _is_mem(i.operands[1]):
            mem = i.operands[1].mem
            if int(mem.disp) == 8 and "x0" in i.op_str:
                return True
    return False


def _x64_function_loads_rdi_plus_8(d: Disassembler, entry: int) -> bool:
    for i in d.instructions(entry, 0x80):
        if i.mnemonic == "call":
            return False
        if i.mnemonic == "mov" and len(i.operands) >= 2 and _is_mem(i.operands[1]):
            mem = i.operands[1].mem
            if mem.base == X86_REG_RDI and int(mem.disp) == 8:
                return True
    return False


def _x64_previous_prologue(text_address: int, data: bytes, pos: int, max_back: int) -> Optional[int]:
    lo = max(0, pos - max_back)
    window = data[lo:pos]
    rel = window.rfind(b"\x55\x48\x89\xe5")
    if rel < 0:
        return None
    return text_address + lo + rel


def _arm_accessor_struct_offset(d: Disassembler, address: int) -> Optional[int]:
    ins = d.instructions(address, 12)
    if len(ins) >= 2 and ins[0].mnemonic == "ldr" and len(ins[0].operands) >= 2 and _is_mem(ins[0].operands[1]):
        mem = ins[0].operands[1].mem
        if mem.base == ins[0].operands[0].reg and 0x400 <= int(mem.disp) <= 0x800 and ins[1].mnemonic == "ret":
            return int(mem.disp)
    return None


def _arm_accessor_scene_offset(d: Disassembler, address: int) -> Optional[int]:
    ins = d.instructions(address, 24)
    if len(ins) >= 4 and ins[0].mnemonic == "ldr" and ins[1].mnemonic.startswith("ldr") and ins[2].mnemonic == "cmp":
        m0 = ins[0].operands[1].mem if len(ins[0].operands) >= 2 and _is_mem(ins[0].operands[1]) else None
        m1 = ins[1].operands[1].mem if len(ins[1].operands) >= 2 and _is_mem(ins[1].operands[1]) else None
        if m0 and m1 and int(m0.disp) == 16 and 0x100 <= int(m1.disp) <= 0x300:
            if any(_is_imm(op) and int(op.imm) == 1101 for op in ins[2].operands):
                return int(m1.disp)
    return None


def _x64_accessor_struct_offset(d: Disassembler, address: int) -> Optional[int]:
    ins = d.instructions(address, 24)
    for i in ins[:4]:
        if i.mnemonic == "mov" and len(i.operands) >= 2 and _is_mem(i.operands[1]):
            mem = i.operands[1].mem
            if mem.base == X86_REG_RDI and 0x400 <= int(mem.disp) <= 0x800:
                return int(mem.disp)
    return None


def _x64_accessor_scene_offset(d: Disassembler, address: int) -> Optional[int]:
    ins = d.instructions(address, 32)
    saw_inner = False
    for i in ins[:6]:
        if i.mnemonic == "mov" and len(i.operands) >= 2 and _is_mem(i.operands[1]) and int(i.operands[1].mem.disp) == 16:
            saw_inner = True
        if saw_inner and i.mnemonic == "cmp" and len(i.operands) >= 2 and _is_mem(i.operands[0]) and _is_imm(i.operands[1]):
            disp = int(i.operands[0].mem.disp)
            if 0x100 <= disp <= 0x300 and int(i.operands[1].imm) == 1101:
                return disp
    return None


def _near_cmp_imm(ins, address: int, imm: int) -> bool:
    seen = False
    for i in ins:
        if i.address < address:
            continue
        if i.address > address + 80:
            return False
        if i.mnemonic == "cmp" and any(_is_imm(op) and int(op.imm) == imm for op in i.operands):
            return True
    return False


def _call_followed_by_ret_plus8_cmp_6(d: Disassembler, call_addr: int, size: int) -> bool:
    ins = d.instructions(call_addr, size)
    if d.image.arch == "arm64":
        # look for ldr w?, [x0,#8] then cmp ..., #6
        reg = None
        saw_cmp = False
        for i in ins[1:14]:
            if i.mnemonic.startswith("ldr") and len(i.operands) >= 2 and _is_mem(i.operands[1]) and int(i.operands[1].mem.disp) == 8:
                reg = i.operands[0].reg
            elif reg is not None and i.mnemonic == "cmp" and any(_is_imm(op) and int(op.imm) == 6 for op in i.operands):
                saw_cmp = True
            elif saw_cmp and i.mnemonic.startswith("b."):
                return True
            elif saw_cmp and i.mnemonic != "nop":
                return False
    else:
        saw_cmp = False
        for i in ins[1:14]:
            if i.mnemonic == "cmp" and len(i.operands) >= 2 and _is_mem(i.operands[0]) and int(i.operands[0].mem.disp) == 8 and _is_imm(i.operands[1]) and int(i.operands[1].imm) == 6:
                saw_cmp = True
            elif saw_cmp and i.mnemonic.startswith("j"):
                return True
            elif saw_cmp and i.mnemonic != "nop":
                return False
    return False


def _scan_cdp_pattern(d: Disassembler, evidence: List[str]) -> List[int]:
    candidates = []
    for i in d.text_instructions():
        if (d.image.arch == "arm64" and i.mnemonic != "bl") or (d.image.arch == "x64" and i.mnemonic != "call"):
            continue
        if not i.operands or not _is_imm(i.operands[0]):
            continue
        target = int(i.operands[0].imm)
        if d.looks_like_function_entry(target) and _call_followed_by_ret_plus8_cmp_6(d, i.address, 0x80):
            candidates.append(target)
            evidence.append(f"global direct call 0x{i.address:X}->0x{target:X}; return +8 compared with 6")
    return sorted(set(candidates))
