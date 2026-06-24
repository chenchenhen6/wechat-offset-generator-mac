import mmap
import struct
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from .models import Section

MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
LC_SEGMENT_64 = 0x19
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C


class MachOError(ValueError):
    pass


class MachOImage:
    def __init__(self, path: Path, data: bytes, arch: str, sections: List[Section]):
        self.path = Path(path)
        self.data = data
        self.arch = arch
        self.sections = sections
        self._section_map: Dict[Tuple[str, str], Section] = {
            (s.segment, s.name): s for s in sections
        }

    @classmethod
    def from_path(cls, path: Path) -> "MachOImage":
        path = Path(path)
        data = path.read_bytes()
        if len(data) < 32:
            raise MachOError(f"not a Mach-O file: {path}")
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != MH_MAGIC_64:
            if magic == MH_CIGAM_64:
                raise MachOError("big-endian Mach-O is not supported")
            raise MachOError(f"only thin 64-bit Mach-O is supported: {path}")
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
            "<IiiIIIII", data, 0
        )
        if cputype == CPU_TYPE_ARM64:
            arch = "arm64"
        elif cputype == CPU_TYPE_X86_64:
            arch = "x64"
        else:
            raise MachOError(f"unsupported CPU type: 0x{cputype:x}")

        sections: List[Section] = []
        off = 32
        for _ in range(ncmds):
            if off + 8 > len(data):
                raise MachOError("truncated load command")
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmdsize < 8 or off + cmdsize > len(data):
                raise MachOError("invalid load command size")
            if cmd == LC_SEGMENT_64:
                segname_b, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, segflags = struct.unpack_from(
                    "<16sQQQQiiII", data, off + 8
                )
                segname = _clean_name(segname_b)
                sec_off = off + 72
                for _j in range(nsects):
                    if sec_off + 80 > off + cmdsize:
                        raise MachOError("truncated section_64")
                    sectname_b, sec_seg_b, addr, size, offset, align, reloff, nreloc, flags, r1, r2, r3 = struct.unpack_from(
                        "<16s16sQQIIIIIIII", data, sec_off
                    )
                    sections.append(
                        Section(
                            segment=_clean_name(sec_seg_b) or segname,
                            name=_clean_name(sectname_b),
                            address=addr,
                            size=size,
                            file_offset=offset,
                        )
                    )
                    sec_off += 80
            off += cmdsize
        return cls(path, data, arch, sections)

    def section(self, segment: str, name: str) -> Section:
        try:
            return self._section_map[(segment, name)]
        except KeyError:
            raise KeyError(f"missing Mach-O section {segment},{name}")

    def va_to_offset(self, address: int) -> int:
        for s in self.sections:
            if s.address <= address < s.address + s.size:
                return s.file_offset + (address - s.address)
        raise ValueError(f"address 0x{address:x} is not mapped")

    def offset_to_va(self, offset: int) -> int:
        for s in self.sections:
            if s.file_offset <= offset < s.file_offset + s.size:
                return s.address + (offset - s.file_offset)
        raise ValueError(f"offset 0x{offset:x} is not mapped")

    def read_va(self, address: int, size: int) -> bytes:
        off = self.va_to_offset(address)
        return self.data[off : off + size]

    def section_bytes(self, segment: str, name: str) -> Tuple[Section, bytes]:
        sec = self.section(segment, name)
        return sec, self.data[sec.file_offset : sec.file_offset + sec.size]

    def find_bytes(self, needle: bytes, sections: Iterable[Section] = None) -> List[int]:
        hay_sections = list(sections) if sections is not None else self.sections
        out: List[int] = []
        for sec in hay_sections:
            if sec.file_offset >= len(self.data):
                continue
            blob = self.data[sec.file_offset : min(len(self.data), sec.file_offset + sec.size)]
            start = 0
            while True:
                idx = blob.find(needle, start)
                if idx < 0:
                    break
                out.append(sec.address + idx)
                start = idx + 1
        return out


def _clean_name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", "replace")
