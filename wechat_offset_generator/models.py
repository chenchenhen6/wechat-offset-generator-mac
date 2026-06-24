from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass(frozen=True)
class Section:
    segment: str
    name: str
    address: int
    size: int
    file_offset: int

    @property
    def end_address(self) -> int:
        return self.address + self.size

    @property
    def end_offset(self) -> int:
        return self.file_offset + self.size


@dataclass(frozen=True)
class Recognition:
    address: int
    confidence: str
    evidence: List[str]


@dataclass(frozen=True)
class SceneRecognition:
    address: int
    struct_offset: int
    scene_offset: int
    evidence: List[str]


@dataclass(frozen=True)
class SliceInput:
    arch: str
    path: Path
