import json
import os
import tempfile
from pathlib import Path
from typing import Dict, Tuple

from .macho import MachOImage
from .recognizers import (
    RecognitionError,
    recognize_cdp_filter,
    recognize_load_start,
    recognize_resource_cache_policy,
    recognize_scene_hook,
)


def hex_addr(value: int) -> str:
    return f"0x{value:X}"


def analyze_slice(path: Path) -> Tuple[dict, dict]:
    image = MachOImage.from_path(path)
    load = recognize_load_start(image)
    scene = recognize_scene_hook(image)
    cdp = recognize_cdp_filter(image)
    cache = recognize_resource_cache_policy(image)
    config = {
        "LoadStartHookOffset": hex_addr(load.address),
        "LoadStartHookOffset2": hex_addr(scene.address),
        "StructOffset": scene.struct_offset,
        "SceneOffset": scene.scene_offset,
        "CDPFilterHookOffset": hex_addr(cdp.address),
    }
    if cache is not None:
        config["ResourceCachePolicyHookOffset"] = hex_addr(cache.address)
    report = {
        "path": str(path),
        "arch": image.arch,
        "load_start": load.__dict__,
        "scene_hook": scene.__dict__,
        "cdp_filter": cdp.__dict__,
        "resource_cache_policy": cache.__dict__ if cache else {"omitted": True, "reason": "no high-confidence evidence"},
    }
    return config, report


def build_config(version: int, slices: Dict[str, Path]) -> Tuple[dict, dict]:
    config = {"Version": version, "Arch": {}}
    report = {"version": version, "architectures": {}}
    for arch, path in slices.items():
        arch_config, arch_report = analyze_slice(Path(path))
        config["Arch"][arch] = arch_config
        report["architectures"][arch] = arch_report
    return config, report


def write_config(config: dict, output_dir: Path) -> Path:
    return _atomic_json(config, Path(output_dir) / f"addresses.{config['Version']}.json")


def write_report(report: dict, work_dir: Path, version: int) -> Path:
    return _atomic_json(report, Path(work_dir) / f"analysis-report.{version}.json")


def _atomic_json(payload: dict, final_path: Path) -> Path:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=final_path.name + ".", suffix=".tmp", dir=str(final_path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.write("\n")
        json.loads(tmp.read_text(encoding="utf-8"))
        os.replace(str(tmp), str(final_path))
    finally:
        if tmp.exists():
            tmp.unlink()
    return final_path
