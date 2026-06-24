import hashlib
import plistlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Iterable, Optional


def read_bundle_version(info_plist: Path) -> str:
    with Path(info_plist).open("rb") as f:
        data = plistlib.load(f)
    value = data.get("CFBundleVersion") or data.get("CFBundleShortVersionString")
    if not isinstance(value, str):
        raise ValueError(f"缺少版本字段: {info_plist}")
    return value


def parse_wmpf_version(value: str) -> int:
    match = re.search(r"(?:^|\.)(\d{4,})$", value)
    if not match:
        raise ValueError(f"无法解析 WMPF 版本: {value}")
    return int(match.group(1))


def validate_app(path: Path) -> None:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_dir() or path.suffix != ".app":
        raise ValueError(f"不是 .app bundle: {path}")
    info = path / "Contents" / "Info.plist"
    if not info.exists():
        raise FileNotFoundError(info)


def copy_app(source: Path, destination: Path, runner=subprocess.run) -> Path:
    source = Path(source)
    destination = Path(destination)
    validate_app(source)
    if destination.exists():
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    runner(["ditto", str(source), str(destination)], check=True)
    return destination


def locate_wmpf_app(app: Path) -> Path:
    app = Path(app)
    candidates = [app / "Contents" / "Frameworks" / "WeChatAppEx.app"]
    candidates.extend((app / "Contents").glob("**/WeChatAppEx*.app"))
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return app


def read_wmpf_version_from_app(app: Path) -> int:
    validate_app(app)
    wmpf_app = locate_wmpf_app(app)
    return parse_wmpf_version(read_bundle_version(wmpf_app / "Contents" / "Info.plist"))


def locate_framework(app: Path) -> Path:
    app = Path(app)
    roots = [app]
    nested = locate_wmpf_app(app)
    if nested != app:
        roots.insert(0, nested)

    # Prefer the actual framework dylib.  The nested WMPF app also contains a
    # `Contents/MacOS/WeChatAppEx` executable, but the offsets used by First
    # live in `WeChatAppEx Framework.framework/...`.
    for root in roots:
        framework_hits = [
            p
            for p in root.glob("**/*.framework/*")
            if p.is_file() and ("WeChatAppEx" in p.name and "Framework" in p.name)
        ]
        if framework_hits:
            return sorted(framework_hits, key=lambda p: (len(p.parts), len(str(p))))[0]

    for root in roots:
        hits = [
            p
            for p in root.glob("**/*")
            if p.is_file() and p.name.startswith("WeChatAppEx") and "Framework" in p.name
        ]
        if hits:
            return sorted(hits, key=lambda p: len(str(p)))[0]
    raise FileNotFoundError(f"未找到 WeChatAppExFramework: {app}")


def thin_framework(binary: Path, arch: str, output: Path, runner=subprocess.run) -> Path:
    if arch not in ("arm64", "x86_64", "x64"):
        raise ValueError(f"unsupported arch: {arch}")
    lipo_arch = "x86_64" if arch == "x64" else arch
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    runner(["lipo", str(binary), "-thin", lipo_arch, "-output", str(output)], check=True)
    return output


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
