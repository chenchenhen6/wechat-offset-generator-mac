#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
import venv
from pathlib import Path

from wechat_offset_generator.app import (
    copy_app,
    locate_framework,
    read_wmpf_version_from_app,
    thin_framework,
    validate_app,
)

DEFAULT_APP = Path("/Applications/WeChat.app")
BOOTSTRAP_ENV = "WECHAT_OFFSET_GENERATOR_BOOTSTRAPPED"


def ensure_capstone(no_install: bool, work_dir: Path) -> None:
    try:
        import capstone  # noqa: F401
        return
    except ImportError:
        if no_install:
            raise SystemExit("缺少 capstone；请安装后重试，或去掉 --no-install 允许自动安装")
        if os.environ.get(BOOTSTRAP_ENV) == "1":
            raise SystemExit("capstone 自动安装后仍不可用")
    venv_dir = work_dir / ".venv"
    python = venv_dir / "bin" / "python"
    if not python.exists():
        venv.EnvBuilder(with_pip=True).create(str(venv_dir))
    subprocess.run([str(python), "-m", "pip", "install", "capstone"], check=True)
    env = os.environ.copy()
    env[BOOTSTRAP_ENV] = "1"
    os.execve(str(python), [str(python), str(Path(__file__).resolve())] + sys.argv[1:], env)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="静态生成微信 WMPF First JSON 偏移（默认复制 /Applications/WeChat.app 后分析副本）")
    parser.add_argument("--app", type=Path, default=DEFAULT_APP, help="微信 .app 路径，默认 /Applications/WeChat.app")
    parser.add_argument("--work-dir", type=Path, default=Path.cwd(), help="副本、切片和报告工作目录")
    parser.add_argument("--output-dir", type=Path, default=None, help="addresses.<WMPF>.json 输出目录，默认 work-dir")
    parser.add_argument("--keep-copy", action="store_true", help="保留复制出的 .app 副本")
    parser.add_argument("--no-install", action="store_true", help="缺少 capstone 时不要创建 .venv 或安装")
    parser.add_argument("--verbose", action="store_true", help="输出详细步骤")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    work_dir = args.work_dir.resolve()
    output_dir = (args.output_dir or work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    ensure_capstone(args.no_install, work_dir)
    from wechat_offset_generator.generator import build_config, write_config, write_report

    validate_app(args.app)
    version = read_wmpf_version_from_app(args.app)
    copy_path = work_dir / f"WeChat-WMPF-{version}-analysis.app"
    if args.verbose:
        print(f"copy: {args.app} -> {copy_path}")
    copied = copy_app(args.app, copy_path)
    framework = locate_framework(copied)
    slices = {}
    for cli_arch, config_arch in (("arm64", "arm64"), ("x86_64", "x64")):
        out = work_dir / f"{framework.name}.{cli_arch}"
        if args.verbose:
            print(f"thin: {cli_arch} -> {out}")
        thin_framework(framework, cli_arch, out)
        slices[config_arch] = out
    if args.verbose:
        print("analyze slices")
    config, report = build_config(version, slices)
    report_path = write_report(report, work_dir, version)
    config_path = write_config(config, output_dir)
    if args.verbose:
        print(f"report: {report_path}")
        print(f"config: {config_path}")
        if any("ResourceCachePolicyHookOffset" not in v for v in config["Arch"].values()):
            print("warning: ResourceCachePolicyHookOffset omitted: no high-confidence evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
