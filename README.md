# WeChat / First 偏移地址 JSON 生成器

这个文件夹可以拷贝到另一台 macOS 电脑上，用来静态生成 Spade-sec/First 使用的 `addresses.<WMPF版本>.json`。

## 目录内容

- `generate_wechat_offsets.py`：入口脚本。
- `wechat_offset_generator/`：Mach-O 解析、反汇编和偏移识别逻辑。
- `requirements.txt`：依赖说明，主要是 `capstone`。
- `addresses.25071.example.json`：当前机器上微信 4.1.11 / WMPF 25071 的示例输出。
- `analysis-report.25071.example.json`：示例分析报告。

## 最简单用法

把整个 `wechat-offset-generator-mac` 文件夹复制到目标 Mac，例如放到桌面，然后执行：

```bash
cd ~/Desktop/wechat-offset-generator-mac
python3 generate_wechat_offsets.py --verbose
```

成功后会在当前目录生成：

```text
addresses.<WMPF版本>.json
analysis-report.<WMPF版本>.json
```

例如 WMPF 版本是 `25071` 时，会生成：

```text
addresses.25071.json
analysis-report.25071.json
```

## 指定微信路径或输出目录

默认分析 `/Applications/WeChat.app`。如果微信不在默认位置，可以指定：

```bash
python3 generate_wechat_offsets.py --app /path/to/WeChat.app --verbose
```

指定工作目录和输出目录：

```bash
python3 generate_wechat_offsets.py \
  --app /Applications/WeChat.app \
  --work-dir ./work \
  --output-dir ./out \
  --verbose
```

## 它会不会逆向/调试原始微信？

不会。脚本只做静态分析：

1. 读取微信 bundle 版本信息；
2. 用 `ditto` 把微信复制到工作目录；
3. 在副本里定位 `WeChatAppEx Framework.framework`；
4. 用 `lipo -thin` 切出 arm64 和 x86_64；
5. 静态扫描字符串引用、函数入口、调用链和字段访问模式；
6. 写出 First 需要的 JSON。

不会启动微信、不会注入 Frida、不会调试 `/Applications/WeChat.app`，也不会修改原始微信。

## 是不是随便放在一台 Mac 都能用？

基本可以，但目标 Mac 需要满足这些条件：

1. macOS 上有 Python 3：

   ```bash
   python3 --version
   ```

2. 目标 Mac 上已安装微信，并且能访问微信 app bundle，默认路径是：

   ```text
   /Applications/WeChat.app
   ```

3. 系统有 `ditto` 和 `lipo`。它们通常随 macOS / Xcode Command Line Tools 提供：

   ```bash
   which ditto
   which lipo
   ```

4. Python 能安装或已经安装 `capstone`：
   - 默认情况下，脚本发现缺少 `capstone` 会在当前工作目录创建 `.venv`，执行 `pip install capstone`，然后自动重启。
   - 如果目标 Mac 没网络，可以提前安装：

     ```bash
     python3 -m pip install capstone
     ```

   - 如果不允许自动安装，运行时加：

     ```bash
     python3 generate_wechat_offsets.py --no-install --verbose
     ```

5. 当前目录需要可写，因为脚本会写副本、切片、报告和 JSON。

## 版本号说明

输出文件名取的是嵌套 `WeChatAppEx.app` 的 WMPF 版本，不是微信主程序 build。

例如：

- 微信主版本：`4.1.11`
- WMPF bundle version：`4.25071`
- 输出文件：`addresses.25071.json`

## 可选字段说明

`ResourceCachePolicyHookOffset` 是可选字段。脚本只有在找到高置信完整证据链时才会写入；否则会省略并继续生成 JSON，避免错误 Hook。

核心字段失败时不会生成 JSON：

- `LoadStartHookOffset`
- `LoadStartHookOffset2`
- `StructOffset`
- `SceneOffset`
- `CDPFilterHookOffset`

## 当前示例输出

本文件夹里的 `addresses.25071.example.json` 是当前这台机器上生成的微信 4.1.11 / WMPF 25071 示例，可对照 First 的 `frida/config/mac/addresses.25071.json` 使用。
