#!/usr/bin/env python3
"""Generate a reviewed-pattern mac/arm64 config in first_ex, never directly in First."""
import argparse
import hashlib
import json
import plistlib
import re
import subprocess
import tempfile
from pathlib import Path

from first_files import choose_cdp_policy, install_transaction, json_bytes, runtime_validated, sha256, validate_config
from mac_scanner import find_xrefs_multi, is_add_imm, scan_image

ROOT = Path(__file__).resolve().parent


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as fp:
        for block in iter(lambda: fp.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read_version(app):
    with open(Path(app) / 'Contents/MacOS/WeChatAppEx.app/Contents/Info.plist', 'rb') as fp:
        raw = str(plistlib.load(fp)['CFBundleVersion'])
    match = re.fullmatch(r'7\.(\d+)', raw)
    if not match:
        raise ValueError(f'不支持的 WMPF 版本格式: {raw}')
    return int(match[1])


def framework_path(app):
    folder = Path(app) / 'Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework'
    for p in (folder / 'WeChatAppEx Framework', folder / 'Versions/Current/WeChatAppEx Framework', folder / 'Versions/C/WeChatAppEx Framework'):
        if p.is_file():
            return p
    raise ValueError(f'未找到 WeChatAppEx Framework: {folder}')


def verified_profile(root, version, binary_hash, hook):
    name = f'addresses.{version}.json'
    config_path = Path(root) / 'config/mac' / name
    meta_path = Path(root) / 'validation/mac' / name
    if not config_path.exists() or not meta_path.exists():
        return None
    config = config_path.read_bytes()
    meta = json.loads(meta_path.read_text(encoding='utf-8'))
    if meta.get('binary_sha256') != binary_hash or not runtime_validated(root, 'mac', name, hook, config):
        return None
    return validate_config(config, name, 'mac')['Arch'].get('arm64')


def generate(binary, version, root=ROOT, cdp_policy=None, cdp_filter_offset=None):
    hook = (Path(root) / 'hook.js').read_bytes()
    binary_hash = file_digest(binary)
    fields, evidence = scan_image(binary)
    profile = verified_profile(root, version, binary_hash, hook)
    fields['CDPFilterHookOffset'], policy_source = choose_cdp_policy(profile, cdp_policy, cdp_filter_offset)
    value = {'Version': version, 'Arch': {'arm64': fields}}
    data = json_bytes(value)
    name = f'addresses.{version}.json'
    validate_config(data, name, 'mac')
    verified = bool(profile == fields and runtime_validated(root, 'mac', name, hook, data))
    previous = {}
    if verified:
        previous = json.loads((Path(root) / 'validation/mac' / name).read_text(encoding='utf-8'))
        if 'limitations' in previous:
            previous['runtime_limitations'] = previous.pop('limitations')
    metadata = {**previous, 'Version': version, 'platform': 'mac', 'architecture': 'arm64',
                'binary_sha256': binary_hash, 'hook_sha256': sha256(hook), 'config_sha256': sha256(data),
                'runtime_verified': verified, 'cdp_policy_source': policy_source,
                'verification': 'previous exact binary/config/hook validation' if verified else 'pending runtime CDP validation'}
    evidence.update(metadata)
    return value, evidence, metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wechat-app', type=Path, default=Path('/Applications/WeChat.app'))
    parser.add_argument('--binary', type=Path, help='指定 Framework 或 arm64 slice；默认检测已安装微信')
    parser.add_argument('--version', type=int, help='离线分析时显式指定配置版本号')
    parser.add_argument('--cdp-policy', choices=['native'], help='未知版本调试时显式选择原生 CDP（待验证）')
    parser.add_argument('--cdp-filter-offset', help='人工确认的 CDP 过滤钩子地址，不能指向共享 JSON 解析函数')
    parser.add_argument('--write', action='store_true', help='保存到 first_ex/config/mac，不安装到 App')
    args = parser.parse_args(argv)
    try:
        version = args.version if args.version is not None else read_version(args.wechat_app)
        if version <= 0:
            raise ValueError('版本必须是正整数')
        binary = args.binary or framework_path(args.wechat_app)
        with tempfile.TemporaryDirectory(prefix='first_ex_arm64_') as td:
            with binary.open('rb') as fp:
                magic = fp.read(4)
            if magic == b'\xcf\xfa\xed\xfe':
                thin = binary
            else:
                thin = Path(td) / 'arm64'
                subprocess.run(['lipo', '-thin', 'arm64', str(binary), '-output', str(thin)], check=True, capture_output=True, text=True)
            value, evidence, metadata = generate(thin, version, cdp_policy=args.cdp_policy, cdp_filter_offset=args.cdp_filter_offset)
        print(json.dumps(value, ensure_ascii=False, indent=4))
        print('定位证据:', json.dumps(evidence, ensure_ascii=False))
        print('运行验证:', '已匹配同一二进制/脚本/配置的历史验证' if metadata['runtime_verified'] else '未验证；需实际打开小程序并验证 CDP')
        if args.write:
            name = f'addresses.{version}.json'
            backup = install_transaction(ROOT, {'config/mac/' + name: json_bytes(value),
                                                'evidence/mac/' + name: json_bytes(evidence),
                                                'validation/mac/' + name: json_bytes(metadata)}, ROOT / 'backups/generated')
            print(f'已保存: {ROOT / "config/mac" / name}；备份: {backup or "内容一致，无需替换"}')
        else:
            print('干跑完成；--write 保存到本项目。使用 install_first.py 安装。')
        return 0
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f'停止生成: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
