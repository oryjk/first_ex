#!/usr/bin/env python3
"""Install first_ex/hook.js and selected JSONs; preview by default, --apply to replace."""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from first_files import install_transaction, rollback_transaction, runtime_validated, validate_config

ROOT = Path(__file__).resolve().parent


def check_hook(hook, node):
    executable = shutil.which(node)
    if not executable:
        raise ValueError('需要 Node.js 做 hook.js 语法检查；可用 --node 指定 node 路径')
    with tempfile.TemporaryDirectory(prefix='first_ex_jscheck_') as td:
        p = Path(td) / 'hook.js'; p.write_bytes(hook)
        result = subprocess.run([executable, '--check', str(p)], capture_output=True, text=True)
        if result.returncode:
            raise ValueError('hook.js 语法检查失败: ' + result.stderr[:2000])


def collect_payloads(source, platform, versions, allow_unverified, node):
    source = Path(source).resolve()
    hook = (source / 'hook.js').read_bytes()
    check_hook(hook, node)
    folder = source / 'config' / platform
    selected = [folder / f'addresses.{v}.json' for v in sorted(set(versions))] if versions else sorted(folder.glob('addresses.*.json'))
    if not selected:
        raise ValueError(f'没有待安装的 {platform} 配置: {folder}')
    payloads, status = {'hook.js': hook}, []
    for path in selected:
        data = path.read_bytes()
        validate_config(data, path.name, platform)
        validated = runtime_validated(source, platform, path.name, hook, data)
        if not validated and not allow_unverified:
            raise ValueError(f'{path.name} 未运行验证，或 hook/JSON 已变化；调试安装请显式使用 --allow-unverified')
        payloads[f'config/{platform}/{path.name}'] = data
        status.append((path.name, validated))
    return payloads, status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT, help='适配源目录；默认脚本所在目录')
    parser.add_argument('--app', type=Path, default=Path('/Applications/First.app'), help='macOS First.app 路径')
    parser.add_argument('--resources', type=Path, help='含 frida 子目录的目录；Windows 必须显式指定')
    parser.add_argument('--platform', choices=['mac', 'win'], default='win' if sys.platform == 'win32' else 'mac')
    parser.add_argument('--version', type=int, action='append', help='只安装指定版本；可重复，默认当前平台所有本地 JSON')
    parser.add_argument('--node', default='node', help='Node.js 可执行文件名或路径')
    parser.add_argument('--allow-unverified', action='store_true', help='允许调试安装候选配置；不代表已打通')
    parser.add_argument('--apply', action='store_true', help='执行替换或回滚；默认仅预览')
    parser.add_argument('--rollback', type=Path, help='恢复指定备份目录，与 --apply 配合执行')
    args = parser.parse_args(argv)
    try:
        if args.platform == 'win' and args.resources is None:
            raise ValueError('Windows 请用 --resources 指定实际含 frida 子目录的目录')
        resources = args.resources or args.app / 'Contents/Resources'
        destination = (resources / 'frida').resolve()
        if not destination.is_dir():
            raise ValueError(f'目标 frida 目录不存在: {destination}')
        if args.rollback:
            manifest = json.loads((args.rollback / 'manifest.json').read_text(encoding='utf-8'))
            if manifest.get('destination') != str(destination):
                raise ValueError('备份属于其他目标目录，拒绝回滚')
            print(f'回滚预览: {args.rollback} -> {destination}')
            if args.apply:
                rollback_transaction(args.rollback, destination)
                print('回滚完成；重启 First 后生效')
            else:
                print('未修改文件；--apply 执行回滚')
            return 0
        payloads, statuses = collect_payloads(args.source, args.platform, args.version, args.allow_unverified, args.node)
        print(f'来源: {args.source.resolve()}\n目标: {destination}')
        for name, verified in statuses:
            print(f'{name}: ' + ('有匹配此 hook/JSON 的运行验证记录' if verified else '候选配置，尚未运行验证'))
        for rel, data in payloads.items():
            target = destination / rel
            same = target.exists() and target.read_bytes() == data
            print(('一致' if same else '替换') + ': ' + str(target))
        if args.apply:
            backup = install_transaction(destination, payloads, args.source / 'backups/installed')
            print('文件完全一致，无需替换' if backup is None else f'安装完成；备份: {backup}')
            print('如文件有变化，请退出并重新启动 First；本脚本不会注入、重签名或改动网络')
        else:
            print('预览完成，未修改文件；--apply 执行安装')
        return 0
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f'停止安装: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
