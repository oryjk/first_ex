"""Configuration validation and recoverable file replacement; Python stdlib only."""
import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data):
    """Keep the existing file until a complete, flushed replacement is ready."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f'拒绝替换符号链接: {path}')
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as fp:
            fp.write(data)
            fp.flush()
            if hasattr(os, 'fchmod'):
                os.fchmod(fp.fileno(), mode)
            os.fsync(fp.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=4) + '\n').encode('utf-8')


def safe_target(root, relative):
    rel = PurePosixPath(relative)
    if rel.is_absolute() or not rel.parts or any(p in ('..', '.', '') for p in rel.parts) or '\\' in relative or ':' in relative:
        raise ValueError(f'非法相对路径: {relative}')
    root = Path(root).resolve()
    target = root.joinpath(*rel.parts)
    for path in (target, *target.parents):
        if path == root:
            break
        if path.is_symlink():
            raise ValueError(f'拒绝通过符号链接替换: {path}')
    return target


def install_transaction(destination, payloads, backup_root):
    destination = Path(destination).resolve()
    if not destination.is_dir():
        raise ValueError(f'目标目录不存在: {destination}')
    snapshots = {}
    for rel, data in payloads.items():
        p = safe_target(destination, rel)
        old = p.read_bytes() if p.exists() else None
        if old != data:
            snapshots[rel] = old
    if not snapshots:
        return None
    backup = Path(backup_root).resolve() / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:12])
    backup.mkdir(parents=True)
    entries = {}
    for rel, old in snapshots.items():
        target = safe_target(destination, rel)
        entries[rel] = {'existed': old is not None, 'old_sha256': sha256(old) if old is not None else None,
                        'new_sha256': sha256(payloads[rel]),
                        'old_mode': stat.S_IMODE(target.stat().st_mode) if old is not None else None}
        if old is not None:
            atomic_write(safe_target(backup / 'files', rel), old)
    manifest = {'destination': str(destination), 'status': 'prepared', 'entries': entries}
    atomic_write(backup / 'manifest.json', json_bytes(manifest))
    written = []
    try:
        for rel, old in snapshots.items():
            target = safe_target(destination, rel)
            # Reject an external edit between preflight and replacement.
            now = target.read_bytes() if target.exists() else None
            if now != old:
                raise ValueError(f'安装期间文件被修改: {target}')
            atomic_write(target, payloads[rel])
            written.append(rel)
        manifest['status'] = 'installed'
        atomic_write(backup / 'manifest.json', json_bytes(manifest))
    except BaseException:
        for rel in reversed(written):
            target = safe_target(destination, rel)
            if target.read_bytes() != payloads[rel]:
                raise RuntimeError(f'回滚时目标已被其他程序改动，请从 {backup} 手动恢复')
            if snapshots[rel] is None:
                target.unlink()
            else:
                atomic_write(target, snapshots[rel])
        manifest['status'] = 'failed-and-restored'
        atomic_write(backup / 'manifest.json', json_bytes(manifest))
        raise
    return backup


def rollback_transaction(backup, destination):
    backup, destination = Path(backup).resolve(), Path(destination).resolve()
    manifest = json.loads((backup / 'manifest.json').read_text(encoding='utf-8'))
    if manifest['destination'] != str(destination) or manifest['status'] not in ('installed', 'prepared'):
        raise ValueError('备份目标或状态不匹配，拒绝回滚')
    restorations = {}
    for rel, entry in manifest['entries'].items():
        target = safe_target(destination, rel)
        current = sha256(target.read_bytes()) if target.exists() else None
        if current == entry['old_sha256']:
            continue  # Recover an interrupted installation/rollback.
        if current != entry['new_sha256']:
            raise ValueError(f'目标后来被修改，拒绝覆盖: {target}')
        old = safe_target(backup / 'files', rel).read_bytes() if entry['existed'] else None
        if old is not None and sha256(old) != entry['old_sha256']:
            raise ValueError(f'备份校验失败: {rel}')
        restorations[rel] = old
    for rel, old in restorations.items():
        target = safe_target(destination, rel)
        if old is None:
            target.unlink()
        else:
            atomic_write(target, old)
            os.chmod(target, manifest['entries'][rel]['old_mode'])
    manifest['status'] = 'rolled-back'
    atomic_write(backup / 'manifest.json', json_bytes(manifest))


def choose_cdp_policy(verified_profile, policy, filter_offset):
    if policy and filter_offset:
        raise ValueError('--cdp-policy 与 --cdp-filter-offset 不能同时使用')
    if filter_offset:
        return offset_value(filter_offset), 'explicit-filter-candidate'
    if policy == 'native':
        return None, 'explicit-native-candidate'
    if verified_profile is not None:
        return verified_profile.get('CDPFilterHookOffset'), 'verified-profile'
    raise ValueError('未知二进制的 CDP 策略未验证；调试时显式指定 --cdp-policy native，或人工确认后的 --cdp-filter-offset 地址')


def offset_value(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f'非法钩子地址: {value!r}')
    try:
        n = int(value, 0) if isinstance(value, str) else value
    except ValueError:
        raise ValueError(f'非法钩子地址: {value!r}') from None
    if not 0 < n < (1 << 48):
        raise ValueError(f'钩子地址超出范围: {value!r}')
    return hex(n)


def validate_config(data, filename, platform):
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError('配置必须是 JSON 对象')
    match = re.fullmatch(r'addresses\.(\d+)\.json', filename)
    version = value.get('Version')
    if not match or isinstance(version, bool) or not isinstance(version, int) or version <= 0 or version != int(match[1]):
        raise ValueError(f'配置版本与文件名不符: {filename}')
    # Upstream Windows JSONs use top-level offsets; mac uses Arch.{arm64|x64}.
    arches = {'x64': value} if platform == 'win' and value.get('LoadStartHookOffset') is not None else value.get('Arch')
    if not isinstance(arches, dict) or not arches:
        raise ValueError('Arch 必须是非空对象')
    for arch, fields in arches.items():
        supported = ('arm64', 'x64', 'x86_64', 'amd64') if platform == 'mac' else ('x64', 'x86_64', 'amd64')
        if arch not in supported or not isinstance(fields, dict):
            raise ValueError(f'不支持的架构配置: {arch}')
        offset_value(fields.get('LoadStartHookOffset'))
        for key in ('LoadStartHookOffset2', 'CDPFilterHookOffset', 'ResourceCachePolicyHookOffset'):
            if fields.get(key) is not None:
                offset_value(fields[key])
        if platform == 'mac':
            offset_value(fields.get('LoadStartHookOffset2'))
            for key in ('StructOffset', 'FirstHopOffset', 'SceneOffset', 'WebSocketURLStringOffset', 'RemoteDebugModeOffset'):
                if key == 'StructOffset' or key in fields:
                    n = fields.get(key)
                    if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n < (1 << 24):
                        raise ValueError(f'非法结构偏移: {key}={n!r}')
            if 'ThirdHopOffset' in fields and fields['ThirdHopOffset'] != 16:
                raise ValueError('当前 hook.js 第三跳固定为 16，不能安装该配置')
        else:
            offsets = fields.get('SceneOffsets')
            if not isinstance(offsets, list) or len(offsets) != 6 or any(isinstance(n, bool) or not isinstance(n, int) or not 0 <= n < (1 << 24) for n in offsets):
                raise ValueError('Windows SceneOffsets 必须包含六个非负整数')
    return value


def runtime_validated(root, platform, filename, hook, config):
    path = Path(root) / 'validation' / platform / filename
    if not path.exists():
        return False
    meta = json.loads(path.read_text(encoding='utf-8'))
    return (meta.get('runtime_verified') is True and meta.get('hook_sha256') == sha256(hook)
            and meta.get('config_sha256') == sha256(config))
