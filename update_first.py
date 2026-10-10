#!/usr/bin/env python3
"""macOS workflow: generate local JSON, then preview/apply it with local hook.js."""
import argparse
from pathlib import Path

import gen_wmpf_config
import install_first


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wechat-app', type=Path, default=Path('/Applications/WeChat.app'))
    parser.add_argument('--app', type=Path, default=Path('/Applications/First.app'))
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--version', type=int)
    parser.add_argument('--cdp-policy', choices=['native'])
    parser.add_argument('--cdp-filter-offset')
    parser.add_argument('--allow-unverified', action='store_true')
    parser.add_argument('--apply', action='store_true', help='安装到 First；默认生成本地文件后仅预览安装')
    args = parser.parse_args(argv)
    generation = ['--write', '--wechat-app', str(args.wechat_app)]
    for flag, value in (('--binary', args.binary), ('--version', args.version), ('--cdp-policy', args.cdp_policy), ('--cdp-filter-offset', args.cdp_filter_offset)):
        if value is not None:
            generation += [flag, str(value)]
    code = gen_wmpf_config.main(generation)
    if code:
        return code
    version = args.version if args.version is not None else gen_wmpf_config.read_version(args.wechat_app)
    installation = ['--platform', 'mac', '--app', str(args.app), '--version', str(version)]
    if args.allow_unverified:
        installation.append('--allow-unverified')
    if args.apply:
        installation.append('--apply')
    return install_first.main(installation)


if __name__ == '__main__':
    raise SystemExit(main())
