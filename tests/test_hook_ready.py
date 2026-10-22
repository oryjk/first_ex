"""Exercise the real hook's initialization protocol with a native API boundary fake."""
import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const events = [];
const module = {base: {add: offset => Number(offset)}};
const context = {
  Process: {platform: input.platform, arch: input.arch,
    findModuleByName: name => {events.push({module: name}); return input.missing ? null : module;}},
  Interceptor: {attach: address => {
    if (input.failAttach) throw new Error('native attach failed');
    events.push({attach: address});
  }},
  console: {log() {}, error() {}},
  send: payload => events.push({send: payload})
};
let error = null;
try {vm.runInNewContext(input.source.replace('@@CONFIG@@', JSON.stringify(input.config)), context);}
catch (e) {error = e.message;}
process.stdout.write(JSON.stringify({events, error}));
'''


class HookReadyTests(unittest.TestCase):
    def run_hook(self, config, platform='darwin', arch='arm64', **options):
        payload = dict(source=(ROOT / 'hook.js').read_text(), config=config,
                       platform=platform, arch=arch, **options)
        run = subprocess.run(['node', '-e', HARNESS], input=json.dumps(payload),
                             capture_output=True, text=True, check=True)
        return json.loads(run.stdout)

    def assert_ready(self, result, version, platform, arch, addresses):
        self.assertIsNone(result['error'])
        self.assertEqual([event['attach'] for event in result['events'] if 'attach' in event], addresses)
        self.assertEqual([event['send'] for event in result['events'] if 'send' in event],
                         [{'type': 'first-hook-ready', 'version': version, 'platform': platform, 'arch': arch}])
        self.assertIn('send', result['events'][-1], 'readiness must follow every native hook registration')

    def test_mac_25755_and_25800_report_ready_after_all_hooks(self):
        for version, offset in [(25755, 0x5775170), (25800, 0x577760c)]:
            with self.subTest(version=version):
                config = json.loads((ROOT / f'config/mac/addresses.{version}.json').read_text())
                self.assert_ready(self.run_hook(config), version, 'darwin', 'arm64', [offset, offset])

    def test_legacy_mac_keeps_cdp_load_and_cache_hooks_before_ready(self):
        config = {'Version': 17078, 'Arch': {'arm64': {
            'LoadStartHookOffset': '0x4F0620C', 'LoadStartHookOffset2': '0x81CEC08',
            'CDPFilterHookOffset': '0x81BFC04', 'ResourceCachePolicyHookOffset': '0x4F699E8',
            'StructOffset': 1376, 'SceneOffset': 488}}}
        self.assert_ready(self.run_hook(config), 17078, 'darwin', 'arm64',
                          [0x81BFC04, 0x4F0620C, 0x81CEC08, 0x4F699E8])

    def test_windows_flat_and_arch_configs_keep_module_selection_and_hooks(self):
        for version, module in [(11581, 'WeChatAppEx.exe'), (18955, 'flue.dll')]:
            for nested in [False, True]:
                with self.subTest(version=version, nested=nested):
                    fields = {'LoadStartHookOffset': '0x100', 'CDPFilterHookOffset': '0x200',
                              'SceneOffsets': [56, 1408, 8, 1344, 16, 488]}
                    config = {'Version': version, 'Arch': {'x64': fields}} if nested else dict(Version=version, **fields)
                    result = self.run_hook(config, platform='windows', arch='x64')
                    self.assertEqual(result['events'][0], {'module': module})
                    self.assert_ready(result, version, 'windows', 'x64', [0x200, 0x100])

    def test_missing_module_or_arch_never_reports_ready(self):
        config = json.loads((ROOT / 'config/mac/addresses.25800.json').read_text())
        for options in [{'missing': True}, {'arch': 'x64'}]:
            with self.subTest(options=options):
                result = self.run_hook(config, **options)
                self.assertFalse(any('send' in event for event in result['events']))

    def test_native_registration_failure_never_reports_ready(self):
        config = json.loads((ROOT / 'config/mac/addresses.25800.json').read_text())
        result = self.run_hook(config, failAttach=True)
        self.assertEqual(result['error'], 'native attach failed')
        self.assertFalse(any('send' in event for event in result['events']))
