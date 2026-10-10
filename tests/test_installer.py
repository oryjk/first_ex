import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from first_files import json_bytes, sha256

SCRIPT = Path(__file__).resolve().parents[1] / 'install_first.py'
CONFIG = {'Version': 100, 'Arch': {'arm64': {'LoadStartHookOffset': '0x100', 'LoadStartHookOffset2': '0x100', 'StructOffset': 24, 'CDPFilterHookOffset': None}}}


class InstallerCLITests(unittest.TestCase):
    def run_install(self, root, *args):
        return subprocess.run([sys.executable, str(SCRIPT), '--source', str(root / 'src'), '--resources', str(root / 'resources'), '--platform', 'mac', *args], capture_output=True, text=True)

    def fixture(self, root, verified=True):
        source = root / 'src'; configs = source / 'config/mac'; configs.mkdir(parents=True)
        hook = b'const ready = true;\n'; data = json_bytes(CONFIG)
        (source / 'hook.js').write_bytes(hook)
        (configs / 'addresses.100.json').write_bytes(data)
        meta = source / 'validation/mac'; meta.mkdir(parents=True)
        (meta / 'addresses.100.json').write_text(json.dumps({'runtime_verified': verified, 'config_sha256': sha256(data), 'hook_sha256': sha256(hook)}))
        destination = root / 'resources/frida'; destination.mkdir(parents=True)
        (destination / 'hook.js').write_bytes(b'old-hook')
        return destination

    def test_preview_does_not_replace_anything(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); dest = self.fixture(root)
            result = self.run_install(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((dest / 'hook.js').read_bytes(), b'old-hook')
            self.assertFalse((dest / 'config/mac/addresses.100.json').exists())

    def test_unverified_config_blocks_before_any_file_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); dest = self.fixture(root, False)
            result = self.run_install(root, '--apply')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('未运行验证', result.stdout)
            self.assertEqual((dest / 'hook.js').read_bytes(), b'old-hook')
            self.assertFalse((dest / 'config/mac/addresses.100.json').exists())

    def test_invalid_json_is_not_bypassed_by_allow_unverified(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); dest = self.fixture(root)
            (root / 'src/config/mac/addresses.100.json').write_text('{}')
            result = self.run_install(root, '--apply', '--allow-unverified')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('配置版本', result.stdout)
            self.assertEqual((dest / 'hook.js').read_bytes(), b'old-hook')

    def test_apply_and_cli_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); dest = self.fixture(root)
            result = self.run_install(root, '--apply')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((dest / 'hook.js').read_bytes(), b'const ready = true;\n')
            self.assertEqual(json.loads((dest / 'config/mac/addresses.100.json').read_text()), CONFIG)
            backup = next((root / 'src/backups/installed').iterdir())
            result = self.run_install(root, '--rollback', str(backup), '--apply')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((dest / 'hook.js').read_bytes(), b'old-hook')
            self.assertFalse((dest / 'config/mac/addresses.100.json').exists())

    def test_broken_hook_syntax_blocks_before_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); dest = self.fixture(root)
            (root / 'src/hook.js').write_text('const = ;')
            result = self.run_install(root, '--apply', '--allow-unverified')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('hook.js 语法', result.stdout)
            self.assertEqual((dest / 'hook.js').read_bytes(), b'old-hook')

    def test_native_windows_flat_json_can_be_installed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); dest = self.fixture(root)
            folder = root / 'src/config/win'; folder.mkdir()
            value = {'Version': 101, 'LoadStartHookOffset': '0x100', 'CDPFilterHookOffset': '0x200', 'SceneOffsets': [56, 1408, 8, 1344, 16, 488]}
            (folder / 'addresses.101.json').write_bytes(json_bytes(value))
            result = self.run_install(root, '--platform', 'win', '--allow-unverified', '--apply')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads((dest / 'config/win/addresses.101.json').read_text()), value)


if __name__ == '__main__':
    unittest.main()
