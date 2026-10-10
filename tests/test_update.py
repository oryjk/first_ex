import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class UpdatePipelineTests(unittest.TestCase):
    def test_generation_failure_does_not_install_hook(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); app = root / 'First.app'
            frida = app / 'Contents/Resources/frida'; frida.mkdir(parents=True)
            hook = frida / 'hook.js'; hook.write_text('keep-me')
            script = Path(__file__).resolve().parents[1] / 'update_first.py'
            result = subprocess.run([sys.executable, str(script), '--wechat-app', str(root / 'missing'), '--app', str(app), '--apply'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('停止生成', result.stdout)
            self.assertEqual(hook.read_text(), 'keep-me')


if __name__ == '__main__':
    unittest.main()
