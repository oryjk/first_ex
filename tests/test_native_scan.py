import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from mac_scanner import scan_image
from gen_wmpf_config import generate
from first_files import json_bytes, sha256
from test_safety import guard_words


def macho_fixture(path, bodies):
    blob = bytearray(0x700)
    struct.pack_into('<8I', blob, 0, 0xFEEDFACF, 0x100000C, 0, 1, 1, 232, 0, 0)
    struct.pack_into('<II16sQQQQIIII', blob, 32, 0x19, 232, b'__TEXT', 0, len(blob), 0, len(blob), 7, 5, 2, 0)
    struct.pack_into('<16s16sQQIIIIIIII', blob, 104, b'__text', b'__TEXT', 0x200, 0x200, 0x200, 2, 0, 0, 0x80000400, 0, 0, 0)
    string = b'void applet::AppletIndexContainer::OnLoadStart(bool)\0'
    struct.pack_into('<16s16sQQIIIIIIII', blob, 184, b'__cstring', b'__TEXT', 0x600, len(string), 0x600, 0, 0, 0, 0, 0, 0, 0)
    blob[0x600:0x600 + len(string)] = string
    for i, words in enumerate(bodies):
        struct.pack_into('<' + 'I' * len(words), blob, 0x200 + i * 0x100, *words)
    path.write_bytes(blob)


def body(with_xref=True, with_guard=True, root=19):
    words = [0xD10103FF, 0xA9037BFD, 0x9100C3FD, 0xAA0003F3, 0xAA0103F4,
             0x90000000, 0x91180000]
    if not with_xref:
        words[5:7] = [0xD503201F, 0xD503201F]
    if with_guard:
        words += guard_words(root=root) + [0xD503201F] * 4 + [0xD65F03C0]
    else:
        words += [0xD65F03C0]
    return words


@unittest.skipUnless(shutil.which('xcrun'), 'LLVM fixture integration requires Xcode command line tools')
class NativeCandidateTests(unittest.TestCase):
    def test_complete_binary_scan_derives_literal_expected_config(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'test'; macho_fixture(p, [body()])
            fields, evidence = scan_image(p)
            self.assertEqual(fields['LoadStartHookOffset'], '0x200')
            self.assertEqual(fields['FirstHopOffset'], 56)
            self.assertEqual(fields['StructOffset'], 1520)
            self.assertEqual(fields['SceneOffset'], 456)
            self.assertEqual(fields['RemoteDebugModeOffset'], 724)
            self.assertEqual(fields['WebSocketURLStringOffset'], 416)

    def test_two_valid_candidates_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'test'; macho_fixture(p, [body(), body()])
            with self.assertRaisesRegex(ValueError, '实际 2 个'):
                scan_image(p)

    def test_guard_in_neighbor_function_is_not_selected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'test'; macho_fixture(p, [body(with_guard=False), body(with_xref=False)])
            with self.assertRaisesRegex(ValueError, '实际 0 个'):
                scan_image(p)

    def test_object_chain_from_other_parameter_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'test'; macho_fixture(p, [body(root=20)])
            with self.assertRaisesRegex(ValueError, '实际 0 个'):
                scan_image(p)

    def test_runtime_profile_does_not_hide_static_analysis_limits(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); p = root / 'binary'; macho_fixture(p, [body()])
            hook = b'const ready = true;\n'; (root / 'hook.js').write_bytes(hook)
            fields = {'LoadStartHookOffset': '0x200', 'LoadStartHookOffset2': '0x200', 'StructOffset': 1520, 'FirstHopOffset': 56, 'SceneOffset': 456, 'WebSocketURLStringOffset': 416, 'RemoteDebugModeOffset': 724, 'CDPFilterHookOffset': None}
            data = json_bytes({'Version': 100, 'Arch': {'arm64': fields}})
            (root / 'config/mac').mkdir(parents=True); (root / 'validation/mac').mkdir(parents=True)
            (root / 'config/mac/addresses.100.json').write_bytes(data)
            meta = {'runtime_verified': True, 'binary_sha256': sha256(p.read_bytes()), 'hook_sha256': sha256(hook), 'config_sha256': sha256(data), 'limitations': ['historical runtime scope']}
            (root / 'validation/mac/addresses.100.json').write_bytes(json_bytes(meta))
            _, evidence, metadata = generate(p, 100, root=root)
            self.assertTrue(metadata['runtime_verified'])
            self.assertIn('adjacent ADRP+ADD only', evidence['limitations'])


if __name__ == '__main__':
    unittest.main()
