import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import mac_scanner as scan
import first_files as files


def guard_words(third=16, root=19):
    # Independently assembled arm64 instructions, including the boolean guard.
    return [0x34000274, 0xF9400008 | (7 << 10) | (root << 5),
            0xF942F909, 0xF9400129 | ((third // 8) << 10), 0xB40001E9,
            0xB942D52A, 0x7100055F, 0x54000181, 0xB941C92A,
            0x7111355F, 0x54000121, 0x3986DD2A, 0xB6F8004A,
            0xF940D52A, 0xB40000AA]


class ScannerSafetyTests(unittest.TestCase):
    def test_three_hop_signature_decodes_expected_offsets(self):
        g = scan.parse_guard_block(guard_words(), 0x1000, 0x1024, 10)
        self.assertEqual((g['hops'], g['scene'], g['mode'], g['url']), ([56, 1520, 16], 456, 724, 416))

    def test_incompatible_third_hop_is_rejected(self):
        with self.assertRaises(ValueError):
            scan.parse_guard_block(guard_words(32), 0x1000, 0x1024, 10)

    def test_four_hops_cannot_be_silently_truncated(self):
        w = [0xF9402E68] + guard_words()
        w[1] = 0xF9400148  # replace boolean guard with a fourth dereference
        self.assertIsNone(scan.parse_guard_block(w, 0x1000, 0x1028, 10))

    def test_macho_vmaddr_is_not_a_file_offset(self):
        with tempfile.TemporaryDirectory() as td:
            blob = bytearray(0x104)
            struct.pack_into('<8I', blob, 0, 0xFEEDFACF, 0x100000C, 0, 6, 1, 152, 0, 0)
            struct.pack_into('<II16sQQQQIIII', blob, 32, 0x19, 152, b'__TEXT', 0x100000000, len(blob), 0, len(blob), 7, 5, 1, 0)
            struct.pack_into('<16s16sQQIIIIIIII', blob, 104, b'__text', b'__TEXT', 0x100000100, 4, 0x100, 2, 0, 0, 0, 0, 0, 0)
            struct.pack_into('<I', blob, 0x100, 0xD65F03C0)
            p = Path(td) / 'test'; p.write_bytes(blob)
            image = scan.MachOImage(p)
            self.assertEqual(tuple(image.text_words), (0xD65F03C0,))
            self.assertEqual(image.module_offset(0x100000100), 0x100)
            image.close()

    def test_abi_proof_rejects_this_overwritten_on_one_path(self):
        ins = {0x1000: ('mov', 'x19, x0'), 0x1004: ('mov', 'x20, x1'),
               0x1008: ('cbz', 'w2, 0x1014'), 0x100C: ('mov', 'x19, x3'),
               0x1010: ('b', '0x1014'), 0x1014: ('ret', '')}
        states = scan.argument_states(ins, 0x1000)
        self.assertNotEqual(states[0x1014][19], 'this')
        self.assertEqual(states[0x1014][20], 'debug')

    def test_neighbor_after_return_is_not_reachable(self):
        ins = {0x1000: ('ret', ''), 0x1004: ('mov', 'x19, x0')}
        self.assertNotIn(0x1004, scan.argument_states(ins, 0x1000))

    def test_writeback_load_invalidates_this_base_register(self):
        ins = {0x1000: ('mov', 'x19, x0'), 0x1004: ('ldp', 'x2, x3, [x19], #16'), 0x1008: ('ret', '')}
        self.assertIsNone(scan.argument_states(ins, 0x1000)[0x1008][19])

    def test_atomic_store_status_invalidates_this_register(self):
        ins = {0x1000: ('mov', 'x19, x0'), 0x1004: ('stxr', 'w19, x2, [x3]'), 0x1008: ('ret', '')}
        self.assertIsNone(scan.argument_states(ins, 0x1000)[0x1008][19])

    def test_atomic_swap_result_invalidates_this_register(self):
        ins = {0x1000: ('mov', 'x19, x0'), 0x1004: ('swp', 'x2, x19, [x3]'), 0x1008: ('ret', '')}
        self.assertIsNone(scan.argument_states(ins, 0x1000)[0x1008][19])

    def test_unknown_version_requires_explicit_cdp_choice(self):
        with self.assertRaises(ValueError):
            files.choose_cdp_policy(None, None, None)


class AtomicFileTests(unittest.TestCase):
    def test_failed_replace_preserves_old_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'config'; p.write_bytes(b'old')
            with patch('first_files.os.replace', side_effect=OSError('disk failure')):
                with self.assertRaises(OSError): files.atomic_write(p, b'new')
            self.assertEqual(p.read_bytes(), b'old')
            self.assertEqual(sorted(x.name for x in Path(td).iterdir()), ['config'])

    def test_failed_second_install_restores_first_and_old_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); dest = root / 'resources'; dest.mkdir()
            (dest / 'hook.js').write_bytes(b'old-hook')
            (dest / 'config.json').write_bytes(b'old-json')
            original = files.atomic_write
            failed = False
            def fail_once(path, data):
                nonlocal failed
                if Path(path).name == 'config.json' and data == b'new-json' and not failed:
                    failed = True
                    raise OSError('disk failure')
                return original(path, data)
            with patch('first_files.atomic_write', side_effect=fail_once):
                with self.assertRaises(OSError):
                    files.install_transaction(dest, {'hook.js': b'new-hook', 'config.json': b'new-json'}, root / 'backups')
            self.assertEqual((dest / 'hook.js').read_bytes(), b'old-hook')
            self.assertEqual((dest / 'config.json').read_bytes(), b'old-json')

    def test_backup_and_rollback_restore_old_and_remove_new_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); dest = root / 'resources'; dest.mkdir()
            (dest / 'hook.js').write_bytes(b'old-hook')
            backup = files.install_transaction(dest, {'hook.js': b'new-hook', 'config/mac/new.json': b'new-json'}, root / 'backups')
            self.assertEqual((dest / 'hook.js').read_bytes(), b'new-hook')
            files.rollback_transaction(backup, dest)
            self.assertEqual((dest / 'hook.js').read_bytes(), b'old-hook')
            self.assertFalse((dest / 'config/mac/new.json').exists())

    def test_rollback_rejects_changed_destination(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); dest = root / 'resources'; dest.mkdir()
            backup = files.install_transaction(dest, {'hook.js': b'new'}, root / 'backups')
            (dest / 'hook.js').write_bytes(b'changed-by-user')
            with self.assertRaises(ValueError): files.rollback_transaction(backup, dest)
            self.assertEqual((dest / 'hook.js').read_bytes(), b'changed-by-user')

    def test_changed_hook_invalidates_previous_runtime_validation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); meta = root / 'validation/mac'; meta.mkdir(parents=True)
            (meta / 'addresses.25755.json').write_text(json.dumps({'runtime_verified': True, 'hook_sha256': files.sha256(b'old-hook'), 'config_sha256': files.sha256(b'config')}))
            self.assertFalse(files.runtime_validated(root, 'mac', 'addresses.25755.json', b'new-hook', b'config'))


if __name__ == '__main__':
    unittest.main()
