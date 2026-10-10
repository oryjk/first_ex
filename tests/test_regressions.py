import unittest
import gen_wmpf_config as gen


class DecoderRegressionTests(unittest.TestCase):
    def test_sub_does_not_create_pretty_string_reference(self):
        self.assertIsNone(gen.is_add_imm(0xD1040100))
        self.assertEqual(gen.find_xrefs_multi([0x90000008, 0xD1040100], 0x1000, {0x1100}), {0x1100: []})

    def test_overwritten_adrp_register_does_not_create_reference(self):
        self.assertEqual(gen.find_xrefs_multi([0x90000008, 0xAA0003E8, 0x91040100], 0x1000, {0x1100}), {0x1100: []})

    def test_adjacent_add_resolves_real_reference(self):
        self.assertEqual(gen.find_xrefs_multi([0x90000008, 0x91040100], 0x1000, {0x1100}), {0x1100: [0x1000]})


if __name__ == '__main__':
    unittest.main()
