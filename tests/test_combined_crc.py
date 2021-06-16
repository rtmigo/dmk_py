# import unittest
# import zlib
#
#
# class TestCombined(unittest.TestCase):
#     def test(self):
#         data_parts = [
#             b'part one',
#             b'second part',
#         ]
#
#         crcs = [
#             zlib.crc32(p)
#             for p in data_parts
#         ]
#
#         self.assertEqual(crcs, [2333348784, 3066740598])
#
#         self.assertEqual(zlib.crc32(b''.join(data_parts)), 3668275695)
#         self.assertEqual(crcs[0] ^ crcs[1], 3668275695)
#
# if __name__ == "__main__":
#     unittest.main()