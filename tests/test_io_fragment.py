# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import unittest
from io import BytesIO

from dmk.b_storage_file._10_fragment_io import FragmentIO


class Test(unittest.TestCase):

    def test_read_full(self):
        buffer = b'0123456789'

        with BytesIO(buffer) as larger:
            reader = FragmentIO(larger, 0, 3)
            reader.seek(0, io.SEEK_SET)
            self.assertEqual(reader.read(), b'012')

        with BytesIO(buffer) as larger:
            reader = FragmentIO(larger, 0, 5)
            reader.seek(0, io.SEEK_SET)
            self.assertEqual(reader.read(), b'01234')

    def test_read_parts(self):
        buffer = b'0123456789'

        with BytesIO(buffer) as larger:
            reader = FragmentIO(larger, 0, 5)
            reader.seek(0, io.SEEK_SET)
            self.assertEqual(reader.read(2), b'01')
            self.assertEqual(reader.read(2), b'23')
            self.assertEqual(reader.read(2), b'4')
            self.assertEqual(reader.read(2), b'')
            self.assertEqual(reader.read(2), b'')

    #
    def test_inner_seek_set(self):
        buffer = b'0123456789'

        with BytesIO(buffer) as larger:
            with FragmentIO(larger, 1, 5) as reader:
                reader.seek(0, io.SEEK_SET)
                self.assertEqual(reader.read(3), b'123')

                self.assertEqual(reader.seek(1, io.SEEK_SET), 1)
                self.assertEqual(reader.read(3), b'234')

                self.assertEqual(reader.seek(1, io.SEEK_SET), 1)
                self.assertEqual(reader.read(), b'2345')

                self.assertEqual(reader.seek(2, io.SEEK_SET), 2)
                self.assertEqual(reader.read(), b'345')

                self.assertEqual(reader.seek(20, io.SEEK_SET), 5)
                self.assertEqual(reader.read(), b'')

    #
    def test_inner_seek_end(self):
        buffer = b'0123456789'

        with BytesIO(buffer) as larger:
            # larger.seek(1, io.SEEK_SET)
            with FragmentIO(larger, 1, 5) as reader:
                reader.seek(0, io.SEEK_SET)
                self.assertEqual(reader.read(3), b'123')
                self.assertEqual(reader.seek(0, io.SEEK_END), 5)
                self.assertEqual(reader.read(), b'')
                self.assertEqual(reader.seek(-1, io.SEEK_END), 4)

    #
    def assertAllEqual(self, a, b, c):
        self.assertEqual(a, b, "a!=b")
        self.assertEqual(a, c, "a!=c")

    def test_compare_ref(self):
        large_bytes = b'0123456789'
        part_bytes = b'345678'
        self.assertTrue(part_bytes in large_bytes)

        with BytesIO(large_bytes) as large_io:
            with FragmentIO(large_io, 3, 6) as fragment:
                fragment.seek(0, io.SEEK_SET)
                with BytesIO(part_bytes) as bytesio:
                    self.assertAllEqual(
                        bytesio.read(),
                        fragment.read(),
                        b'345678')

                    with self.subTest('seek set'):
                        self.assertAllEqual(
                            bytesio.seek(2, io.SEEK_SET),
                            fragment.seek(2, io.SEEK_SET),
                            2)

                        self.assertAllEqual(
                            bytesio.read(),
                            fragment.read(),
                            b'5678')

                    with self.subTest('seek zero'):
                        self.assertAllEqual(
                            bytesio.seek(0, io.SEEK_SET),
                            fragment.seek(0, io.SEEK_SET),
                            0)

                        self.assertAllEqual(
                            bytesio.read(),
                            fragment.read(),
                            b'345678')

                    with self.subTest('seek set far right keeps inside'):
                        # unlike BytesIO, our stream cannot leave the range
                        self.assertEqual(bytesio.seek(25, io.SEEK_SET), 25)
                        self.assertEqual(fragment.seek(25, io.SEEK_SET), 6)
                        self.assertEqual(fragment.tell(), 6)

                        # but when reading results are the same
                        self.assertAllEqual(
                            bytesio.read(),
                            fragment.read(),
                            b'')

                        self.assertEqual(fragment.tell(), 6)

                    with self.subTest('seek set far left'):
                        with self.assertRaises(ValueError):
                            bytesio.seek(-10, io.SEEK_SET)
                        with self.assertRaises(ValueError):
                            fragment.seek(-10, io.SEEK_SET)

                        self.assertAllEqual(
                            bytesio.read(),
                            fragment.read(),
                            b'')

                    with self.subTest('seek set'):
                        self.assertAllEqual(
                            bytesio.seek(6, io.SEEK_SET),
                            fragment.seek(6, io.SEEK_SET),
                            6)

                        self.assertAllEqual(
                            bytesio.read(),
                            fragment.read(),
                            b'')

                        self.assertAllEqual(
                            bytesio.seek(5, io.SEEK_SET),
                            fragment.seek(5, io.SEEK_SET),
                            5)

                        self.assertAllEqual(
                            bytesio.read(),
                            fragment.read(),
                            b'8')

                    with self.subTest('seek end'):
                        self.assertAllEqual(
                            bytesio.seek(0, io.SEEK_END),
                            fragment.seek(0, io.SEEK_END),
                            6)

                        self.assertAllEqual(
                            bytesio.read(),
                            fragment.read(),
                            b'')

                        self.assertAllEqual(
                            bytesio.seek(-2, io.SEEK_END),
                            fragment.seek(-2, io.SEEK_END),
                            4)

                        self.assertAllEqual(
                            bytesio.read(),
                            fragment.read(),
                            b'78')

                    with self.subTest('seek end too far'):
                        self.assertAllEqual(
                            bytesio.seek(-100, io.SEEK_END),
                            fragment.seek(-100, io.SEEK_END),
                            0)


if __name__ == "__main__":
    unittest.main()
