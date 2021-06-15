import io
import unittest
from io import BytesIO

from codn.b_storage_file._10_fragment_io import FragmentIO


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

                self.assertEqual(reader.seek(20, io.SEEK_SET), 20)  # why?..
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

    #
    def test_compare_ref(self):
        large_bytes = b'0123456789'
        part_bytes = b'345678'
        self.assertTrue(part_bytes in large_bytes)

        with BytesIO(large_bytes) as large_io:
            with FragmentIO(large_io, 3, 6) as partial:
                partial.seek(0, io.SEEK_SET)
                with BytesIO(part_bytes) as reference:
                    self.assertAllEqual(
                        reference.read(),
                        partial.read(),
                        b'345678')

                    with self.subTest('seek set'):
                        self.assertAllEqual(
                            reference.seek(2, io.SEEK_SET),
                            partial.seek(2, io.SEEK_SET),
                            2)

                        self.assertAllEqual(
                            reference.read(),
                            partial.read(),
                            b'5678')

                    with self.subTest('seek zero'):
                        self.assertAllEqual(
                            reference.seek(0, io.SEEK_SET),
                            partial.seek(0, io.SEEK_SET),
                            0)

                        self.assertAllEqual(
                            reference.read(),
                            partial.read(),
                            b'345678')

                    with self.subTest('seek set far right'):
                        self.assertAllEqual(
                            reference.seek(25, io.SEEK_SET),
                            partial.seek(25, io.SEEK_SET),
                            25)

                        self.assertAllEqual(
                            reference.read(),
                            partial.read(),
                            b'')

                    with self.subTest('seek set far left'):
                        with self.assertRaises(ValueError):
                            reference.seek(-10, io.SEEK_SET)
                        with self.assertRaises(ValueError):
                            partial.seek(-10, io.SEEK_SET)

                        self.assertAllEqual(
                            reference.read(),
                            partial.read(),
                            b'')

                    with self.subTest('seek set'):
                        self.assertAllEqual(
                            reference.seek(6, io.SEEK_SET),
                            partial.seek(6, io.SEEK_SET),
                            6)

                        self.assertAllEqual(
                            reference.read(),
                            partial.read(),
                            b'')

                        self.assertAllEqual(
                            reference.seek(5, io.SEEK_SET),
                            partial.seek(5, io.SEEK_SET),
                            5)

                        self.assertAllEqual(
                            reference.read(),
                            partial.read(),
                            b'8')

                    with self.subTest('seek end'):
                        self.assertAllEqual(
                            reference.seek(0, io.SEEK_END),
                            partial.seek(0, io.SEEK_END),
                            6)

                        self.assertAllEqual(
                            reference.read(),
                            partial.read(),
                            b'')

                        self.assertAllEqual(
                            reference.seek(-2, io.SEEK_END),
                            partial.seek(-2, io.SEEK_END),
                            4)

                        self.assertAllEqual(
                            reference.read(),
                            partial.read(),
                            b'78')

                    with self.subTest('seek end too far'):
                        self.assertAllEqual(
                            reference.seek(-100, io.SEEK_END),
                            partial.seek(-100, io.SEEK_END),
                            0)


if __name__ == "__main__":
    unittest.main()
