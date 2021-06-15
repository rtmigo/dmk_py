import io
import random
import unittest
import zlib
from io import BytesIO

from codn.b_storage_file._20_blobs_list_io import BlobsSequentialWriter, \
    BlobsSequentialReader, BlobChecksumMismatch, \
    BlobsIndexedReader, _obfuscate_size


class TestBlobsListFile(unittest.TestCase):

    def test_obfuscate_size_const(self):

        x = 0x000A
        obfuscated = 0xF4A3
        crc = 0x1B83EF2A

        self.assertEqual(_obfuscate_size(_obfuscate_size(x, crc), crc), x)
        self.assertEqual(_obfuscate_size(x, crc), obfuscated)

    def test_obfuscate_size_list(self):

        for x in [0x0000, 0x1234, 0xFFFF]:
            for _ in range(3):
                crc = random.randint(0, 0xFFFFFFFF)
                self.assertEqual(_obfuscate_size(_obfuscate_size(x, crc), crc),
                                 x)

    def test_write_read_bytes(self):
        with BytesIO() as large_io:
            writer = BlobsSequentialWriter(large_io)
            writer.write_bytes(b'abc')
            writer.write_bytes(b'hello')
            writer.write_bytes(b'')
            writer.write_bytes(b'777')

            large_io.seek(0, io.SEEK_SET)
            reader = BlobsSequentialReader(large_io)
            self.assertEqual(reader.read_bytes(), b'abc')
            self.assertEqual(reader.read_bytes(), b'hello')
            self.assertEqual(reader.read_bytes(), b'')
            self.assertEqual(reader.read_bytes(), b'777')
            self.assertEqual(reader.read_bytes(), None)
            self.assertEqual(reader.read_bytes(), None)

    def test_write_read_bytes_no_data(self):
        with BytesIO() as empty_io:
            brr = BlobsSequentialReader(empty_io)
            self.assertEqual(brr.read_bytes(), None)
            self.assertEqual(brr.read_bytes(), None)

    def test_write_crc_mismatch(self):
        with BytesIO() as empty_io:
            with BytesIO() as large_io:
                writer = BlobsSequentialWriter(large_io)
                writer.write_bytes(b'abc')
                writer.write_bytes(b'hello')

                large_io.seek(1, io.SEEK_SET)
                large_io.write(b'x')

                large_io.seek(0, io.SEEK_SET)
                reader = BlobsSequentialReader(large_io)
                with self.assertRaises(BlobChecksumMismatch):
                    reader.read_bytes()

    def test_indexed_reader(self):
        with BytesIO() as large_io:
            # The blobs list must start at the current stream position.
            # But not necessarily from the beginning of the stream.
            large_io.write(b'this_line_is_a_header_stub')
            blobs_start_idx = large_io.seek(0, io.SEEK_CUR)

            writer = BlobsSequentialWriter(large_io)
            writer.write_bytes(b'abc')
            writer.write_bytes(b'hello')
            writer.write_bytes(b'')
            writer.write_bytes(b'777')

            large_io.seek(blobs_start_idx, io.SEEK_SET)
            bir = BlobsIndexedReader(large_io)

            with self.subTest("Read content"):
                self.assertEqual(bir.io(1).read(), b'hello')
                self.assertEqual(bir.io(3).read(), b'777')
                self.assertEqual(bir.io(2).read(), b'')
                self.assertEqual(bir.io(0).read(), b'abc')

                # and again
                self.assertEqual(bir.io(1).read(), b'hello')
                self.assertEqual(bir.io(0).read(), b'abc')

            with self.subTest("Wrong index"):
                with self.assertRaises(IndexError):
                    bir.io(10)

            with self.subTest("CRC"):
                for i in range(len(bir)):
                    self.assertEqual(
                        zlib.crc32(bir.io(i).read()),
                        bir.crc(i))


if __name__ == "__main__":
    unittest.main()
