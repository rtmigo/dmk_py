# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import unittest
from io import BytesIO

from dmk._common import CLUSTER_SIZE
from dmk.a_utils.randoms import get_noncrypt_random_bytes
from dmk.b_storage_file._20_blocks_rw import BlocksSequentialWriter, \
    BlocksIndexedReader


class TestBlobsListFile(unittest.TestCase):

    def test_without_tail(self):

        for tail in [False, True]:
            with self.subTest(f"tail: {tail}"):

                a = get_noncrypt_random_bytes(CLUSTER_SIZE)
                b = get_noncrypt_random_bytes(CLUSTER_SIZE)
                c = get_noncrypt_random_bytes(CLUSTER_SIZE)

                # we will make many iterations if testing with tail,
                # because the tail hash random size [1..CLUSTER_SIZE-1],
                # and we need to make sure no random values cause problems
                n = CLUSTER_SIZE * 2 if tail else 1

                for _ in range(n):

                    with BytesIO() as large_io:
                        with BlocksSequentialWriter(large_io) as writer:
                            writer.write_bytes(a)
                            writer.write_bytes(b)
                            writer.write_bytes(c)
                            if tail:
                                writer.write_tail()

                        large_io.seek(0, io.SEEK_SET)
                        reader = BlocksIndexedReader(large_io)
                        self.assertEqual(len(reader), 3)

                        if tail:
                            self.assertGreater(reader.tail_size, 0)
                        else:
                            self.assertEqual(reader.tail_size, 0)

                        for _ in range(2):
                            self.assertEqual(reader.io(2).read(), c)
                            self.assertEqual(reader.io(1).read(), b)
                            self.assertEqual(reader.io(0).read(), a)
                            self.assertEqual(reader.io(1).read(), b)

                        with self.assertRaises(IndexError):
                            reader.io(3)

    # def test_write_read_bytes(self):
    #     with BytesIO() as large_io:
    #         clusters = [
    #             get_noncrypt_random_bytes(CLUSTER_SIZE)
    #             for _ in range(3)
    #         ]
    #
    #         with BlobsSequentialWriter(large_io) as writer:
    #             for cluster_data in clusters:
    #                 writer.write_bytes(cluster_data)
    #
    #         large_io.seek(0, io.SEEK_SET)
    #         reader = BlobsIndexedReader(large_io)
    #         self.assertEqual(reader.io(0).read(), clusters[0])
    #         self.assertEqual(reader.io(1).read(), clusters[1])
    #         self.assertEqual(reader.io(2).read(), clusters[2])
    #         with self.assertRaises(IndexError):
    #             reader.io(3)
    #         self.assertEqual(reader.io(1).read(), clusters[1])

    #            self.assertEqual(reader.read_bytes(), clusters[1])
    #           self.assertEqual(reader.read_bytes(), clusters[2])
    #          self.assertEqual(reader.read_bytes(), None)
    #         self.assertEqual(reader.read_bytes(), None)

    def test_empty_stream(self):
        with BytesIO() as empty_io:
            brr = BlocksIndexedReader(empty_io)
            self.assertEqual(len(brr), 0)

    def test_end_of_stream(self):
        with BytesIO(b'123') as end_io:
            end_io.seek(0, io.SEEK_END)
            brr = BlocksIndexedReader(end_io)
            self.assertEqual(len(brr), 0)

            # self.assertEqual(brr.read_bytes(), None)
            # self.assertEqual(brr.read_bytes(), None)


# def test_write_crc_mismatch(self):
#     with BytesIO() as empty_io:
#         with BytesIO() as large_io:
#             with BlobsSequentialWriter(large_io) as writer:
#                 writer.write_bytes(b'abc')
#                 writer.write_bytes(b'hello')
#
#             large_io.seek(1, io.SEEK_SET)
#             large_io.write(b'x')
#
#             large_io.seek(0, io.SEEK_SET)
#             reader = BlobsSequentialReader(large_io)
#             # with self.assertRaises(BlobChecksumMismatch):
#             #     reader.read_bytes()

# def test_indexed_reader(self):
#     with BytesIO() as large_io:
#         # The blobs list must start at the current stream position.
#         # But not necessarily from the beginning of the stream.
#         large_io.write(b'this_line_is_a_header_stub')
#         blobs_start_idx = large_io.seek(0, io.SEEK_CUR)
#
#         with BlobsSequentialWriter(large_io) as writer:
#             writer.write_bytes(b'abc')
#             writer.write_bytes(b'hello')
#             writer.write_bytes(b'')
#             writer.write_bytes(b'777')
#
#         large_io.seek(blobs_start_idx, io.SEEK_SET)
#         bir = BlobsIndexedReader(large_io)
#
#         with self.subTest("Read content"):
#             self.assertEqual(bir.io(1).read(), b'hello')
#             self.assertEqual(bir.io(3).read(), b'777')
#             self.assertEqual(bir.io(2).read(), b'')
#             self.assertEqual(bir.io(0).read(), b'abc')
#
#             # and again
#             self.assertEqual(bir.io(1).read(), b'hello')
#             self.assertEqual(bir.io(0).read(), b'abc')
#
#         with self.subTest("Wrong index"):
#             with self.assertRaises(IndexError):
#                 bir.io(10)
#
#         # with self.subTest("CRC"):
#         #     for i in range(len(bir)):
#         #         self.assertEqual(
#         #             zlib.crc32(bir.io(i).read()),
#         #             bir.crc(i))


if __name__ == "__main__":
    unittest.main()
