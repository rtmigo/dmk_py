# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import unittest
from io import BytesIO

from dmk._common import KEY_SALT_SIZE, CLUSTER_SIZE
from dmk.a_utils.randoms import get_noncrypt_random_bytes
from dmk.b_storage_file._30_storage_file import StorageFileWriter, \
    StorageFileReader, version_to_bytes, bytes_to_version


class TestContainerFile(unittest.TestCase):

    def test_version(self):
        for v in [0, 1, 2, 3]:
            with self.subTest(f"ver {v}"):
                datas = set()
                for _ in range(100):
                    data = version_to_bytes(v)
                    self.assertEqual(bytes_to_version(data), v)
                    datas.add(data)
                self.assertGreater(len(datas), 4)

        with self.assertRaises(ValueError):
            version_to_bytes(-1)
        with self.assertRaises(ValueError):
            version_to_bytes(4)

    def test(self):
        salt = get_noncrypt_random_bytes(KEY_SALT_SIZE)

        with BytesIO() as stream:
            writer = StorageFileWriter(stream, salt)

            a = get_noncrypt_random_bytes(CLUSTER_SIZE)
            b = get_noncrypt_random_bytes(CLUSTER_SIZE)
            c = get_noncrypt_random_bytes(CLUSTER_SIZE)

            writer.blobs.write_bytes(a)
            writer.blobs.write_bytes(b)
            writer.blobs.write_bytes(c)
            writer.blobs.write_tail()

            stream.seek(0, io.SEEK_SET)
            reader = StorageFileReader(stream)
            self.assertEqual(reader.salt, salt)
            self.assertEqual(len(reader.blobs), 3)
            self.assertEqual(reader.blobs.io(1).read(), b)
            self.assertEqual(reader.blobs.io(2).read(), c)
            self.assertEqual(reader.blobs.io(0).read(), a)
            self.assertEqual(reader.blobs.io(2).read(), c)

        pass


if __name__ == "__main__":
    unittest.main()
