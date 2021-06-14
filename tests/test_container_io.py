import io
import unittest
from io import BytesIO

from codn._common import PK_SALT_SIZE
from codn.container._container import ContainerWriter, ContainerReader
from codn.utils.randoms import get_noncrypt_random_bytes


class TestContainerFile(unittest.TestCase):
    def test(self):
        salt = get_noncrypt_random_bytes(PK_SALT_SIZE)

        with BytesIO() as stream:
            writer = ContainerWriter(stream, salt)
            writer.blobs.write_bytes(b'abc')
            writer.blobs.write_bytes(b'x')
            writer.blobs.write_bytes(b'zz')

            stream.seek(0, io.SEEK_SET)
            reader = ContainerReader(stream)
            self.assertEqual(reader.salt, salt)
            self.assertEqual(len(reader.blobs), 3)
            self.assertEqual(reader.blobs.io(1).read(), b'x')
            self.assertEqual(reader.blobs.io(2).read(), b'zz')
            self.assertEqual(reader.blobs.io(0).read(), b'abc')
            self.assertEqual(reader.blobs.io(2).read(), b'zz')




        pass


if __name__ == "__main__":
    unittest.main()
