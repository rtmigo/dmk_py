import io
from typing import BinaryIO

from codn._common import PK_SALT_SIZE, read_or_fail
from codn.container._blobs_list_io import BlobsWriter, BlobsIndexedReader


class ContainerWriter:
    def __init__(self,
                 output_io: BinaryIO,
                 salt: bytes):
        if output_io.seek(0, io.SEEK_CUR) != 0:
            raise ValueError("Unexpected stream position")

        output_io.write(b'X')  # file identifier

        version = 2
        output_io.write(bytes([version]))

        if len(salt) != PK_SALT_SIZE:
            raise ValueError("Unexpected salt size")
        output_io.write(salt)

        output_io.write(b'~')  # header end marker

        self.blobs = BlobsWriter(output_io)


class ContainerReader:
    def __init__(self,
                 input_io: BinaryIO):
        if input_io.seek(0, io.SEEK_CUR) != 0:
            raise ValueError("Unexpected stream position")

        marker = input_io.read(1)
        if marker != b'X':
            raise ValueError("File format marker not found")

        version = read_or_fail(input_io, 1)[0]
        if version != 2:
            raise ValueError(f"Unexpected version: {version}")

        self.salt = read_or_fail(input_io, PK_SALT_SIZE)

        marker = input_io.read(1)
        if marker != b'~':
            raise ValueError("Header end marker not found")

        self.blobs = BlobsIndexedReader(input_io)
