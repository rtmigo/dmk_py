# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

"""The storage file consists of a header and a list of blobs following it.
Blobs contain encrypted data. We are not trying to interpret this data here.
We only write them down and read them."""

import io
import random
from typing import BinaryIO

from codn._common import KEY_SALT_SIZE, read_or_fail
from codn.b_storage_file._20_blobs_list_io import BlobsSequentialWriter, \
    BlobsIndexedReader


def version_to_bytes(ver: int) -> bytes:
    """We generate two almost random bytes secretly containing the file format
    version. If you add up these bytes and divide by 4, the remainder of the
    division will indicate the version.

    Although the utility interprets these bytes unambiguously, the bytes
    themselves do not indicate that the file was created by the utility.
    About a quarter of the files ever created in the world will have
    the same remainder."""

    if not 0 <= ver < 4:
        raise ValueError

    a = random.randint(0, 0xFF)
    while True:
        b = random.randint(0, 0xFF)
        data = bytes((a, b))
        if bytes_to_version(data) == ver:
            return data


def bytes_to_version(data: bytes) -> int:
    return sum(data) % 4


BLOBS_START_POS = 26


class StorageFileWriter:
    def __init__(self,
                 output_io: BinaryIO,
                 salt: bytes):
        if output_io.seek(0, io.SEEK_CUR) != 0:
            raise ValueError("Unexpected stream position")

        # the first ever file format has version number 1
        output_io.write(version_to_bytes(1))

        # WRITING SALT (32 BYTES)

        if len(salt) != KEY_SALT_SIZE:
            raise ValueError("Unexpected salt size")
        output_io.write(salt)

        assert output_io.tell() == BLOBS_START_POS, output_io.tell()

        # READY TO WRITE BLOBS
        self.blobs = BlobsSequentialWriter(output_io)

    def __enter__(self):
        # todo remove
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
        #self.blobs.close()


class StorageFileReader:
    def __init__(self,
                 input_io: BinaryIO):
        if input_io.seek(0, io.SEEK_CUR) != 0:
            raise ValueError("Unexpected stream position")

        ver = bytes_to_version(read_or_fail(input_io, 2))
        if ver != 1:
            raise ValueError(f"Unexpected version: {ver}")

        # READING SALT

        self.salt = read_or_fail(input_io, KEY_SALT_SIZE)

        assert input_io.tell() == BLOBS_START_POS, input_io.tell()

        # READY TO READ BLOBS

        self.blobs = BlobsIndexedReader(input_io)
