# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

"""The storage file consists of a header and a list of blobs following it.
Blobs contain encrypted data. We are not trying to interpret this data here.
We only write them down and read them."""

import io
import random
from typing import BinaryIO

from Crypto.Random import get_random_bytes

from codn._common import PK_SALT_SIZE, read_or_fail
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

        # While the blobs are encrypted, the file is open. However, it is
        # slightly obfuscated by simple tricks like XOR. When you first
        # look at the file, it will appear that it has no structure.

        # the first ever file format has version number 1
        output_io.write(version_to_bytes(1))

        # # WRITING RANDOM LEADING (2 BYTES)
        #
        # two_random_bytes = get_random_bytes(2)
        # output_io.write(two_random_bytes)
        #
        # # WRITING FORMAT IDENTIFIER (2 BYTES)
        #
        # format_identifier_data = bytes((
        #     ord('N') ^ two_random_bytes[0],
        #     ord('C') ^ two_random_bytes[1]
        # ))
        # output_io.write(format_identifier_data)
        #
        # # WRITING VERSION (1 BYTE)
        #
        # version = 2
        # version_data = bytes(
        #     (version ^ two_random_bytes[0] ^ two_random_bytes[1],))
        # output_io.write(version_data)

        # WRITING SALT (32 BYTES)

        if len(salt) != PK_SALT_SIZE:
            raise ValueError("Unexpected salt size")
        output_io.write(salt)

        assert output_io.tell() == BLOBS_START_POS, output_io.tell()

        # # WRITING HEADER END MARKER
        #
        # header_end_marker = two_random_bytes[0] ^ two_random_bytes[1]
        # output_io.write(bytes((header_end_marker,)))

        # READY TO WRITE BLOBS
        self.blobs = BlobsSequentialWriter(output_io)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.blobs.close()


class StorageFileReader:
    def __init__(self,
                 input_io: BinaryIO):
        if input_io.seek(0, io.SEEK_CUR) != 0:
            raise ValueError("Unexpected stream position")

        ver = bytes_to_version(read_or_fail(input_io, 2))
        if ver!=1:
            raise ValueError(f"Unexpected version: {ver}")
        #if version_to_bytes(read_or_fail(input_io, 2)) != 1:

        #two_random_bytes = read_or_fail(input_io, 2)

        # READING FORMAT IDENTIFIER

        # format_identifier_data = read_or_fail(input_io, 2)
        #
        # expected_format_identifier_data = bytes((
        #     ord('N') ^ two_random_bytes[0],
        #     ord('C') ^ two_random_bytes[1]
        # ))
        #
        # if format_identifier_data != expected_format_identifier_data:
        #     raise ValueError("Format identifier not found")
        #
        # # READING VERSION
        #
        # version = read_or_fail(input_io, 1)[0]
        # version = version ^ two_random_bytes[0] ^ two_random_bytes[1]
        # if version != 2:
        #     raise ValueError(f"Unexpected version: {version}")

        # READING SALT

        self.salt = read_or_fail(input_io, PK_SALT_SIZE)

        assert input_io.tell() == BLOBS_START_POS, input_io.tell()

        # # CHECKING HEADER END MARKER
        #
        # expected_header_end_marker = two_random_bytes[0] ^ two_random_bytes[1]
        # marker = read_or_fail(input_io, 1)[0]
        # if marker != expected_header_end_marker:
        #     raise ValueError("Header end marker not found")

        # READY TO READ BLOBS

        self.blobs = BlobsIndexedReader(input_io)
