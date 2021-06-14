# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

"""The storage file consists of a header and a list of blobs following it.
Blobs contain encrypted data. We are not trying to interpret this data here.
We only write them down and read them."""

import io
from typing import BinaryIO

from Crypto.Random import get_random_bytes

from codn._common import PK_SALT_SIZE, read_or_fail
from codn.container._20_blobs_list_io import BlobsSequentialWriter, BlobsIndexedReader


class StorageFileWriter:
    def __init__(self,
                 output_io: BinaryIO,
                 salt: bytes):
        if output_io.seek(0, io.SEEK_CUR) != 0:
            raise ValueError("Unexpected stream position")

        # While the blobs are encrypted, the file is open. However, it is
        # slightly obfuscated by simple tricks like XOR. When you first
        # look at the file, it will appear that it has no structure.

        # WRITING RANDOM LEADING (2 BYTES)

        two_random_bytes = get_random_bytes(2)
        output_io.write(two_random_bytes)

        # WRITING FORMAT IDENTIFIER (2 BYTES)

        format_identifier_data = bytes((
            ord('N') ^ two_random_bytes[0],
            ord('C') ^ two_random_bytes[1]
        ))
        output_io.write(format_identifier_data)

        # WRITING VERSION (1 BYTE)

        version = 2
        version_data = bytes(
            (version ^ two_random_bytes[0] ^ two_random_bytes[1],))
        output_io.write(version_data)

        # WRITING SALT (32 BYTES)

        if len(salt) != PK_SALT_SIZE:
            raise ValueError("Unexpected salt size")
        output_io.write(salt)

        # WRITING HEADER END MARKER

        header_end_marker = two_random_bytes[0] ^ two_random_bytes[1]
        output_io.write(bytes((header_end_marker,)))

        # READY TO WRITE BLOBS

        self.blobs = BlobsSequentialWriter(output_io)


class StorageFileReader:
    def __init__(self,
                 input_io: BinaryIO):
        if input_io.seek(0, io.SEEK_CUR) != 0:
            raise ValueError("Unexpected stream position")

        two_random_bytes = read_or_fail(input_io, 2)

        # READING FORMAT IDENTIFIER

        format_identifier_data = read_or_fail(input_io, 2)

        expected_format_identifier_data = bytes((
            ord('N') ^ two_random_bytes[0],
            ord('C') ^ two_random_bytes[1]
        ))

        if format_identifier_data != expected_format_identifier_data:
            raise ValueError("Format identifier not found")

        # READING VERSION

        version = read_or_fail(input_io, 1)[0]
        version = version ^ two_random_bytes[0] ^ two_random_bytes[1]
        if version != 2:
            raise ValueError(f"Unexpected version: {version}")

        # READING SALT

        self.salt = read_or_fail(input_io, PK_SALT_SIZE)

        # CHECKING HEADER END MARKER

        expected_header_end_marker = two_random_bytes[0] ^ two_random_bytes[1]
        marker = read_or_fail(input_io, 1)[0]
        if marker != expected_header_end_marker:
            raise ValueError("Header end marker not found")

        # READY TO READ BLOBS

        self.blobs = BlobsIndexedReader(input_io)
