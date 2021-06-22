# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import zlib
from pathlib import Path
from typing import Optional, NamedTuple, BinaryIO

from Crypto.Cipher import ChaCha20
from Crypto.Hash import BLAKE2s
from Crypto.Random import get_random_bytes

from dmk._common import read_or_fail, InsufficientData, \
    MAX_CLUSTER_CONTENT_SIZE, CLUSTER_SIZE, CLUSTER_META_SIZE, \
    HEADER_SIZE, IMPRINT_SIZE
from dmk.a_base._10_kdf import CodenameKey
from dmk.a_utils.bytes import bytes_to_str
from dmk.a_utils.dirty_file import WritingToTempFile
from dmk.a_utils.randoms import set_random_last_modified, \
    get_noncrypt_random_bytes
from dmk.b_cryptoblobs._10_byte_funcs import bytes_to_uint32, \
    uint32_to_bytes, uint16_to_bytes, \
    bytes_to_uint16

_DEBUG_PRINT = False


class VerificationFailure(Exception):
    pass


class GroupImprintMismatch(Exception):
    pass


class ItemImprintMismatch(Exception):
    pass


# in 2021 there is finished ChaCha20 standards with 64-bit and 96-bit nonce
ENCRYPTION_NONCE_LEN = 12  # 96-bit
HEADER_CHECKSUM_LEN = 21


def blake2s(data: bytes, target_size_bytes: int) -> bytes:
    h_obj = BLAKE2s.new(digest_bits=target_size_bytes * 8)
    h_obj.update(data)
    result = h_obj.digest()
    assert len(result) == target_size_bytes
    return result


class Cryptographer:
    def __init__(self,
                 fpk: CodenameKey,
                 nonce: Optional[bytes]):
        self.fpk = fpk
        if nonce is None:
            nonce = get_random_bytes(ENCRYPTION_NONCE_LEN)

        if len(nonce) != ENCRYPTION_NONCE_LEN:
            raise ValueError("Unexpected nonce length")
        self.cipher = ChaCha20.new(key=self.fpk.as_bytes, nonce=nonce)

    @property
    def nonce(self):
        return self.cipher.nonce

    def __str__(self):
        return '\n'.join([
            f'fpk: {self.fpk.as_bytes}',

            f'nonce: {bytes_to_str(self.nonce)}',
        ])


class Header(NamedTuple):
    valid: bool
    content_crc32: int
    is_last_part: int
    # format_version: int  # todo rename
    data_version: int  # todo rename
    # data_size: int  # todo rename
    # parts_len: int
    part_idx: int
    part_size: int


def get_stream_size(stream: BinaryIO) -> int:
    pos = stream.seek(0, io.SEEK_CUR)
    size = stream.seek(0, io.SEEK_END)
    stream.seek(pos, io.SEEK_SET)
    return size


def get_highest_bit_16(x: int) -> bool:
    if not 0 <= x <= 0xFFFF:
        raise ValueError
    return (0x8000 & x) != 0


def set_highest_bit_16(x: int, value: bool) -> int:
    if not 0 <= x <= 0xFFFF:
        raise ValueError
    if value:
        x |= 0x8000
        assert get_highest_bit_16(x)
    else:
        x = x & 0x7FFF
        assert not get_highest_bit_16(x)
    assert 0 <= x <= 0xFFFF
    return x


def get_lower15bits(x: int) -> int:
    return x & 0x7FFF


FAKE_CONTENT_VERSION = 0xFFFFFFFF


def to_imprint(cnk: CodenameKey, nonce: bytes):
    assert len(nonce) == ENCRYPTION_NONCE_LEN
    return blake2s(cnk.as_bytes + nonce, IMPRINT_SIZE)


class Encrypt:
    def __init__(self,
                 cnk: CodenameKey,

                 data_version: int = 0,  # todo None
                 target_size=CLUSTER_SIZE,
                 # is_fake=False,
                 # original_size: int = None,
                 part_idx: int = 0,
                 parts_len: int = 1,
                 part_size: int = None):

        self.target_size = target_size

        if not 0 <= part_idx <= 0xFF:
            raise ValueError(f"part_idx={part_idx}")
        if not 1 <= parts_len <= 0xFF + 1:
            raise ValueError(f"parts_len={parts_len}")

        # we cannot fit blocks size larger than that into 15 bits
        assert MAX_CLUSTER_CONTENT_SIZE <= 0x7FFF

        if part_size is not None and not (
                0 <= part_size <= MAX_CLUSTER_CONTENT_SIZE):
            raise ValueError(f"part_size={part_size}")

        self.cnk = cnk
        self.data_version = data_version

        # self.original_size = original_size

        if not 0 <= part_idx <= 0xFF:
            raise ValueError(part_idx)

        self.part_idx = part_idx

        if not 0 <= parts_len <= 0xFFFFFF:
            raise ValueError(part_idx)

        self.parts_len = parts_len

        if part_size is None and not (part_idx == 0 and parts_len == 1):
            raise ValueError("part_size is not specified")
        self.part_size = part_size

    def io_to_io(self,
                 source: Optional[BinaryIO],
                 outfile: BinaryIO):
        """
        File format
        -----------

        <imprint>
            NONCE               (12 bytes)  Random bytes.
            HASH                (32 bytes)  Blake2s from PK+NONCE
        </imprint>

        <encrypted>
            <header>
                CONTENT_CRC32 (uint32)  Checksum of the CONTENT_DATA
                                        (the entry data, stored in current
                                        block).

                                        For fake blocks it is not checksum,
                                        but four random bytes.

                FORMAT_VER    (uint8)   Always 1.

                                        This constant will hypothetically make
                                        it possible to change the format of
                                        the blocks without changing the format
                                        of the container file.


                PART_IDX      (uint16)  Zero-based part index. If we split
                                        the data into three clusters, they
                                        will have PART_IDX values 0, 1, 2.

                PART_SIZE     (uint16)  Lower 15 bits is the size of the
                                        real data stored in the current
                                        cluster (without the padding)

                                        Highest bit is 1 if this is
                                        the last cluster, 0 if not

                ITEM_VER      (uint32)  Increases on each write.

                                        For fake blocks it's 0xFFFFFFFF.

            </header>

            CONTENT_DATA: bytes

        </encrypted>
        <random-padding/>
        ****


        When decrypting, we will check the name against the imprint. After that,
        we assume that the name is correct and the data can be successfully
        decrypted by this name.

        Instead of cryptographic MAC algorithms, we will use CRC32 for header
        and CRC32 for body. This will help us verify that the program is working
        as expected and that the contents of the file is correct. The CRC values
        themselves will be encrypted.

        """

        is_fake = source is None

        nonce = get_random_bytes(ENCRYPTION_NONCE_LEN)

        # ITEM_VER
        if is_fake:
            content_ver_bytes = uint32_to_bytes(FAKE_CONTENT_VERSION)
        else:
            content_ver_bytes = uint32_to_bytes(self.data_version)

        # PART_SIZE
        if self.part_size is None:
            if is_fake:
                self.part_size = 0  # todo random?
            else:
                assert self.parts_len == 1 and self.part_idx == 0
                assert source is not None
                self.part_size = get_stream_size(source)

        assert get_lower15bits(self.part_size) == self.part_size

        is_last_part = self.part_idx == self.parts_len - 1

        part_is_last_and_size = self.part_size
        part_is_last_and_size = set_highest_bit_16(
            part_is_last_and_size,
            is_last_part
        )

        assert get_lower15bits(part_is_last_and_size) == self.part_size, \
            (get_lower15bits(part_is_last_and_size), self.part_size)
        assert get_highest_bit_16(part_is_last_and_size) == is_last_part

        ##########

        body_bytes: Optional[bytes]
        body_crc_bytes: bytes
        if is_fake:
            body_bytes = None
            body_crc_bytes = get_random_bytes(4)
        else:
            assert source is not None
            body_bytes = read_or_fail(source, self.part_size)
            body_crc_bytes = uint32_to_bytes(zlib.crc32(body_bytes))

        part_idx_bytes = uint16_to_bytes(self.part_idx)
        part_size_bytes = uint16_to_bytes(part_is_last_and_size)

        # codename_data = CodenameAscii.to_padded_ascii(self.cnk.codename)

        cryptographer = Cryptographer(fpk=self.cnk,
                                      nonce=nonce)

        if _DEBUG_PRINT:
            print("---")
            print("ENCRYPTION:")
            print(cryptographer)
            print("---")

        outfile.write(nonce)

        imprint = to_imprint(self.cnk, nonce)
        assert imprint != self.cnk.as_bytes
        outfile.write(imprint)

        assert len(cryptographer.nonce) == ENCRYPTION_NONCE_LEN, \
            f"Unexpected nonce length: {len(cryptographer.nonce)}"

        assert outfile.seek(0, io.SEEK_CUR) <= 1024

        def encrypt_and_write(data: bytes):
            outfile.write(cryptographer.cipher.encrypt(data))

        version = bytes((1,))

        header_data = b''.join((
            # codename_data,
            body_crc_bytes,
            version,

            part_idx_bytes,
            part_size_bytes,
            content_ver_bytes,
        ))

        assert len(header_data) == HEADER_SIZE, len(header_data)

        encrypt_and_write(header_data)

        # checksum = blake2s(header_data, HEADER_CHECKSUM_LEN)
        # encrypt_and_write(checksum)

        assert outfile.tell() == CLUSTER_META_SIZE, f"pos is {outfile.tell()}"

        if not is_fake:  # todo test fakes creation separately
            assert body_bytes is not None
            encrypt_and_write(body_bytes)

        # adding random data to the end of block.
        # This data is not encrypted, it's from urandom (is it ok?)
        current_size = outfile.tell()
        padding_size = self.target_size - current_size
        assert padding_size >= 0

        # instead of just appending "cryptographic" random bytes with
        #   outfile.write(urandom(padding_size))
        # we generate bytes with standard RNG, and then encrypting them.
        # If urandom created any anomalies distinct from the cipher,
        # now they will not be
        encrypt_and_write(get_noncrypt_random_bytes(padding_size))

    def io_to_file(self,
                   source_io: BinaryIO,
                   target_file: Path):
        with WritingToTempFile(target_file) as wtf:
            # must be the same as writing a fake file
            with wtf.dirty.open('wb') as outfile:
                self.io_to_io(source_io, outfile)
            set_random_last_modified(wtf.dirty)
            # dirty file is written AND closed (important for Windows)
            wtf.replace()

    def file_to_file(self, source_file: Path, target_file: Path):
        with source_file.open('rb') as source_io:
            self.io_to_file(source_io, target_file)


def _expect_position(stream: BinaryIO, expected_pos: int):
    pos = stream.tell()
    if pos != expected_pos:
        raise ValueError(f"Unexpected stream position {pos}")


class DecryptedIO:
    """
    Reads encrypted data in a "lazy manner".

    After the object is created, only the imprint is read and checked.
    After accessing the `header` property, the header is read.
    After calling read_data() - the data itself (and the header).
    """

    def __init__(self,
                 fpk: CodenameKey,
                 source: BinaryIO):
        self.fpk = fpk
        self._source = source

        self._nonce: Optional[bytes] = None
        self._imprint: Optional[bytes] = None

        self._header: Optional[Header] = None
        self._tried_to_read_header = False

        self._data_read = False

        pos = self._source.tell()
        if pos != 0:
            raise ValueError(f"Unexpected stream position {pos}")

    def __read_and_decrypt(self, n: int) -> bytes:
        encrypted = self._source.read(n)
        assert encrypted is not None
        if len(encrypted) < n:
            raise InsufficientData
        return self.cfg.cipher.decrypt(encrypted)

    @property
    def nonce(self) -> bytes:
        if self._nonce is None:
            _expect_position(self._source, 0)
            self._nonce = read_or_fail(self._source, ENCRYPTION_NONCE_LEN)
        return self._nonce

    @property
    def imprint(self) -> bytes:

        if self._imprint is None:
            _ = self.nonce
            _expect_position(self._source, ENCRYPTION_NONCE_LEN)
            self._imprint = read_or_fail(self._source, IMPRINT_SIZE)
        return self._imprint

    @property
    def belongs_to_namegroup(self) -> bool:
        return self.header_opt is not None

    @property
    def contains_data(self) -> bool:
        return self.header_opt is not None \
               and self.header_opt.data_version != FAKE_CONTENT_VERSION

    @property
    def header(self) -> Header:
        result = self.header_opt
        if result is None:
            raise TypeError
        else:
            return result

    @property
    def header_opt(self) -> Optional[Header]:
        if not self._tried_to_read_header:
            self._tried_to_read_header = True
            try:
                self._header = self.__read_header()
            except VerificationFailure:
                self._header = None

        return self._header

    def __read_header(self) -> Header:

        if to_imprint(self.fpk, self.nonce) != self.imprint:
            raise VerificationFailure

        self.cfg = Cryptographer(fpk=self.fpk, nonce=self.nonce)

        if _DEBUG_PRINT:
            print("---")
            print("DECRYPTION:")
            print(self.cfg)
            print("---")

        body_crc32_data = self.__read_and_decrypt(4)
        format_version_data = self.__read_and_decrypt(1)

        # after reading the format version version we can choose different
        # paths. Do not forget that this may not be a version, but random data.
        # And there are no different ways yet: there is only one block format
        # version.

        part_idx_data = self.__read_and_decrypt(2)
        part_size_data = self.__read_and_decrypt(2)
        content_version_data = self.__read_and_decrypt(4)
        # header_checksum = self.__read_and_decrypt(HEADER_CHECKSUM_LEN)

        # todo read whole header data, then re-read from bytesio?

        header_data = b''.join((
            # codename_data,
            body_crc32_data,
            format_version_data,

            part_idx_data,
            part_size_data,
            content_version_data,
        ))

        assert len(header_data) == HEADER_SIZE, len(header_data)

        assert format_version_data[0] == 1
        part_idx = bytes_to_uint16(part_idx_data)

        last_and_size = bytes_to_uint16(part_size_data)
        part_size = get_lower15bits(last_and_size)
        is_last = get_highest_bit_16(last_and_size)

        content_version = bytes_to_uint32(content_version_data)
        content_crc32 = bytes_to_uint32(body_crc32_data)

        return Header(content_crc32=content_crc32,
                      data_version=content_version,
                      # format_version=format_version,
                      # data_size=size,
                      part_size=part_size,
                      # parts_len=parts_len,
                      part_idx=part_idx,
                      is_last_part=is_last,
                      valid=True)

    def read_data(self) -> bytes:
        if self._data_read:
            raise RuntimeError("Cannot read data more than once")

        if not self.contains_data:
            raise RuntimeError("contains_data is False")

        assert self._source.tell() == CLUSTER_META_SIZE, f"pos is {self._source.tell()}"

        body = self.__read_and_decrypt(self.header.part_size)
        if zlib.crc32(body) != self.header.content_crc32:
            raise VerificationFailure("Body CRC mismatch.")

        self._data_read = True
        return body


def is_content_io(fpk: CodenameKey, stream: BinaryIO) -> bool:
    return DecryptedIO(fpk, stream).contains_data


def is_fake_io(fpk: CodenameKey, stream: BinaryIO) -> bool:
    dio = DecryptedIO(fpk, stream)
    return dio.belongs_to_namegroup and not dio.contains_data
