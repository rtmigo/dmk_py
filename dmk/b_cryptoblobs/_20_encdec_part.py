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
    MAX_CLUSTER_CONTENT_SIZE, CLUSTER_SIZE, CLUSTER_META_SIZE
from dmk.a_base._05_codename import CodenameAscii, CODENAME_LENGTH_BYTES
from dmk.a_base._10_kdf import CodenameKey
from dmk.a_utils.dirty_file import WritingToTempFile
from dmk.a_utils.randoms import set_random_last_modified
from dmk.b_cryptoblobs._10_byte_funcs import bytes_to_uint32, \
    uint32_to_bytes, uint16_to_bytes, \
    bytes_to_uint16
from dmk.b_cryptoblobs._10_padding import IntroPadding

_DEBUG_PRINT = False


class VerificationFailure(Exception):
    pass


class GroupImprintMismatch(Exception):
    pass


class ItemImprintMismatch(Exception):
    pass


_intro_padding_64 = IntroPadding(64)

ENCRYPTION_NONCE_LEN = 12  # "The TLS ChaCha20 as defined in RFC7539."
MAC_LEN = 16
HEADER_CHECKSUM_LEN = 4
VERSION_LEN = 1


def blake2s_128(data: bytes) -> bytes:
    h_obj = BLAKE2s.new(digest_bits=128)
    h_obj.update(data)
    return h_obj.digest()


def blake2s_256(data: bytes) -> bytes:
    h_obj = BLAKE2s.new(digest_bits=256)
    h_obj.update(data)
    return h_obj.digest()


def bytes_to_str(lst: bytes):
    result = '['
    if len(lst) > 0:
        result += hex(lst[0])[2:]
    if len(lst) > 1:
        result += ' ' + hex(lst[1])[2:]
    if len(lst) > 2:
        result += ' .. ' + hex(lst[-1])[2:]
    result += ']'
    result += f' len {len(lst)}'
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

    #            self.cipher = ChaCha20.new(key=self.fpk.as_bytes)

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

        # self.is_fake = is_fake

        # if self.is_fake:
        #     self.data_version = FAKE_DATA_VERSION
        # else:
        #     if data_version == FAKE_DATA_VERSION:
        #         raise ValueError(
        #             f"Data version {data_version} is for fakes only")

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

        </imprint>


        <encrypted>
            <header>
                CODENAME    (24 bytes)  The codename string in ASCII.

                                        For codenames shorter than 24 chars
                                        it is prefixed with random bytes
                                        ending with 0x00.

                                        "...\0codename"

                                        We deliberately place it at the
                                        beginning of the stream to check for
                                        a match as quickly as possible (quickly
                                        discard inappropriate blocks).

                                        And it's good that our decrypted stream
                                        starts from such a randomish data.

                CONTENT_CRC32 (uint32)  Checksum of the CONTENT_DATA
                                        (the entry data, stored in current
                                        block).

                                        For fake bloks it is not checksum,
                                        but four random bytes.


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

            HEADER_CHECKSUM (32 bytes)  Blake2s 256-bit hash of the header.

                                        This is the final stage of verification,
                                        after which we will definitely decide
                                        that the block belongs to the codename.


                                        It is stored inside the encrypted
                                        stream, so even for identical headers
                                        the checksum will look different from
                                        the outside.

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

        # imprint_a = Imprint(self.cnk)
        # imprint_b = Imprint(self.cnk)
        # assert imprint_a.as_bytes != imprint_b.as_bytes

        # if total_size is None:

        # ITEM_VER
        if is_fake:
            content_ver_bytes = uint32_to_bytes(FAKE_CONTENT_VERSION)
        else:
            content_ver_bytes = uint32_to_bytes(self.data_version)

        # # FULL_SIZE
        # full_size = get_stream_size(source)
        # full_size_bytes = uint24_to_bytes(full_size)

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

        # parts_len_bytes = uint16_to_bytes(self.parts_len - 1)
        part_idx_bytes = uint16_to_bytes(self.part_idx)
        part_size_bytes = uint16_to_bytes(part_is_last_and_size)
        # header_end_marker = b'~'

        codename_data = CodenameAscii.to_padded_ascii(self.cnk.codename)

        # header_crc_bytes = uint32_to_bytes(zlib.crc32(header_bytes))

        cryptographer = Cryptographer(fpk=self.cnk,
                                      nonce=nonce)

        if _DEBUG_PRINT:
            print("---")
            print("ENCRYPTION:")
            print(cryptographer)
            print("---")

        # writing the imprint. It is not encrypted, but it's a hash +
        # random nonce. It's indistinguishable from any random rubbish
        outfile.write(nonce)
        # outfile.write(imprint_b.as_bytes)

        assert len(cryptographer.nonce) == ENCRYPTION_NONCE_LEN, \
            f"Unexpected nonce length: {len(cryptographer.nonce)}"

        # outfile.write(cryptographer.nonce)

        assert outfile.seek(0, io.SEEK_CUR) <= 1024

        def encrypt_and_write(data: bytes):
            outfile.write(cryptographer.cipher.encrypt(data))

        # CRC-32 are extremely unpredictable bytes. Therefore, we place
        # them at the very beginning of the data to be encrypted.

        header_data = b''.join((
            codename_data,
            body_crc_bytes,
            part_idx_bytes,
            part_size_bytes,
            content_ver_bytes,
        ))

        encrypt_and_write(header_data)
        encrypt_and_write(blake2s_256(header_data))

        # encrypt_and_write(body_crc_bytes)
        # encrypt_and_write(item_version_bytes)
        # encrypt_and_write(part_idx_bytes)
        # encrypt_and_write(part_size_bytes)
        # encrypt_and_write(header_end_marker)

        # encrypt_and_write(header_bytes)

        assert outfile.tell() == CLUSTER_META_SIZE, f"pos is {outfile.tell()}"

        if not is_fake:  # todo test fakes creation separately
            assert body_bytes is not None
            encrypt_and_write(body_bytes)

        # adding random data to the end of block.
        # This data is not encrypted, it's from urandom (is it ok?)
        current_size = outfile.tell()
        padding_size = self.target_size - current_size
        assert padding_size >= 0
        outfile.write(get_random_bytes(padding_size))

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

        self._header: Optional[Header] = None
        self._tried_to_read_header = False

        self._data_read = False

        self._belongs_to_namegroup: Optional[bool] = None
        self._contains_data: Optional[bool] = None

        self._imprint_a_checked = False
        self._imprint_b_checked = False

        self._imprint_a_bytes: Optional[bytes] = None
        # self._imprint_b_bytes: Optional[bytes] = None

        pos = self._source.tell()
        if pos != 0:
            raise ValueError(f"Unexpected stream position {pos}")

    def __read_and_decrypt(self, n: int) -> bytes:
        encrypted = self._source.read(n)
        assert encrypted is not None
        if len(encrypted) < n:
            raise InsufficientData
        return self.cfg.cipher.decrypt(encrypted)

    # @property
    # def imprint_a_bytes(self) -> bytes:
    #     if self._imprint_a_bytes is None:
    #         _expect_position(self._source, 0)
    #         self._imprint_a_bytes = read_or_fail(self._source, Imprint.FULL_LEN)
    #
    #         # self._imprint_a_bytes = self.read_imprint_a_bytes(self._source)
    #         # self._expect_position(0)
    #         # self._imprint_a_bytes = read_or_fail(self._source, Imprint.FULL_LEN)
    #     return self._imprint_a_bytes

    @property
    def nonce(self) -> bytes:
        if self._nonce is None:
            _expect_position(self._source, 0)
            self._nonce = read_or_fail(self._source, ENCRYPTION_NONCE_LEN)
        return self._nonce
        # return Imprint.bytes_to_nonce(self.imprint_a_bytes)

    # @staticmethod
    # def read_imprint_a_bytes(stream: BinaryIO) -> bytes:
    #     _expect_position(stream, 0)
    #     return read_or_fail(stream, Imprint.FULL_LEN)

    # @staticmethod
    # def read_imprint_b_bytes(stream: BinaryIO) -> bytes:
    #     _expect_position(stream, Imprint.FULL_LEN)
    #     return read_or_fail(stream, Imprint.FULL_LEN)

    # @property
    # def imprint_b_bytes(self) -> bytes:
    #     _ = self.imprint_a_bytes
    #     if self._imprint_b_bytes is None:
    #         _expect_position(self._source,  Imprint.FULL_LEN)
    #         self._imprint_b_bytes = read_or_fail(self._source, Imprint.FULL_LEN)
    #     return self._imprint_b_bytes

    # @property
    # def imprint_b_bytes(self) -> bytes:
    #     if self._imprint_b_bytes is None:
    #         pos = self._source.tell()
    #         if pos != 0:
    #             raise ValueError(f"Unexpected stream position {pos}")
    #         self._imprint_b_bytes = read_or_fail(self._source, Imprint.FULL_LEN)
    #     return self._imprint_b_bytes

    @property
    def belongs_to_namegroup(self) -> bool:
        # reads and interprets IMPRINT_A

        return self.header_opt is not None

        # if self._belongs_to_namegroup is None:
        #     try:
        #
        #         # pos = self._source.tell()
        #         # if pos != 0:
        #         #     raise ValueError(f"Unexpected stream position {pos}")
        #         # imp = read_or_fail(self._source, Imprint.FULL_LEN)
        #         self._belongs_to_namegroup = \
        #             pk_matches_imprint_bytes(self.fpk,
        #                                      self.imprint_a_bytes)
        #     except InsufficientData:
        #         self._belongs_to_namegroup = False
        # assert self._belongs_to_namegroup is not None
        # return self._belongs_to_namegroup

    @property
    def contains_data(self) -> bool:
        # reads and interprets IMPRINT_B

        return self.header_opt is not None \
               and self.header_opt.data_version != FAKE_CONTENT_VERSION

        # if not self.belongs_to_namegroup:
        #     return False
        #
        # return self.header.data_version != FAKE_CONTENT_VERSION

        # if self._contains_data is None:
        #     try:
        #         # imp = read_or_fail(self._source, Imprint.FULL_LEN)
        #         self._contains_data = pk_matches_imprint_bytes(
        #             self.fpk, self.read_imprint_b_bytes(self._source))
        #     except InsufficientData:
        #         self._contains_data = False
        #
        # assert self._contains_data is not None
        # return self._contains_data

    @property
    def header(self) -> Header:
        result = self.header_opt
        if result is None:
            raise TypeError
        else:
            return result
        # if not self.belongs_to_namegroup:
        #     raise GroupImprintMismatch
        #
        # if self._tried_to_read_header:
        #     if self._header is None:
        #         raise TypeError
        #     else:
        #         return self._header
        #
        # self._tried_to_read_header = True
        # self._header = self.__read_header()
        # assert self._header is not None
        # return self._header

    @property
    def header_opt(self) -> Optional[Header]:
        # if not self.belongs_to_namegroup:
        #    raise GroupImprintMismatch

        if not self._tried_to_read_header:
            self._tried_to_read_header = True
            try:
                self._header = self.__read_header()
            except VerificationFailure:
                self._header = None

        return self._header

    def __read_header(self) -> Header:

        # nonce = read_or_fail(self._source, ENCRYPTION_NONCE_LEN)

        self.cfg = Cryptographer(fpk=self.fpk, nonce=self.nonce)

        if _DEBUG_PRINT:
            print("---")
            print("DECRYPTION:")
            print(self.cfg)
            print("---")

        # skipping the padding
        # ip_first = self.__read_and_decrypt(1)[0]
        # ip_len = _intro_padding_64.first_byte_to_len(ip_first)
        # if ip_len > 0:
        #     self.__read_and_decrypt(ip_len)

        # format_id = self.__read_and_decrypt(2)
        # assert format_id.decode('ascii') == "LS"

        # FORMAT VERSION is always 1
        # format_version_bytes = self.__read_and_decrypt(VERSION_LEN)
        # format_version = format_version_bytes[0]
        # assert format_version == 1

        codename_data = self.__read_and_decrypt(CODENAME_LENGTH_BYTES)
        if CodenameAscii.unpadded(codename_data) != CodenameAscii.to_ascii(
                self.fpk.codename):
            # todo cache codename_to_ascii in fpk
            raise VerificationFailure("Codename mismatch.")

        body_crc32_data = self.__read_and_decrypt(4)
        content_crc32 = bytes_to_uint32(body_crc32_data)

        # # FULL_SIZE is the size of original file
        # full_size_bytes = self.__read_and_decrypt(3)
        # size = bytes_to_uint24(full_size_bytes)

        # # PARTS_LEN
        # parts_len_bytes = self.__read_and_decrypt(2)
        # parts_len = bytes_to_uint16(parts_len_bytes) + 1

        # PART_IDX
        part_idx_data = self.__read_and_decrypt(2)
        part_idx = bytes_to_uint16(part_idx_data)

        # PART_SIZE
        part_size_data = self.__read_and_decrypt(2)
        last_and_size = bytes_to_uint16(part_size_data)
        part_size = get_lower15bits(last_and_size)
        is_last = get_highest_bit_16(last_and_size)
        # part_size_bytes = self.__read_and_decrypt(2)
        # part_size = bytes_to_uint16(part_size_bytes)

        # CONTENT_VER
        content_version_data = self.__read_and_decrypt(4)
        content_version = bytes_to_uint32(content_version_data)

        header_checksum = self.__read_and_decrypt(32)

        # todo read whole header data, then re-read from bytesio?

        header_data = b''.join((
            codename_data,
            body_crc32_data,
            part_idx_data,
            part_size_data,
            content_version_data,
        ))

        # we had already made sure that a matching codename was found inside
        # the decrypted data. This is how we insured ourselves against private
        # key collisions.
        #
        # But it is possible that we "decrypted" the expected codename from
        # random data. For example, if the code name consists of a single byte,
        # then each 256th private key combination with a nonce would "decrypt"
        # the expected byte. And the variety of possible key+nonce combinations
        # would not have helped in any way. Figuratively speaking, by using
        # a new nonce every time, we deliberately brute force such a collision.
        #
        # The good news is that we are ready for this. Now is the final stage
        # of verification: we compare the checksum of the decrypted header
        # with the checksum also read from the encrypted data.
        #
        # This is how we verify everything together in combination:
        #
        # - the 256-bit checksum can be read correctly from the stream.
        #   If we decode nonsense with a random key, then the checksum will
        #   not match the header: either the header or the sum will be read
        #   incorrectly. The match almost certainly means, the private key
        #   is correct
        #
        # - the codename we decrypted from the header was correct according
        #   to the checksum. That almost certainly means, that when we matched
        #   the read codename against the codename provided by user, it proved
        #   (a) was is the correct codename (b) we are so successful at
        #   decrypting the data not because of the KDF collision
        #
        # So we got perfect match of 256-bit key with a 256-bit checksum and
        # variable-length codename (up to 24 bytes).
        #
        # It's still not deterministic. But even if you brute force it hard, it
        # will lead to a collision only on a spaceship with infinite
        # improbability drive. This is also not a completely deterministic
        # statement.


        if blake2s_256(header_data) != header_checksum:
            raise VerificationFailure("Header checksum mismatch.")

        # header_end_marker = self.__read_and_decrypt(1)
        # if header_end_marker != b'~':
        #     raise RuntimeError("Header end marker not found")

        # reading and checking the header checksum
        # header_crc = int.from_bytes(
        #     self.__read_and_decrypt(HEADER_CHECKSUM_LEN),
        #     byteorder='big',
        #     signed=False)
        # header_bytes = b''.join((#format_id,
        #                          #format_version_bytes,
        #                          data_version_bytes,
        #                          full_size_bytes,
        #                          parts_len_bytes,
        #                          part_idx_bytes,
        #                          part_size_bytes))
        # if zlib.crc32(header_bytes) != header_crc:
        #     raise ChecksumMismatch("Header CRC mismatch.")

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

        # _ = self.header

        assert self._source.tell() == CLUSTER_META_SIZE, f"pos is {self._source.tell()}"

        body = self.__read_and_decrypt(self.header.part_size)
        # body_crc = bytes_to_uint32(self.__read_and_decrypt(4))
        if zlib.crc32(body) != self.header.content_crc32:
            raise VerificationFailure("Body CRC mismatch.")

        self._data_read = True
        return body


# class _DecryptedFile:
#     """It is better to always use DecryptedIO instead of this class.
#     The class is kept for temporary compatibility with tests."""
#
#     # todo remove all usages of this class
#     def __init__(self,
#                  source_file: Path,
#                  fpk: CodenameKey,
#                  decrypt_body=True):
#
#         with source_file.open('rb') as f:
#             di = DecryptedIO(fpk, f)
#             self.data_version = di.header.data_version
#             self.size = di.header.data_size
#
#             self.data: Optional[bytes]
#             if decrypt_body:
#                 self.data = di.read_data()
#             else:
#                 self.data = None
#
#     def write(self, target: Path):
#         if self.data is None:
#             raise RuntimeError("Body is not set.")
#         target.write_bytes(self.data)


def is_content_io(fpk: CodenameKey, stream: BinaryIO) -> bool:
    return DecryptedIO(fpk, stream).contains_data


def is_fake_io(fpk: CodenameKey, stream: BinaryIO) -> bool:
    dio = DecryptedIO(fpk, stream)
    return dio.belongs_to_namegroup and not dio.contains_data
