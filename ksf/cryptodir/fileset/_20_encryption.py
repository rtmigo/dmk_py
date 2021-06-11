# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import io
import os
import struct
import zlib
from pathlib import Path
from typing import Optional, BinaryIO, NamedTuple

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

from ksf._common import read_or_fail, InsufficientData, \
    looks_like_our_basename, unique_filename
from ksf.cryptodir._10_kdf import FilesetPrivateKey
from ksf.cryptodir.fileset._10_fakes import set_random_last_modified
from ksf.cryptodir.fileset._10_imprint import Imprint, HashCollision, \
    pk_matches_imprint_bytes
from ksf.cryptodir.fileset._10_padding import IntroPadding
from ksf.cryptodir.fileset.random_sizes import random_size_like_file_greater
from ksf.utils.dirty_file import WritingToTempFile

_DEBUG_PRINT = False


class ChecksumMismatch(Exception):
    pass


class GroupImprintMismatch(Exception):
    pass


class ItemImprintMismatch(Exception):
    pass


def double_to_bytes(x: float) -> bytes:
    return struct.pack('>d', x)


def bytes_to_double(b: bytes) -> float:
    result = struct.unpack('>d', b)
    # print(result)
    return result[0]


def bytes_to_uint32(data: bytes) -> int:
    if len(data) != 4:
        raise ValueError
    return int.from_bytes(data, byteorder='big', signed=False)


def bytes_to_int64(data: bytes) -> int:
    if len(data) != 8:
        raise ValueError
    return int.from_bytes(data, byteorder='big', signed=True)


def uint32_to_bytes(x: int) -> bytes:
    return x.to_bytes(4, byteorder='big', signed=False)


def int64_to_bytes(x: int) -> bytes:
    return x.to_bytes(8, byteorder='big', signed=True)


_intro_padding_64 = IntroPadding(64)

ENCRYPTION_NONCE_LEN = 8
MAC_LEN = 16
HEADER_CHECKSUM_LEN = 4
VERSION_LEN = 1


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
                 fpk: FilesetPrivateKey,
                 nonce: Optional[bytes]):
        self.fpk = fpk
        if nonce is not None:
            self.cipher = ChaCha20.new(key=self.fpk.as_bytes, nonce=nonce)
        else:
            self.cipher = ChaCha20.new(key=self.fpk.as_bytes)

    @property
    def nonce(self):
        return self.cipher.nonce

    def __str__(self):
        return '\n'.join([
            f'fpk: {self.fpk.as_bytes}',
            # f'name salt: {bytes_to_str(self.name_salt)}',
            # f'key: {bytes_to_str(self.key)}',
            f'nonce: {bytes_to_str(self.nonce)}',
        ])


class Encrypt:
    def __init__(self, fpk, data_version: int = 0):
        self.fpk = fpk
        self.data_version = data_version

    def io_to_io(self,
                 source: BinaryIO,
                 outfile: BinaryIO):
        """
        File format
        -----------

        <imprint A/>
        <imprint B/>
        <encrypted>
            intro padding: bytes (1-64 bytes)
            <header>
                'AG': format identifier, two bytes
                format version: byte (always 1)
                data_version: int64 (increases on each write)
                body size: uint32
            </header>
            header crc-32: uint32
            body: bytes
            body crc-32: uint32
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

        imprint_a = Imprint(self.fpk)
        imprint_b = Imprint(self.fpk)
        assert imprint_a.as_bytes != imprint_b.as_bytes

        version_bytes = bytes([1])

        data_version_bytes = int64_to_bytes(self.data_version)

        src_size = source.seek(0, io.SEEK_END)
        source.seek(0, io.SEEK_SET)

        src_size_bytes = uint32_to_bytes(src_size)

        format_identifier = 'AG'.encode('ascii')
        assert len(format_identifier) == 2

        header_bytes = b''.join((
            format_identifier,
            version_bytes,
            data_version_bytes,
            src_size_bytes,
        ))

        header_crc_bytes = uint32_to_bytes(zlib.crc32(header_bytes))

        body_bytes = source.read()
        body_crc_bytes = uint32_to_bytes(zlib.crc32(body_bytes))

        cryptographer = Cryptographer(fpk=self.fpk,
                                      nonce=None)

        if _DEBUG_PRINT:
            print("---")
            print("ENCRYPTION:")
            print(cryptographer)
            print("---")

        # writing the imprint. It is not encrypted, but it's a hash +
        # random nonce. It's indistinguishable from any random rubbish
        outfile.write(imprint_a.as_bytes)
        outfile.write(imprint_b.as_bytes)

        assert len(cryptographer.nonce) == ENCRYPTION_NONCE_LEN, \
            f"Unexpected nonce length: {len(cryptographer.nonce)}"

        outfile.write(cryptographer.nonce)

        def encrypt_and_write(data: bytes):
            outfile.write(cryptographer.cipher.encrypt(data))

        encrypt_and_write(_intro_padding_64.gen_bytes())
        encrypt_and_write(header_bytes)
        encrypt_and_write(header_crc_bytes)
        # todo chunked r/w
        encrypt_and_write(body_bytes)
        encrypt_and_write(body_crc_bytes)

        # adding random data to the end of file.
        # This data is not encrypted, it's from urandom (is it ok?)
        current_size = outfile.seek(0, os.SEEK_CUR)
        target_size = random_size_like_file_greater(current_size)
        padding_size = target_size - current_size
        assert padding_size >= 0
        outfile.write(get_random_bytes(padding_size))

    def io_to_file(self,
                   source_io: BinaryIO,
                   target_file: Path):
        with WritingToTempFile(target_file) as wtf:
            # must be the same as writing a fake file
            with wtf.dirty.open('wb') as outfile:
                self.io_to_io(source_io, outfile)
                set_random_last_modified(wtf.dirty)  # todo test it
            # dirty file is written AND closed (important for Windows)
            wtf.replace()

    def file_to_file(self, source_file: Path, target_file: Path):
        with source_file.open('rb') as source_io:
            self.io_to_file(source_io, target_file)


class Header(NamedTuple):
    format_version: int
    data_version: int
    data_size: int


class DecryptedIO:
    """
    Reads encrypted data in a "lazy manner".

    After the object is created, only the imprint is read and checked.
    After accessing the `header` property, the header is read.
    After calling read_data() - the data itself (and the header).
    """

    def __init__(self,
                 fpk: FilesetPrivateKey,
                 source: BinaryIO):
        self.fpk = fpk
        self.source = source

        self._header: Optional[Header] = None
        self._data_read = False

        # self._belongs_to_fileset: Optional[bool] = None

        # self._imprint_a_bytes: Optional[bytes] = None
        # self._imprint_b_bytes: Optional[bytes] = None

        self._imprint_a_checked = False
        self._imprint_b_checked = False

        # self.__read_imprint()

    def __read_and_decrypt(self, n: int) -> bytes:
        encrypted = self.source.read(n)
        if len(encrypted) < n:
            raise InsufficientData
        return self.cfg.cipher.decrypt(encrypted)

    def read_imprint_a(self):
        if self._imprint_a_checked:
            return
        imp = read_or_fail(self.source, Imprint.FULL_LEN)
        if not pk_matches_imprint_bytes(self.fpk, imp):
            raise GroupImprintMismatch
        self._imprint_a_checked = True

    def read_imprint_b(self):
        # doing this at most once
        if self._imprint_b_checked:
            return
        # reading everything in the file before
        self.read_imprint_a()
        # reading and checking the imprint
        imp = read_or_fail(self.source, Imprint.FULL_LEN)
        if not pk_matches_imprint_bytes(self.fpk, imp):
            raise GroupImprintMismatch
        self._imprint_b_checked = True

    # @property
    # def belongs_to_fileset(self) -> bool:
    #     return pk_matches_imprint_bytes(self.fpk, self._rc_imprint_a_bytes)
    #
    # @property
    # def contains_data(self) -> bool:
    #     return pk_matches_imprint_bytes(self.fpk, self.imprint_b_bytes)

    # def __read_imprint(self):
    #     f = self.source
    #     # reading and the imprint and checking that the name
    #     # matches this imprint
    #     imprint_bytes = read_or_fail(f, Imprint.FULL_LEN)
    #     if not pk_matches_imprint_bytes(self.fpk, imprint_bytes):
    #         raise ImprintMismatch("The private key does not match the imprint.")
    #
    #     self.__nonce = read_or_fail(f, ENCRYPTION_NONCE_LEN)

    @property
    def header(self) -> Header:
        if self._header is None:
            self._header = self.__read_header()
        assert self._header is not None
        return self._header

    def __read_header(self) -> Header:

        self.read_imprint_b()

        nonce = read_or_fail(self.source, ENCRYPTION_NONCE_LEN)

        self.cfg = Cryptographer(fpk=self.fpk, nonce=nonce)

        if _DEBUG_PRINT:
            print("---")
            print("DECRYPTION:")
            print(self.cfg)
            print("---")

        # skipping the padding
        ip_first = self.__read_and_decrypt(1)[0]
        ip_len = _intro_padding_64.first_byte_to_len(ip_first)
        if ip_len > 0:
            self.__read_and_decrypt(ip_len)

        format_id = self.__read_and_decrypt(2)
        assert format_id.decode('ascii') == "AG"

        # FORMAT VERSION is always 1
        format_version_bytes = self.__read_and_decrypt(VERSION_LEN)
        format_version = format_version_bytes[0]
        assert format_version == 1

        data_version_bytes = self.__read_and_decrypt(8)
        data_version = bytes_to_int64(data_version_bytes)

        # SIZE is the size of original file
        body_size_bytes = self.__read_and_decrypt(4)
        size = bytes_to_uint32(body_size_bytes)

        # reading and checking the header checksum
        header_crc = int.from_bytes(
            self.__read_and_decrypt(HEADER_CHECKSUM_LEN),
            byteorder='big',
            signed=False)
        header_bytes = (format_id +
                        format_version_bytes +
                        data_version_bytes +
                        body_size_bytes)
        if zlib.crc32(header_bytes) != header_crc:
            raise ChecksumMismatch("Header CRC mismatch.")

        return Header(data_version=data_version,
                      format_version=format_version,
                      data_size=size)

    def read_data(self) -> bytes:
        if self._data_read:
            raise RuntimeError("Cannot read data more than once")

        _ = self.header

        body = self.__read_and_decrypt(self.header.data_size)
        body_crc = bytes_to_uint32(self.__read_and_decrypt(4))
        if zlib.crc32(body) != body_crc:
            raise ChecksumMismatch("Body CRC mismatch.")

        self._data_read = True
        return body


class _DecryptedFile:
    """It is better to always use DecryptedIO instead of this class.
    The class is kept for temporary compatibility with tests."""

    # todo remove all usages of this class
    def __init__(self,
                 source_file: Path,
                 fpk: FilesetPrivateKey,
                 decrypt_body=True):

        with source_file.open('rb') as f:
            di = DecryptedIO(fpk, f)
            self.data_version = di.header.data_version
            self.size = di.header.data_size

            self.data: Optional[bytes]
            if decrypt_body:
                self.data = di.read_data()
            else:
                self.data = None

    def write(self, target: Path):
        if self.data is None:
            raise RuntimeError("Body is not set.")
        target.write_bytes(self.data)


def encrypt_file_to_dir(source_file: Path, fpk: FilesetPrivateKey,
                        target_dir: Path,
                        data_version: int = 0) -> Path:
    # todo remove this method
    with source_file.open('rb') as f:
        return encrypt_io_to_dir(f,
                                 fpk,
                                 target_dir,
                                 data_version)

    # imprint = Imprint(fpk)
    #
    # fn = target_dir / imprint.as_str
    # assert looks_like_our_basename(fn.name)
    # if fn.exists():
    #     raise HashCollision
    # Encrypt(fpk, data_version).file_to_file(source_file, fn)
    # return fn


def encrypt_io_to_dir(source_io: BinaryIO,
                      fpk: FilesetPrivateKey,
                      target_dir: Path,
                      data_version: int = 0) -> Path:
    #imprint = Imprint(fpk)
    #unique_filename

    fn = unique_filename(target_dir) # / imprint.as_str
    assert looks_like_our_basename(fn.name)
    if fn.exists():
        raise HashCollision
    Encrypt(fpk, data_version).io_to_file(source_io, fn)
    return fn


def is_file_from_group(fpk: FilesetPrivateKey, file: Path) -> bool:
    with file.open('rb') as f:
        try:
            DecryptedIO(fpk, f).read_imprint_a()
            return True
        except (InsufficientData, GroupImprintMismatch) as e:
            #print("EXC", type(e))
            return False


def is_file_with_data(fpk: FilesetPrivateKey, file: Path) -> bool:
    with file.open('rb') as f:
        try:
            DecryptedIO(fpk, f).read_imprint_b()
            return True
        except (InsufficientData, ItemImprintMismatch, GroupImprintMismatch):
            return False
