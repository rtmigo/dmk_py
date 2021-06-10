# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import os
import random
import struct
import zlib
from pathlib import Path
from typing import Optional

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

from ksf._00_common import read_or_fail, InsufficientData
from ksf._00_wtf import WritingToTempFile
from ksf._20_key_derivation import FilesetPrivateKey
from ksf._40_imprint import Imprint, HashCollision, pk_matches_imprint_bytes
from ksf._50_sur import set_random_last_modified
from ksf._60_intro_padding import IntroPadding
from ksf.random_sizes import random_size_like_file

_DEBUG_PRINT = False


class ChecksumMismatch(Exception):
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


# SRC_MTIME_LEN = 8
# TIMESTAMP_LEN = 8
# SRC_SIZE_LEN = 3


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


def _encrypt_file_to_file(source_file: Path,
                          fpk: FilesetPrivateKey,
                          target_file: Path,
                          data_version: int = None):
    """
    File format
    -----------

    <imprint/>
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

    header_imprint = Imprint(fpk)

    stat = source_file.stat()

    version_bytes = bytes([1])

    if data_version is None:
        data_version = random.randint(0, 999999)
    data_version_bytes = int64_to_bytes(data_version)

    # src_mtime_bytes = double_to_bytes(stat.st_mtime)
    # assert len(src_mtime_bytes) == SRC_MTIME_LEN
    #
    # timestamp_bytes = double_to_bytes(time.time())
    # assert len(timestamp_bytes) == TIMESTAMP_LEN

    src_size_bytes = uint32_to_bytes(stat.st_size)

    format_identifier = 'AG'.encode('ascii')
    assert len(format_identifier) == 2

    header_bytes = b''.join((
        format_identifier,
        version_bytes,
        data_version_bytes,
        # timestamp_bytes,
        # src_mtime_bytes,
        src_size_bytes,
    ))

    # todo

    header_crc_bytes = uint32_to_bytes(zlib.crc32(header_bytes))

    body_bytes = source_file.read_bytes()
    body_crc_bytes = uint32_to_bytes(zlib.crc32(body_bytes))

    cryptographer = Cryptographer(fpk=fpk,
                                  # №name_salt=header_imprint.nonce,
                                  nonce=None)

    if _DEBUG_PRINT:
        print("---")
        print("ENCRYPTION:")
        print(cryptographer)
        print("---")

    # encrypted_bytes = cryptographer.cipher.encrypt(decrypted_bytes)

    # mac = get_fast_random_bytes(MAC_LEN)
    # if _DEBUG_PRINT:
    #     print(f"ENC: Original {bytes_to_str(decrypted_bytes)}")
    #     #print(f"ENC: Encrypted {bytes_to_str(encrypted_bytes)}")

    with WritingToTempFile(target_file) as wtf:
        # must be the same as writing a fake file
        with wtf.dirty.open('wb') as outfile:
            # writing the imprint. It is not encrypted, but it's a hash +
            # random nonce. It's indistinguishable from any random rubbish
            outfile.write(header_imprint.as_bytes)
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
            target_size = random_size_like_file(current_size)
            padding_size = target_size - current_size
            assert padding_size >= 0
            outfile.write(get_random_bytes(padding_size))
            set_random_last_modified(wtf.dirty)  # todo test it
            wtf.replace()


class DecryptedFile:

    def __init__(self,
                 source_file: Path,
                 fpk: FilesetPrivateKey,
                 decrypt_body=True):

        with source_file.open('rb') as f:
            # reading and the imprint and checking that the name
            # matches this imprint
            imprint_bytes = read_or_fail(f, Imprint.FULL_LEN)
            if not pk_matches_imprint_bytes(fpk, imprint_bytes):
                raise ChecksumMismatch("The name does not match the imprint.")

            nonce = read_or_fail(f, ENCRYPTION_NONCE_LEN)

            cfg = Cryptographer(
                fpk=fpk,
                # name=name,
                # name_salt=Imprint.bytes_to_nonce(imprint_bytes),
                nonce=nonce)

            if _DEBUG_PRINT:
                print("---")
                print("DECRYPTION:")
                print(cfg)
                print("---")

            def read_and_decrypt(n: int) -> bytes:
                encrypted = f.read(n)
                if len(encrypted) < n:
                    raise InsufficientData
                return cfg.cipher.decrypt(encrypted)

            # skipping the padding
            ip_first = read_and_decrypt(1)[0]
            ip_len = _intro_padding_64.first_byte_to_len(ip_first)
            if ip_len > 0:
                read_and_decrypt(ip_len)

            format_id = read_and_decrypt(2)
            assert format_id.decode('ascii') == "AG"

            # VERSION is always 1
            version_bytes = read_and_decrypt(VERSION_LEN)
            version = version_bytes[0]
            assert version == 1

            data_version_bytes = read_and_decrypt(8)
            self.data_version = bytes_to_int64(data_version_bytes)

            # self.size = int.from_bytes(body_size_bytes,
            #                            byteorder='big',
            #                            signed=False)

            # # TIMESTAMP is the time when the data was encrypted
            # ts_bytes = read_and_decrypt(TIMESTAMP_LEN)
            # self.timestamp = bytes_to_double(ts_bytes)
            #
            # # MTIME is the last modification time of original file
            # mtime_bytes = read_and_decrypt(SRC_MTIME_LEN)
            # self.mtime = bytes_to_double(mtime_bytes)

            # SIZE is the size of original file
            body_size_bytes = read_and_decrypt(4)
            self.size = bytes_to_uint32(body_size_bytes)

            # reading and checking the header checksum
            header_crc = int.from_bytes(
                read_and_decrypt(HEADER_CHECKSUM_LEN),
                byteorder='big',
                signed=False)
            header_bytes = (format_id +
                            version_bytes +
                            data_version_bytes +
                            body_size_bytes)
            if zlib.crc32(header_bytes) != header_crc:
                raise ChecksumMismatch("Header CRC mismatch.")

            # DATA is the content of original file
            self.data: Optional[bytes]
            if decrypt_body:
                body = read_and_decrypt(self.size)
                body_crc = bytes_to_uint32(read_and_decrypt(4))
                if zlib.crc32(body) != body_crc:
                    raise ChecksumMismatch("Body CRC mismatch.")
                self.data = body
            else:
                self.data = None

    def write(self, target: Path):
        if self.data is None:
            raise RuntimeError("Body is not set.")
        target.write_bytes(self.data)
        # os.utime(str(target), (self.mtime, self.mtime))
        # set_file_last_modified(target, self.mtime)


def encrypt_to_dir(source_file: Path, fpk: FilesetPrivateKey,
                   target_dir: Path,
                   data_version: Optional[int] = None
                   ) -> Path:
    """The file contains two imprints: one in the file name, and the other
    at the beginning of the file.

    Both imprints are generated from the same name, but with different
    nonce values.
    """

    imprint = Imprint(fpk)
    fn = target_dir / imprint.as_str
    if fn.exists():
        raise HashCollision

    _encrypt_file_to_file(source_file, fpk, fn, data_version=data_version)
    return fn


def pk_matches_header(fpk: FilesetPrivateKey, file: Path) -> bool:
    """Returns True if the header imprint (written into the file) matches
    the `name`."""
    with file.open('rb') as f:
        header_bytes = f.read(Imprint.FULL_LEN)
        if len(header_bytes) < Imprint.FULL_LEN:
            return False
        nonce = Imprint.bytes_to_nonce(header_bytes)
    return Imprint(fpk, nonce=nonce).as_bytes == header_bytes
