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

from ksf._05_common import read_or_fail, InsufficientData
from ksf._40_imprint import Imprint, HashCollision, name_matches_imprint_bytes
from ksf._50_sur import set_random_last_modified
from ksf._wtf import WritingToTempFile
from ksf.intro_padding import IntroPadding
from ksf.key_derivation import password_to_key

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
    return int.from_bytes(data, byteorder='big', signed=False)


def uint32_to_bytes(x: int) -> bytes:
    return x.to_bytes(4, byteorder='big', signed=False)


def encrypt_to_dir(source_file: Path, name: str, target_dir: Path) -> Path:
    """The file contains two imprints: one in the file name, and the other
    at the beginning of the file.

    Both imprints are generated from the same name, but with different
    nonce values.
    """

    imprint = Imprint(name)
    fn = target_dir / imprint.as_str
    if fn.exists():
        raise HashCollision

    _encrypt_file_to_file(source_file, name, fn)
    return fn


# def pwd_to_encryption_key(password: str, salt: bytes) -> bytes:
#     """Converts string password to a 256-bit key.
#
#     This function will be used to generate:
#     - dictionary keys (they are public)
#     - encryption keys (they are secret)
#     For each item both keys are generated from the same password,
#     but the salt must be different."""
#     password = ''.join(reversed(password))
#     h_obj = BLAKE2b.new(digest_bits=256)
#
#     a, b = half_n_half(salt)
#     h_obj.update(a + password.encode('utf-8') + b)
#     return h_obj.digest()


ENCRYPTION_NONCE_LEN = 8
MAC_LEN = 16
HEADER_CHECKSUM_LEN = 4
VERSION_LEN = 1
SRC_MTIME_LEN = 8
SRC_SIZE_LEN = 3


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
    def __init__(self, name: str, name_salt: bytes, nonce: Optional[bytes]):
        self.name = name
        self.name_salt = name_salt
        self.key = password_to_key(name, salt=name_salt, size=32)
        if nonce is not None:
            self.cipher = ChaCha20.new(key=self.key, nonce=nonce)
        else:
            self.cipher = ChaCha20.new(key=self.key)

    @property
    def nonce(self):
        return self.cipher.nonce

    def __str__(self):
        return '\n'.join([
            f'name: {self.name}',
            f'name salt: {bytes_to_str(self.name_salt)}',
            f'key: {bytes_to_str(self.key)}',
            f'nonce: {bytes_to_str(self.nonce)}',
        ])


def randomized_size(real_size: int) -> int:
    return real_size + random.randint(0, round(real_size / 2))


# def two_random_bytes_sum_0xFF() -> bytes:
#     a = random.randint(0, 0xFF)
#     b = 0xFF - a
#     assert a + b == 0xFF


def _encrypt_file_to_file(source_file: Path, name: str, target_file: Path):
    """
    File format
    -----------

    <imprint/>
    <encrypted>
        intro padding: bytes (1-16 bytes)
        <header>
            format version: byte
            timestamp: double
            body size: uint24
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

    header_imprint = Imprint(name)

    stat = source_file.stat()

    version_bytes = bytes([1])

    src_mtime_bytes = double_to_bytes(stat.st_mtime)
    assert len(src_mtime_bytes) == SRC_MTIME_LEN

    src_size_bytes = stat.st_size.to_bytes(SRC_SIZE_LEN,
                                           byteorder='big',
                                           signed=False)
    assert len(src_size_bytes) == SRC_SIZE_LEN

    header_bytes = b''.join((
        version_bytes,
        src_mtime_bytes,
        src_size_bytes,
    ))

    header_crc_bytes = uint32_to_bytes(zlib.crc32(header_bytes))

    body_bytes = source_file.read_bytes()
    body_crc_bytes = uint32_to_bytes(zlib.crc32(body_bytes))

    decrypted_bytes = (IntroPadding.gen_bytes() +
                       header_bytes + header_crc_bytes +
                       body_bytes + body_crc_bytes)

    cryptographer = Cryptographer(name=name,
                                  name_salt=header_imprint.salt,
                                  nonce=None)

    if _DEBUG_PRINT:
        print("---")
    print("ENCRYPTION:")
    print(cryptographer)
    print("---")

    encrypted_bytes = cryptographer.cipher.encrypt(decrypted_bytes)

    # mac = get_fast_random_bytes(MAC_LEN)
    if _DEBUG_PRINT:
        print(f"ENC: Original {bytes_to_str(decrypted_bytes)}")
    print(f"ENC: Encrypted {bytes_to_str(encrypted_bytes)}")

    with WritingToTempFile(target_file) as wtf:
        # must be the same as writing a fake file
        with wtf.dirty.open('wb') as outfile:
            # writing the imprint. It is not encrypted, but it's a hash +
            # random nonce. It's indistinguishable from any random rubbish
            outfile.write(header_imprint.as_bytes)
            assert len(cryptographer.nonce) == ENCRYPTION_NONCE_LEN, \
                f"Unexpected nonce length: {len(cryptographer.nonce)}"

            # writing nonce, header+crc and body+crc
            outfile.write(cryptographer.nonce)
            outfile.write(encrypted_bytes)

            # adding random data to the end of file.
            # This data is not encrypted, it's from urandom (is it ok?)
            current_size = outfile.seek(0, os.SEEK_CUR)
            target_size = randomized_size(current_size)
            padding_size = target_size - current_size
            assert padding_size >= 0
            outfile.write(get_random_bytes(padding_size))
            set_random_last_modified(wtf.dirty)  # todo test it
            wtf.replace()


class DecryptedFile:

    def __init__(self, source_file: Path, name: str, decrypt_body=True):

        with source_file.open('rb') as f:
            imprint_bytes = f.read(Imprint.FULL_LEN)

            if not name_matches_imprint_bytes(name, imprint_bytes):
                raise ChecksumMismatch("The name does not match the imprint.")

            nonce = read_or_fail(f, ENCRYPTION_NONCE_LEN)

            cfg = Cryptographer(
                name=name,
                name_salt=Imprint.bytes_to_nonce(imprint_bytes),
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

            ip_first = read_and_decrypt(1)[0]
            ip_len = IntroPadding.first_byte_to_len(ip_first)
            if ip_len > 0:
                read_and_decrypt(ip_len)

            # version
            version_bytes = read_and_decrypt(VERSION_LEN)
            version = version_bytes[0]
            assert version == 1

            # mtime
            mtime_bytes = read_and_decrypt(SRC_MTIME_LEN)
            self.mtime = bytes_to_double(mtime_bytes)

            # size
            body_size_bytes = read_and_decrypt(SRC_SIZE_LEN)
            body_size = int.from_bytes(body_size_bytes,
                                       byteorder='big',
                                       signed=False)

            header_crc = int.from_bytes(
                read_and_decrypt(HEADER_CHECKSUM_LEN),
                byteorder='big',
                signed=False)

            header_bytes = version_bytes + mtime_bytes + body_size_bytes
            if zlib.crc32(header_bytes) != header_crc:
                raise ChecksumMismatch("Header CRC mismatch.")

            # body
            self.body: Optional[bytes]
            if decrypt_body:
                body = read_and_decrypt(body_size)
                body_crc = bytes_to_uint32(read_and_decrypt(4))
                if zlib.crc32(body) != body_crc:
                    raise ChecksumMismatch("Body CRC mismatch.")
                self.body = body
            else:
                # todo test
                self.body = None

    def write(self, target: Path):
        if self.body is None:
            raise RuntimeError("Body is not set.")
        target.write_bytes(self.body)
        os.utime(str(target), (self.mtime, self.mtime))
        # set_file_last_modified(target, self.mtime)


def name_matches_header(name: str, file: Path) -> bool:
    """Returns True if the header imprint (written into the file) matches
    the `name`."""
    with file.open('rb') as f:
        header_bytes = f.read(Imprint.FULL_LEN)
        if len(header_bytes) < Imprint.FULL_LEN:
            return False
        nonce = Imprint.bytes_to_nonce(header_bytes)
    return Imprint(name, nonce=nonce).as_bytes == header_bytes
