# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Optional

from Crypto.Random import get_random_bytes

from ._common import KEY_SALT_SIZE
from .a_base import CodenameKey
from .a_utils.dirty_file import WritingToTempFile
from .b_cryptoblobs import decrypt_from_dios
from .b_storage_file import StorageFileReader, StorageFileWriter, \
    BlocksIndexedReader
from .c_namegroups import NameGroup, update_namegroup_b
from .c_namegroups._update import add_fakes


class DmkFile:
    def __init__(self, path: Path):
        self.path = path
        self._salt: Optional[bytes] = None

    @property
    def salt(self) -> bytes:
        if self._salt is None:
            try:
                with self.path.open('rb') as f:
                    self._salt = StorageFileReader(f).salt
            except FileNotFoundError:
                self._salt = get_random_bytes(KEY_SALT_SIZE)
        assert self._salt is not None
        return self._salt

    def _old_blobs(self) -> BlocksIndexedReader:
        try:
            storage_reader = StorageFileReader(self.path.open('rb'))
            assert not storage_reader.blobs.close_stream
            storage_reader.blobs.close_stream = True
            return storage_reader.blobs
        except FileNotFoundError:
            reader = BlocksIndexedReader(BytesIO())
            assert len(reader) == 0
            return reader

    @property
    def blobs_len(self) -> int:
        try:
            with self.path.open('rb') as f:
                return len(StorageFileReader(f).blobs)
        except FileNotFoundError:
            return 0

    def add_fakes(self, codename: str, blocks_num: int):
        ck = CodenameKey(codename, self.salt)
        with WritingToTempFile(self.path) as wtf:
            with self._old_blobs() as old_blobs, \
                    wtf.dirty.open('wb') as new_file_io, \
                    StorageFileWriter(new_file_io, self.salt) as writer:
                add_fakes(ck,
                          old_blobs,
                          writer.blobs,
                          blocks_num)
            # both files are closed now
            wtf.replace()  # todo securely remove old file

    def set_from_io(self, codename: str, source: BinaryIO):
        ck = CodenameKey(codename, self.salt)
        with WritingToTempFile(self.path) as wtf:
            with self._old_blobs() as old_blobs, \
                    wtf.dirty.open('wb') as new_file_io, \
                    StorageFileWriter(new_file_io, self.salt) as writer:
                update_namegroup_b(ck, source, old_blobs, writer.blobs)
            # both files are closed now

            wtf.replace()  # todo securely remove old file

    def get_bytes(self, name: str) -> Optional[bytes]:
        ck = CodenameKey(name, self.salt)
        # print("pk", ck.as_bytes)
        with self._old_blobs() as old_blobs:
            ng = NameGroup(old_blobs, ck)

            if not ng.fresh_content_dios:
                # print(f"No fresh content case blobs: {len(old_blobs)}")
                return None

            with BytesIO() as decrypted:
                decrypt_from_dios(ng.fresh_content_dios, decrypted)
                decrypted.seek(0, io.SEEK_SET)
                return decrypted.read()
