import io
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Optional

from Crypto.Random import get_random_bytes

from codn._common import PK_SALT_SIZE
from codn.container import StorageFileReader, StorageFileWriter, \
    BlobsIndexedReader
from codn.cryptodir._10_kdf import CodenameKey
from codn.cryptodir.namegroup import decrypt_from_dios
from codn.cryptodir.namegroup.blob_navigator import NameGroup
from codn.cryptodir.namegroup.blob_updater import update_namegroup_b
from codn.utils.dirty_file import WritingToTempFile


class TheFile:
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
                self._salt = get_random_bytes(PK_SALT_SIZE)
        assert self._salt is not None
        return self._salt

    def _old_blobs(self) -> BlobsIndexedReader:
        try:
            storage_reader = StorageFileReader(self.path.open('rb'))
            assert not storage_reader.blobs.close_stream
            storage_reader.blobs.close_stream = True
            return storage_reader.blobs
        except FileNotFoundError:
            return BlobsIndexedReader(None)

    @property
    def blobs_len(self) -> int:
        try:
            with self.path.open('rb') as f:
                return len(StorageFileReader(f).blobs)
        except FileNotFoundError:
            return 0

    def set_from_io(self, codename: str, source: BinaryIO):
        ck = CodenameKey(codename, self.salt)
        with WritingToTempFile(self.path) as wtf:
            with self._old_blobs() as old_blobs:
                with wtf.dirty.open('wb') as new_file_io:
                    writer = StorageFileWriter(new_file_io, self.salt)
                    update_namegroup_b(ck, source, old_blobs, writer.blobs)
            # both files are closed now
            wtf.replace()  # todo securely remove old file

    def get(self, name: str) -> Optional[bytes]:
        ck = CodenameKey(name, self.salt)
        with self._old_blobs() as old_blobs:
            ng = NameGroup(old_blobs, ck)

            if not ng.fresh_content_files:
                #print(f"No fresh content case blobs: {len(old_blobs)}")
                return None

            with BytesIO() as decrypted:
                decrypt_from_dios(ng.fresh_content_files, decrypted)
                decrypted.seek(0, io.SEEK_SET)
                return decrypted.read()
