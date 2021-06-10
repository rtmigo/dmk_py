from pathlib import Path
from typing import Optional

from ksf._10_kdf import FilesetPrivateKey
from ksf.fileset import update_fileset, Fileset, DecryptedIo
from ksf.cryptodir._10_salt import find_salt_in_dir, write_salt


class CryptoDir:

    def __init__(self, directory: Path):
        self.directory = directory

        salt = find_salt_in_dir(self.directory)
        if salt is None:
            salt, _ = write_salt(self.directory)
        assert isinstance(salt, bytes)
        self.salt = salt

    def set_from_file(self, name: str, source: Path):
        pk = FilesetPrivateKey(name, self.salt)
        update_fileset(source, pk, self.directory)

    def get(self, name: str) -> Optional[bytes]:
        pk = FilesetPrivateKey(name, self.salt)
        fs = Fileset(self.directory, pk)
        if fs.real_file is None:
            return None

        with fs.real_file.open('rb') as f:
            return DecryptedIo(pk, f).read_data()
