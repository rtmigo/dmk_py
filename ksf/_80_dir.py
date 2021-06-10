from pathlib import Path
from typing import Optional

from ksf._20_key_derivation import FilesetPrivateKey
from ksf._61_encryption import _DecryptedFile
from ksf._70_navigator import update_fileset, Fileset


class CryptoDir:
    def __init__(self, directory: Path):
        self.directory = directory

    def set_from_file(self, name: str, source: Path):
        pk = FilesetPrivateKey(name)
        update_fileset(source, pk, self.directory)

    def get(self, name: str, body=True) -> Optional[_DecryptedFile]:
        pk = FilesetPrivateKey(name)
        fs = Fileset(self.directory, pk)
        if fs.real_file is None:
            return None
        return _DecryptedFile(fs.real_file, pk, decrypt_body=body)
