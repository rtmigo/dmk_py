import os
import shutil
import subprocess
from io import BytesIO

from ksf._config import Config
from ksf.cryptodir import CryptoDir


def _confirm(txt: str):
    ans = input(f"{txt} (y/N) ")
    return ans and ans.upper().startswith('Y')


class ItemNotFoundExit(SystemExit):
    def __init__(self):
        super().__init__("Item not found.")

    pass


class Main:
    def __init__(self):
        self.config = Config()

    def set(self, name: str, value: str):
        # todo test
        crd = CryptoDir(self.config.data_dir)
        with BytesIO(value.encode('utf-8')) as source_io:
            crd.set_from_io(name, source_io)

    def get(self, name: str):
        # todo test
        crd = CryptoDir(self.config.data_dir)
        decrypted_bytes = crd.get(name)
        if decrypted_bytes is None:
            raise ItemNotFoundExit
        return decrypted_bytes.decode('utf-8')

    def eval(self, name: str):
        # todo test
        crd = CryptoDir(self.config.data_dir)
        decrypted_bytes = crd.get(name)
        if decrypted_bytes is None:
            raise ItemNotFoundExit
        cmd = decrypted_bytes.decode('utf-8')

        exit(os.system(cmd))

    # # def set(self, passwords: List[str], value: str):
    # def set(self, other_passwords: Collection[str], curr_password: str, value: str):
    #
    #     # curr_password = passwords[-1]
    #     other_passwords = set(other_passwords)
    #     # other_passwords.remove(curr_password)
    #     # assert list(other_passwords) + [curr_password] == list(passwords)
    #
    #     if self.config.data_file.exists():
    #         # todo test file loading
    #         enc = Encrypted.load(self.config.data_file)
    #         dec = enc.decrypt(other_passwords)
    #     else:
    #         if other_passwords:
    #             # todo test no file when passwords passed
    #             raise DataFileNotFoundExit
    #         # todo test file creation
    #         dec = Decrypted()
    #         dec.pad(96)
    #
    #     # if not _confirm(f"Remove all items except {len(other_passwords) + 1} "
    #     #                 f"with provided passwords?"):
    #     #     print("Canceled")
    #     #     exit(1)
    #
    #     dec[curr_password] = value
    #
    #     dec.encrypt().save(self.config.data_file)
    #     print("Saved")
    #
    # def nonexistent_password(self, passwords: Iterable[str]) -> Optional[str]:
    #     enc = Encrypted.load(self.config.data_file)
    #     for p in passwords:
    #         if enc.get(p) is None:
    #             return p
    #     return None
    #
    # def get(self, password: str):
    #     # todo test
    #     enc = Encrypted.load(self.config.data_file)
    #     txt = enc.get(password)
    #     if txt is None:
    #         raise PasswordNotFoundExit
    #     print(txt)
    #
    #
    def clear(self):
        shutil.rmtree(str(self.config.data_dir))
        self.config.data_dir.mkdir()

    def edit_config(self):
        subprocess.run(['nano', str(self.config.config_file)])
