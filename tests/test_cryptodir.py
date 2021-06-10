import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._80_dir import CryptoDir


class TestCyrptoDir(unittest.TestCase):
    def test(self):
        CONTENT = 'Text file content'
        NAME = "ident"
        with TemporaryDirectory() as tds:
            temp_dir = Path(tds)
            src = temp_dir / "source.txt"
            src.write_text('Text file content', encoding="utf-8")

            crypto_dir = CryptoDir(temp_dir)
            self.assertEqual(crypto_dir.get(NAME), None)
            crypto_dir.set_from_file(NAME, src)
            self.assertEqual(crypto_dir.get(NAME).data.decode("utf-8"),
                             CONTENT)

            # creating a new CryptoDir instance. This time the salt will
            # not be randomly generated, but read from file
            crypto_dir_b = CryptoDir(temp_dir)
            self.assertEqual(crypto_dir.salt, crypto_dir_b.salt)
            self.assertEqual(crypto_dir_b.get(NAME).data.decode("utf-8"),
                             CONTENT)
