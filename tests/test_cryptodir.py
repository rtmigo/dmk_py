import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._10_kdf import FasterKDF
from ksf.cryptodir._20_cryptodir import CryptoDir
from tests.common import gen_random_content, gen_random_names


class TestCryptoDir(unittest.TestCase):
    faster: FasterKDF

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKDF()
        cls.faster.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faster.end()

    def test(self):

        for _ in range(25):

            names_and_datas = [
                (name, gen_random_content())
                for name in gen_random_names(10)
            ]

            with TemporaryDirectory() as tds:
                temp_dir = Path(tds)

                # writing
                for name, data in names_and_datas:
                    src = temp_dir / "source.txt"
                    src.write_bytes(data)

                    crypto_dir = CryptoDir(temp_dir)
                    self.assertEqual(crypto_dir.get(name), None)
                    crypto_dir.set_from_file(name, src)

                # reading with same instance
                for name, data in names_and_datas:
                    self.assertEqual(crypto_dir.get(name), data)

                # creating a new CryptoDir instance. This time the salt will
                # not be randomly generated, but read from file
                crypto_dir_b = CryptoDir(temp_dir)
                self.assertEqual(crypto_dir.salt, crypto_dir_b.salt)

                # reading with other instance
                for name, data in names_and_datas:
                    self.assertEqual(crypto_dir_b.get(name), data)
