# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from codn.cryptodir._10_kdf import FasterKDF
from codn.cryptodir._20_cryptodir import CryptoDir
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

    def test_encdec_empty(self):
        with TemporaryDirectory() as tds:
            temp_dir = Path(tds)
            crypto_dir = CryptoDir(temp_dir)
            NAME='empty'
            with BytesIO(b'') as input_io:
                crypto_dir.set_from_io(NAME, input_io)

            crypto_dir_b = CryptoDir(temp_dir)
            self.assertEqual(crypto_dir_b.get(NAME), b'')


    def test_random_write_and_read(self):

        for _ in range(7):
            names_and_datas = [
                (name, gen_random_content(max_size=1024*128))
                for name in gen_random_names(10)
            ]

            with TemporaryDirectory() as tds:
                temp_dir = Path(tds)

                # writing
                for name, data in names_and_datas:
                    crypto_dir = CryptoDir(temp_dir)
                    self.assertEqual(crypto_dir.get(name), None)

                    with BytesIO(data) as input_io:
                        crypto_dir.set_from_io(name, input_io)

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

    def test_cryptodir_does_not_create_directories(self):
        with TemporaryDirectory() as tds:
            temp_dir = Path(tds)
            temp_subdir = temp_dir/"sub"
            with self.assertRaises(FileNotFoundError):
                CryptoDir(temp_subdir)

