# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import os
import random
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict

from click.testing import CliRunner

from dmk import dmk_cli
from dmk._cli import VAULT_FILE_ENVNAME
from tests.common import gen_random_string


# noinspection PyTypeChecker
class Test(unittest.TestCase):

    def setUp(self) -> None:
        self._temp_dir_obj = TemporaryDirectory()
        self.temp_dir = Path(self._temp_dir_obj.name)
        self.dmk_file = os.path.join(self._temp_dir_obj.name,
                                     "test_vault.dmk")

        try:
            os.environ[VAULT_FILE_ENVNAME] = self.dmk_file
        except KeyError:
            pass

    def tearDown(self) -> None:
        self._temp_dir_obj.cleanup()

    def assertTestVault(self):
        runner = CliRunner()
        result = runner.invoke(
            dmk_cli,
            ['vault'])
        self.assertIn("test_vault.dmk", result.output)

    def test_set_get_string(self):

        self.assertTestVault()

        self.assertFalse(os.path.exists(self.dmk_file))
        runner = CliRunner()
        result = runner.invoke(
            dmk_cli,
            ['set', '-e', 'abc', '-t', 'The Value'])

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(os.path.exists(self.dmk_file))
        self.assertEqual(result.output, '')
        result = runner.invoke(
            dmk_cli,
            ['get', '-e', 'abc'])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output, 'The Value\n')

    def test_set_get_multiple_random_strings(self):

        self.assertTestVault()

        # with TemporaryDirectory() as tempdir:
        #    storage = os.path.join(tempdir, "storage.dat")
        self.assertFalse(os.path.exists(self.dmk_file))

        reference: Dict[str, str] = dict()

        # writing and overwriting
        for _ in range(15):
            name = random.choice(('one', 'two', 'three', 'four', 'five'))

            val = gen_random_string()

            reference[name] = val

            with self.subTest(f"set {repr(name)} {repr(val)}"):
                runner = CliRunner()
                result = runner.invoke(
                    dmk_cli,
                    ['set', '-e', name, '-t', val],
                    catch_exceptions=False)
                # print(result.stdout)
                self.assertEqual(result.exit_code, 0)

        self.assertTrue(os.path.exists(self.dmk_file))

        # reading
        for name, val in reference.items():
            # self.assertEqual(result.output, '')
            result = runner.invoke(
                dmk_cli,
                ['get', '-e', name])
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.output, val + '\n')

    def test_set_get_file_2(self):

        self.assertTestVault()

        src_file = self.temp_dir / "src.txt"
        src_file.write_text('sample', encoding='utf-8')

        self.assertFalse(os.path.exists(self.dmk_file))
        runner = CliRunner()
        result = runner.invoke(
            dmk_cli,
            ['set', '-e', 'abc', str(src_file)],
            catch_exceptions=False)

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output, '')
        self.assertTrue(os.path.exists(self.dmk_file))

        dst_file = self.temp_dir / "dst.txt"
        self.assertFalse(dst_file.exists())

        result = runner.invoke(
            dmk_cli,
            ['get', '-e', 'abc', str(dst_file)])
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(dst_file.exists())
        self.assertEqual(
            dst_file.read_text(encoding='utf-8'),
            'sample')


if __name__ == "__main__":
    unittest.main()
