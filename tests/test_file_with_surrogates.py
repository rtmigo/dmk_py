# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
import random
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Set

from ksf.cryptodir._10_kdf import FasterKDF, FilesetPrivateKey
from ksf.cryptodir.fileset._10_fakes import create_fake
from ksf.cryptodir.fileset._25_encrypt_part import is_file_from_namegroup, \
    is_fake, is_content
from ksf.cryptodir.fileset._26_encrypt_full import encrypt_to_files
from ksf.cryptodir.fileset._30_navigator import NewNameGroup, update_namegroup
from ksf.utils.randoms import get_noncrypt_random_bytes
from tests.common import testing_salt


def name_group_to_content_files(ng: NewNameGroup) -> List[Path]:
    return [gf.path for gf in ng.files if gf.is_fresh_data]


def unique_strings(items: List) -> Set[str]:
    return set(str(x) for x in items)


class TestFileWithFakes(unittest.TestCase):
    faster: FasterKDF

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKDF()
        cls.faster.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faster.end()

    def test_create_fakes(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            N = 10
            pk = FilesetPrivateKey('abc', testing_salt)
            for _ in range(N):
                fake_file = create_fake(pk, 2000, td)
                # self.assertTrue(is_file_from_group(pk, fake_file))

            # check we really created 10 files with unique names
            files = list(td.glob('*'))
            self.assertEqual(len(files), N)

            # check each encoded name matches source name
            for f in files:
                self.assertTrue(is_file_from_namegroup(pk, f))
                self.assertEqual(f.stat().st_size, 2000)

            # # check sizes are mostly different
            # sizes = set(f.stat().st_size for f in files)
            # self.assertGreater(len(sizes), 5)

            lm_days = [datetime.date.fromtimestamp(f.stat().st_mtime)
                       for f in files]
            # last-modified days are different
            self.assertGreater(len(set(lm_days)), 5)
            # oldest file is older than month
            self.assertLess(min(lm_days),
                            datetime.date.today() - datetime.timedelta(days=30))

            # newest file is newer than 8 years
            self.assertGreater(max(lm_days),
                               datetime.date.today() - datetime.timedelta(
                                   days=365.2425 * 8))

    def test_searching_in_empty_dir(self):
        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            pk = FilesetPrivateKey("abc", testing_salt)

            with NewNameGroup(temp_dir, pk) as ng:
                self.assertEqual(ng.all_content_versions, set())
                self.assertEqual(len(ng.files), 0)
                self.assertEqual(len(ng.fresh_content_files), 0)
                #found_1 = name_group_to_content_files(ng)


    def test_finding_content_files(self):
        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)

            SECRET_NAME = "abc"
            pk = FilesetPrivateKey(SECRET_NAME, testing_salt)

            # creating some fake files that will be ignored
            for _ in range(9):
                create_fake(pk, 2000, temp_dir)

            # WRITING AND FINDING VERSION 1

            with BytesIO(get_noncrypt_random_bytes(1024 * 128)) as inp:
                content_files_1 = encrypt_to_files(pk, inp, temp_dir, 1)
            self.assertGreater(len(content_files_1), 0)

            with NewNameGroup(temp_dir, pk) as ng:
                self.assertEqual(ng.all_content_versions, {1})
                found_1 = name_group_to_content_files(ng)

            self.assertEqual(unique_strings(found_1),
                             unique_strings(content_files_1))

            # WRITING AND FINDING VERSION 2

            with BytesIO(get_noncrypt_random_bytes(1024 * 128)) as inp:
                content_files_2 = encrypt_to_files(pk, inp, temp_dir, 2)
            self.assertGreaterEqual(len(content_files_2), 2)

            with NewNameGroup(temp_dir, pk) as ng:
                self.assertEqual(ng.all_content_versions, {1, 2})
                found_2 = name_group_to_content_files(ng)

            self.assertNotEqual(unique_strings(content_files_1),
                                unique_strings(content_files_2))
            self.assertEqual(unique_strings(found_2),
                             unique_strings(content_files_2))

            # REMOVING RANDOM VERSION 2 PART

            assert len(content_files_2) >= 2
            random.choice(content_files_2).unlink()

            with NewNameGroup(temp_dir, pk) as ng:
                self.assertEqual(ng.all_content_versions, {1, 2})
                found_3 = name_group_to_content_files(ng)

            # with incomplete set of files for v2, we are getting v1 again

            self.assertEqual(unique_strings(found_3),
                             unique_strings(content_files_1))

            #            content_files_2[0].unlink()

            # WITH WRONG KEY NOTHING FOUND

            wrong_key = FilesetPrivateKey("incorrect", testing_salt)
            with NewNameGroup(temp_dir, wrong_key) as ng:
                found_wrong = name_group_to_content_files(ng)
            self.assertEqual(len(found_wrong), 0)

    def test_update_adds_fakes_and_content(self):
        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            pk = FilesetPrivateKey("abc", testing_salt)

            self.assertFalse(any(is_content(pk, f) for f in temp_dir.glob('*')))
            self.assertFalse(any(is_fake(pk, f) for f in temp_dir.glob('*')))

            with BytesIO(b'abc') as inp:
                update_namegroup(inp, pk, temp_dir)

            self.assertTrue(any(is_content(pk, f) for f in temp_dir.glob('*')))
            self.assertTrue(any(is_fake(pk, f) for f in temp_dir.glob('*')))

    # todo test fake mtimes
    # todo test fake sizes
    # todo test content mtimes
    # todo test content sizes

    # def test_write_with_surrogates_sizes(self):
    #     # random.seed(9, version=2)
    #
    #     unique_sizes = set()
    #     with TemporaryDirectory() as tds:
    #         td = Path(tds)
    #         fpk_a = FilesetPrivateKey("some name", testing_salt)
    #         for _ in range(8):
    #             source_file_a = td / "a"
    #             source_file_a.write_bytes(b'abcdef')
    #             with source_file_a.open('rb') as input_io:
    #                 update_namegroup(input_io, fpk_a, td)
    #             unique_sizes.update(f.stat().st_size for f in td.glob('*'))
    #
    #     self.assertGreater(len(unique_sizes), 5)
    #     # self.assertTrue(all(x >= MIN_DATA_FILE_SIZE for x in unique_sizes))
    #
    # def test_write_with_surrogates(self):
    #     with TemporaryDirectory() as tds:
    #         td = Path(tds)
    #
    #         fpk_a = FilesetPrivateKey("some name", testing_salt)
    #         fpk_b = FilesetPrivateKey("other name", testing_salt)
    #         fas = NameGroup(td, fpk_a)
    #         self.assertEqual(len(fas.all_files), 0)
    #
    #         for _ in range(32):
    #             the_data_a = get_noncrypt_random_bytes(1024*128)
    #             source_file_a = td / "a"
    #             source_file_a.write_bytes(the_data_a)
    #
    #             the_data_b = get_noncrypt_random_bytes(1024*128)
    #             source_file_b = td / "b"
    #             source_file_b.write_bytes(the_data_b)
    #
    #             # rewriting two filesets at once
    #             with source_file_a.open('rb') as source_io_a:
    #                 update_namegroup(source_io_a, fpk_a, td)
    #             with source_file_b.open('rb') as source_io_b:
    #                 update_namegroup(source_io_b, fpk_b, td)
    #
    #             # finding the latest file and checking it has the new contents
    #             fas = NameGroup(td, fpk_b)
    #             self.assertGreaterEqual(len(fas.all_files), 2)
    #             self.assertEqual(_DecryptedFile(fas.real_file, fpk_b).data,
    #                              the_data_b)
    #
    #             # todo reall all parts
    #
    #             # finding the latest file and checking it has the new contents
    #             fas = NameGroup(td, fpk_a)
    #             self.assertGreaterEqual(len(fas.all_files), 2)
    #             self.assertEqual(_DecryptedFile(fas.real_file, fpk_a).data,
    #                              the_data_a)


if __name__ == "__main__":
    unittest.main()
