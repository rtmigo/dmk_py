# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Set

from codn.cryptodir._10_kdf import FasterKDF, CodenameKey
from codn.cryptodir.namegroup.fakes import create_fake
from codn.cryptodir.namegroup.encdec._25_encdec_part import is_fake, is_content
from codn.cryptodir.namegroup.encdec._26_encdec_full import encrypt_to_files
from codn.cryptodir.namegroup.navigator_old import NewNameGroup, update_namegroup_old
from codn.utils.randoms import get_noncrypt_random_bytes
from tests.common import testing_salt


def name_group_to_content_files(ng: NewNameGroup) -> List[Path]:
    return [gf.path for gf in ng.files if gf.is_fresh_data]


def unique_strings(items: List) -> Set[str]:
    return set(str(x) for x in items)


class TestNamegroup(unittest.TestCase):
    faster: FasterKDF

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKDF()
        cls.faster.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faster.end()

    def test_namegroup_in_empty_dir(self):
        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            pk = CodenameKey("abc", testing_salt)

            with NewNameGroup(temp_dir, pk) as ng:
                self.assertEqual(ng.all_content_versions, set())
                self.assertEqual(len(ng.files), 0)
                self.assertEqual(len(ng.fresh_content_files), 0)
                # found_1 = name_group_to_content_files(ng)

    def test_namegroup_finds_content(self):
        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)

            SECRET_NAME = "abc"
            pk = CodenameKey(SECRET_NAME, testing_salt)

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

            # WITH WRONG KEY NOTHING FOUND

            wrong_key = CodenameKey("incorrect", testing_salt)
            with NewNameGroup(temp_dir, wrong_key) as ng:
                found_wrong = name_group_to_content_files(ng)
            self.assertEqual(len(found_wrong), 0)

    def test_update_adds_fakes_and_content(self):
        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            pk = CodenameKey("abc", testing_salt)

            self.assertFalse(any(is_content(pk, f) for f in temp_dir.glob('*')))
            self.assertFalse(any(is_fake(pk, f) for f in temp_dir.glob('*')))

            with BytesIO(b'abc') as inp:
                update_namegroup_old(inp, pk, temp_dir)

            self.assertTrue(any(is_content(pk, f) for f in temp_dir.glob('*')))
            self.assertTrue(any(is_fake(pk, f) for f in temp_dir.glob('*')))




if __name__ == "__main__":
    unittest.main()
