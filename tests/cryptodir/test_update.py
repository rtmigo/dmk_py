# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Set

from codn.cryptodir._10_kdf import FasterKDF, FilesetPrivateKey
from codn.cryptodir.namegroup.encdec._25_encdec_part import is_fake, is_content
from codn.cryptodir.namegroup.navigator_old import NewNameGroup, update_namegroup
from tests.common import testing_salt, sizes_are_random, dates_are_random


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

    def test_fakes_have_random_sizes_and_dates(self):
        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            pk = FilesetPrivateKey("abc", testing_salt)

            # updating until at least 10 fakes found
            for _ in range(100):
                with BytesIO(b'abc') as inp:
                    update_namegroup(inp, pk, temp_dir)
                fakes = [f for f in temp_dir.glob('*') if is_fake(pk, f)]
                if len(fakes) >= 10:
                    break

            self.assertTrue(dates_are_random(fakes))
            self.assertTrue(sizes_are_random(fakes))

    def test_content_have_random_dates(self):
        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            pk = FilesetPrivateKey("abc", testing_salt)

            # updating until at least 10 content files found
            for _ in range(100):
                with BytesIO(b'abc') as inp:
                    update_namegroup(inp, pk, temp_dir)
                content = [f for f in temp_dir.glob('*') if is_content(pk, f)]
                if len(content) >= 10:
                    break

            self.assertTrue(dates_are_random(content))

    def test_content_have_random_sizes(self):


            pk = FilesetPrivateKey("abc", testing_salt)

            # updating until at least 10 content files found

            all_part_sizes: List[Set[int]] = list()
            all_file_sizes: List[Set[int]] = list()

            for _ in range(3):
                with TemporaryDirectory() as temp_dir_str:
                    temp_dir = Path(temp_dir_str)
                    with BytesIO(b'0'*1024*128) as inp:
                        update_namegroup(inp, pk, temp_dir)
                    with NewNameGroup(temp_dir, pk) as nng:
                        part_sizes = [
                            gf.dio.header.part_size
                            for gf in nng.files
                            if gf.is_fresh_data
                        ]
                        all_part_sizes.append(set(part_sizes))

                        file_sizes = [gf.path.stat().st_size
                                      for gf in nng.files
                                      if gf.is_fresh_data]
                        all_file_sizes.append(set(file_sizes))

            # not sure about random, but at least different
            self.assertTrue(
                all_file_sizes[0] != all_file_sizes[1] or
                all_file_sizes[0] != all_file_sizes[2])

            # files may be different because of small header padding, so we
            # check part sizes as well
            self.assertTrue(
                all_part_sizes[0] != all_part_sizes[1] or
                all_part_sizes[0] != all_part_sizes[2])

            #self.fail(all_part_sizes)


            # actually this is not a great test: the sizes may be different
            # because of small padding added before the header

            # but the part sizes are random, we


if __name__ == "__main__":
    unittest.main()
