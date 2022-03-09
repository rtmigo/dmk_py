# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import random
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Iterable

from dmk.a_base._10_kdf import FasterKDF, CodenameKey
from dmk.a_utils.randoms import get_noncrypt_random_bytes
from dmk.b_cryptoblobs._30_encdec_multipart import MultipartEncryptor
from dmk.b_storage_file import BlocksIndexedReader, BlocksSequentialWriter
from dmk.c_namegroups._fakes import create_fake_bytes
from dmk.c_namegroups._namegroup import NameGroup
# from codn.c_namegroups._fakes import create_fake_bytes
from tests.common import testing_salt


def name_group_to_content_blobs(ng: NameGroup) -> List[bytes]:
    result = list()
    for gf in ng.items:
        if gf.is_fresh_data:
            gf.dio._source.seek(0, io.SEEK_SET)
            result.append(gf.dio._source.read())
    return result


def write_blobs_to_stream(blobs: Iterable[bytes], out_io: BytesIO):
    with BlocksSequentialWriter(out_io) as w:
        for b in blobs:
            w.write_bytes(b)


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

            with BytesIO() as empty:
                reader = BlocksIndexedReader(empty)

                ng = NameGroup(reader, pk)
                self.assertEqual(ng.all_content_versions, set())
                self.assertEqual(len(ng.items), 0)
                self.assertEqual(len(ng.fresh_content_dios), 0)
                # found_1 = name_group_to_content_files(ng)

    def test_namegroup_finds_content(self):
        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)

            SECRET_NAME = "abc"
            pk = CodenameKey(SECRET_NAME, testing_salt)

            all_blobs: List[bytes] = []

            # creating some fake files that will be ignored
            for _ in range(9):
                all_blobs.append(create_fake_bytes(pk))

            with self.subTest('Write and find version 1'):
                # encrypt and add to all_blobs

                with BytesIO(get_noncrypt_random_bytes(1024 * 128)) as inp:
                    me = MultipartEncryptor(pk, inp, 1)
                    content_blobs_1 = me.encrypt_all_to_list()
                    all_blobs.extend(content_blobs_1)

                # write all_blobs to the stream in random order

                random.shuffle(all_blobs)
                with BytesIO() as blobs_stream:
                    write_blobs_to_stream(all_blobs, blobs_stream)
                    blobs_stream.seek(0, io.SEEK_SET)

                    # find the content blobs in the stream
                    r = BlocksIndexedReader(blobs_stream)
                    # r.check_all_checksums()
                    ng = NameGroup(r, pk)
                    self.assertEqual(ng.all_content_versions, {1})
                    found_1 = name_group_to_content_blobs(ng)

                    self.assertEqual(len(ng.fresh_content_dios),
                                     len(found_1))

                self.assertEqual(set(found_1),
                                 set(content_blobs_1))

            with self.subTest('Write and find version 2'):
                # encrypt and add to all_blobs
                content_blobs_2 = []
                with BytesIO(get_noncrypt_random_bytes(1024 * 128)) as inp:
                    me = MultipartEncryptor(pk, inp, 2)
                    content_blobs_2 = me.encrypt_all_to_list()
                    all_blobs.extend(content_blobs_2)

                # write all_blobs to the stream in random order
                random.shuffle(all_blobs)
                with BytesIO() as blobs_stream:
                    write_blobs_to_stream(all_blobs, blobs_stream)
                    blobs_stream.seek(0, io.SEEK_SET)

                    # find the content blobs in the stream
                    r = BlocksIndexedReader(blobs_stream)
                    # r.check_all_checksums()
                    ng = NameGroup(r, pk)
                    self.assertEqual(ng.all_content_versions, {1, 2})
                    found_2 = name_group_to_content_blobs(ng)

                self.assertNotEqual(set(found_2),
                                    set(content_blobs_1))

                self.assertEqual(set(found_2),
                                 set(content_blobs_2))

            with self.subTest('Removing random version 2 part'):
                assert len(content_blobs_2) >= 2
                all_blobs.remove(content_blobs_2[0])
                random.shuffle(all_blobs)

                with BytesIO() as blobs_stream:
                    write_blobs_to_stream(all_blobs, blobs_stream)
                    blobs_stream.seek(0, io.SEEK_SET)

                    # find the content blobs in the stream
                    r = BlocksIndexedReader(blobs_stream)
                    # r.check_all_checksums()
                    ng = NameGroup(r, pk)
                    self.assertEqual(ng.all_content_versions, {1, 2})
                    found_3 = name_group_to_content_blobs(ng)

                # with incomplete set of files for v2, we are getting v1 again
                self.assertEqual(set(found_3),
                                 set(content_blobs_1))

            with self.subTest('With wrong key nothing found'):
                wrong_key = CodenameKey("incorrect", testing_salt)
                with BytesIO() as blobs_stream:
                    write_blobs_to_stream(all_blobs, blobs_stream)
                    blobs_stream.seek(0, io.SEEK_SET)

                    # find the content blobs in the stream
                    r = BlocksIndexedReader(blobs_stream)
                    # r.check_all_checksums()
                    ng = NameGroup(r, wrong_key)
                    self.assertEqual(len(ng.all_content_versions), 0)
                    self.assertEqual(len(name_group_to_content_blobs(ng)), 0)


if __name__ == "__main__":
    unittest.main()
