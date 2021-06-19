# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import random
import unittest
from io import BytesIO

from dmk._common import MAX_CLUSTER_CONTENT_SIZE, CLUSTER_SIZE, \
    CODENAME_LENGTH_BYTES
from dmk.a_base._05_codename import CodenameAscii
from dmk.a_base._10_kdf import FasterKDF, CodenameKey
from dmk.a_utils.randoms import get_noncrypt_random_bytes
from dmk.b_cryptoblobs._20_encdec_part import Encrypt, \
    DecryptedIO, is_content_io, is_fake_io
from tests.common import testing_salt


# @unittest.skip("tmp")
class TestEncryptDecrypt(unittest.TestCase):
    faster: FasterKDF

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKDF()
        cls.faster.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faster.end()

    def test_codename_to_bytes(self):
        result = CodenameAscii.to_padded_ascii('abc')
        self.assertTrue(result.endswith(b'abc'))
        self.assertEqual(len(result), CODENAME_LENGTH_BYTES)

        NAME = 'abc'
        self.assertNotEqual(
            CodenameAscii.to_padded_ascii(NAME),
            CodenameAscii.to_padded_ascii(NAME))

        for _ in range(200):
            self.assertEqual(CodenameAscii.padded_to_str(
                CodenameAscii.to_padded_ascii(NAME)), NAME)

        with self.assertRaises(ValueError):
            CodenameAscii.to_padded_ascii('Привет!')

        with self.assertRaises(ValueError):
            CodenameAscii.to_padded_ascii('x\0yz')

    def test_codename_max_length(self):

        long = 'N' * CODENAME_LENGTH_BYTES
        self.assertEqual(
            CodenameAscii.padded_to_str(CodenameAscii.to_padded_ascii(long)),
            long)

        almost = long[:-1]
        assert len(almost) == CODENAME_LENGTH_BYTES - 1
        self.assertEqual(
            CodenameAscii.padded_to_str(CodenameAscii.to_padded_ascii(almost)),
            almost)

        longer = long + 'N'
        assert len(longer) == CODENAME_LENGTH_BYTES + 1
        with self.assertRaises(ValueError):
            CodenameAscii.to_padded_ascii(longer)

    def test_imprint_match(self):
        data = bytes([77, 88, 99])
        NAME = 'abc'

        encrypted_io = BytesIO()

        Encrypt(CodenameKey(NAME, testing_salt)) \
            .io_to_io(BytesIO(data), encrypted_io)

        with self.subTest("with right key: is a content"):
            encrypted_io.seek(0, io.SEEK_SET)
            self.assertTrue(
                is_content_io(CodenameKey(NAME, testing_salt),
                              encrypted_io))

        with self.subTest("with right key: not a fake (has content)"):
            encrypted_io.seek(0, io.SEEK_SET)
            self.assertTrue(
                not is_fake_io(CodenameKey(NAME, testing_salt),
                               encrypted_io))

        with self.subTest("with wrong key: not a content"):
            encrypted_io.seek(0, io.SEEK_SET)
            self.assertFalse(
                is_content_io(CodenameKey("lalala", testing_salt),
                              encrypted_io))

        with self.subTest("with wrong key: not a fake (not from namegroup)"):
            encrypted_io.seek(0, io.SEEK_SET)
            self.assertTrue(
                not is_fake_io(CodenameKey("lalala", testing_salt),
                               encrypted_io))

    def test_encdec_constant(self):
        self._encrypt_decrypt('name', b'qwertyuiop!qwertyuiop')

    def test_encdec_empty_data(self):
        self._encrypt_decrypt('empty', b'')

    #
    def test_encdec_part(self):
        dec = self._encrypt_decrypt('name', b'0123abc000',
                                    pos=4,
                                    parts_len=5,
                                    part_size=3,
                                    part_idx=2)
        self.assertEqual(dec, b'abc')

    #
    def test_encdec_part_sized_0(self):
        dec = self._encrypt_decrypt('name', b'0123abc000',
                                    pos=4,
                                    parts_len=5,
                                    part_size=0,
                                    part_idx=2)
        self.assertEqual(dec, b'')

    #
    def test_encdec_part_sized_max(self):
        buf = b'0' * (MAX_CLUSTER_CONTENT_SIZE * 2)
        for _ in range(25):
            # catching random overflows
            self._encrypt_decrypt('name', buf,
                                  pos=0,
                                  parts_len=5,
                                  part_size=MAX_CLUSTER_CONTENT_SIZE,
                                  part_idx=2)

    #
    # @unittest.skip('temp')
    def test_encdec_part_random(self):
        for _ in range(1000):
            name_len = random.randint(0, 10)
            name = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz')
                           for _ in range(name_len))
            assert len(name) == name_len

            full_original_len = random.randint(0, MAX_CLUSTER_CONTENT_SIZE)
            full_original = get_noncrypt_random_bytes(full_original_len)

            if full_original_len > 0:
                part_pos = random.randint(0, full_original_len - 1)
            else:
                part_pos = 0
            part_max_size = full_original_len - part_pos
            part_size = random.randint(0, part_max_size)
            assert part_pos + part_size <= full_original_len

            parts_len = random.randint(1, 10)
            part_idx = random.randint(0, parts_len - 1)

            self._encrypt_decrypt(name,
                                  full_original,
                                  pos=part_pos,
                                  parts_len=parts_len,
                                  part_size=part_size,
                                  part_idx=part_idx)

    #
    def test_nonce_is_different_each_time(self):
        fpk = CodenameKey('abc', testing_salt)

        nonces = set()

        with BytesIO(b'datadatadata') as original_io:
            for _ in range(3):
                original_io.seek(0, io.SEEK_SET)

                with BytesIO() as encrypted_io:
                    Encrypt(fpk).io_to_io(original_io, encrypted_io)
                    encrypted_io.seek(0, io.SEEK_SET)

                    df = DecryptedIO(fpk, encrypted_io)
                    nonces.add(df.nonce)

        self.assertGreaterEqual(len(nonces), 2)

    def _encrypt_decrypt(self,
                         name: str,
                         body: bytes,

                         pos=0,

                         parts_len=1,
                         part_idx=0,
                         part_size=None,

                         check_wrong=True):

        # print(f"ENCDEC: parts_len={parts_len}")
        # print(f"ENCDEC: part_idx={part_idx}")
        # print(f"ENCDEC: part_size={part_size}")

        if part_size is not None:
            expected_part_content = body[pos:pos + part_size]
        else:
            expected_part_content = body

        fpk = CodenameKey(name, testing_salt)

        with BytesIO(body) as original_io:
            original_io.seek(pos)
            with BytesIO() as encrypted_io:
                Encrypt(fpk,
                        parts_len=parts_len,
                        part_idx=part_idx,
                        part_size=part_size) \
                    .io_to_io(original_io, encrypted_io)
                encrypted_io.seek(0)
                encrypted = encrypted_io.read()
                self.assertEqual(len(encrypted), CLUSTER_SIZE)

        # checking that the original content can be found in original file,
        # but not in the encrypted file
        self.assertIn(expected_part_content, body)
        if len(expected_part_content) > 6:
            self.assertNotIn(expected_part_content, encrypted)

        # checking the we cannot decrypt the data with wrong key
        if check_wrong:
            wrong_key = CodenameKey('WrOnG', testing_salt)
            with BytesIO(encrypted) as input_io:
                dio = DecryptedIO(wrong_key, input_io)
                self.assertFalse(dio.contains_data)
                with self.assertRaises(Exception):
                    dio.read_data()

        # we did not accidentally save the private key to the encrypted data
        self.assertNotIn(fpk.as_bytes, encrypted)

        with BytesIO(encrypted) as input_io:
            df = DecryptedIO(fpk, input_io)
            # self.assertEqual(df.header.data_size, len(body))
            self.assertEqual(df.header.part_idx, part_idx)
            # self.assertEqual(df.header.parts_len, parts_len)
            if part_size is not None:
                self.assertEqual(df.header.part_size, part_size)
            else:
                self.assertEqual(df.header.part_size, len(body))

            decrypted_part_content = df.read_data()
            self.assertEqual(decrypted_part_content, expected_part_content)

        self.assertLessEqual(len(decrypted_part_content),
                             MAX_CLUSTER_CONTENT_SIZE)

        return decrypted_part_content


if __name__ == "__main__":
    unittest.main()
    # TestEncryptDecrypt()._encrypt_decrypt('abcdef', b'qwertyuiop',
    #                                     check_wrong=False)
    # print("OK")
