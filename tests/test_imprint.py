import datetime
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._10_imprint import bytes_to_str, str_to_bytes, \
    name_matches_encoded, create_fake, Imprint


class Test(unittest.TestCase):

    def test_bytes_to_str_to_bytes(self):
        b = bytes([11, 33, 22, 55, 44])
        encoded = bytes_to_str(b)
        self.assertEqual(encoded, 'CyEWNyw=')
        self.assertEqual(str_to_bytes(encoded), b)

    def test_encode_match(self):
        name = 'abc.txt'
        encoded = Imprint(name).as_str
        self.assertNotIn(name, encoded)

        self.assertTrue(name_matches_encoded(name, encoded))
        self.assertFalse(name_matches_encoded('other.txt', encoded))
        self.assertFalse(name_matches_encoded('another.txt', encoded))

    def test_imporint_string_not_too_long(self):
        for i in range(1000):
            name = f'abc{i}.txt'
            self.assertLess(len(Imprint(name).as_str), 65)

    def test_encode_each_time_different(self):
        s = set()
        for _ in range(10):
            s.add(Imprint('the_same.file').as_str)
        self.assertEqual(len(s), 10)

    def test_hash_each_time_different(self):
        s = set()
        for _ in range(10):
            s.add(Imprint('the_same.file').as_bytes)
        self.assertEqual(len(s), 10)



    def test_create_fakes(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            N = 10
            for _ in range(N):
                create_fake('abc', 2000, td)

            # check we really created 10 files with unique names
            files = list(td.glob('*'))
            self.assertEqual(len(files), N)

            # check each encoded name matches source name
            for f in files:
                self.assertTrue(name_matches_encoded('abc', f.name))

            # check sizes are mostly different
            sizes = set(f.stat().st_size for f in files)
            self.assertGreater(len(sizes), 5)

            lm_days = [datetime.date.fromtimestamp(f.stat().st_mtime)
                       for f in files]
            # last-modified days are different
            self.assertGreater(len(set(lm_days)), 5)
            # oldest file is older than month
            self.assertLess(min(lm_days),
                            datetime.date.today() - datetime.timedelta(days=30))

            # newest file is newer than 11 months
            self.assertGreater(max(lm_days),
                               datetime.date.today() - datetime.timedelta(
                                   days=30 * 11))



