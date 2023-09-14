import unittest
from statistics import mean

from dmk.c_namegroups.content_ver import initial_version, \
    increased_data_version, MAX_CONTENT_VERSION, MAX_CONTENT_VERSION_DELTA


class TestContentVer(unittest.TestCase):
    def test_avg(self):

        versions = [initial_version() for _ in range(1000)]
        avg = mean(versions)

        m = 2 ** 32
        d = 2 ** 27
        self.assertGreater(avg, m - d)
        self.assertLess(avg, m + d)

    def test_increasing(self):
        versions = []
        for _ in range(100):
            versions.append(increased_data_version(versions))

        self.assertEqual(versions, sorted(versions))

    def test_can_be_increased_many_years(self):
        # Since the number is 48-bit, we still have a lot of room to increase
        # this number. If we increase the version every second, and every time
        # by a thousand, this can continue for about 10 thousand years.
        #
        # Since there is not upper limit, let's we have at least 100 years

        for _ in range(100):
            v = initial_version()
            SECONDS_PER_YEAR = 31556952
            assert MAX_CONTENT_VERSION - v > \
                   (SECONDS_PER_YEAR * 100) * MAX_CONTENT_VERSION_DELTA
