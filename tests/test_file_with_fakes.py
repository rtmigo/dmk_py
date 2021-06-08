import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


class TestFileWithFakes(unittest.TestCase):
    def test(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

