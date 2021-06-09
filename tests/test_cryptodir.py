import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._80_dir import CryptoDir


class TestCyrptoDir(unittest.TestCase):
    def test(self):
        CONTENT = 'Text file content'
        NAME = "ident"
        with TemporaryDirectory() as tds:
            temp_dir = Path(tds)
            src = temp_dir / "source.txt"
            src.write_text('Text file content', encoding="utf-8")

            cd = CryptoDir(temp_dir)
            self.assertEqual(cd.get(NAME), None)
            cd.set_from_file(NAME, src)
            self.assertEqual(cd.get(NAME).data.decode("utf-8"), CONTENT)
