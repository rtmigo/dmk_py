import shutil
import time
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from codn.cryptodir._10_kdf import CodenameKey
from codn.cryptodir._20_cryptodir import CryptoDir

ref_content = [
    ('one', bytes([11, 22, 33])),
    ('empty', bytes([])),
    ('192k large', bytes([1, 2, 3]*(1024*64)))
]

refs_dir = Path(__file__).parent / "data_refs"


def generate_references():
    assert CodenameKey._power >= 17

    if not input(f"Really replace {refs_dir} (y/N)? ").lower().startswith('y'):
        print("Canceled")
        return
    if refs_dir.exists():
        assert "_refs" in refs_dir.name
        shutil.rmtree(str(refs_dir))

    refs_dir.mkdir(parents=True)

    d = CryptoDir(refs_dir)


    for name, data in ref_content:
        with TemporaryDirectory() as tds:
            #td = Path(tds)
            #source_file = td / "source"
            #source_file.write_bytes(data)
            t = time.monotonic()
            with BytesIO(data) as input_io:
                d.set_from_io(name, input_io)
            print(f"Written in {time.monotonic() - t}")


#@unittest.skip('temp')
class TestRefs(unittest.TestCase):
    def test(self):
        d = CryptoDir(refs_dir)
        print("References salt", tuple(d.salt))
        for name, data in ref_content:
            self.assertEqual(d.get(name), data)


if __name__ == "__main__":
    #unittest.main()
    generate_references()
    print("Testing")
    TestRefs().test()
    print("OK")
