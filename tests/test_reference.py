import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

# def generate_reference_file(name: str, body: bytes, target_dir: Path):
#     with TemporaryDirectory() as tds:
#         td = Path(tds)
#         source_file = td / "source"
#         source_file.write_bytes(body)
#
#
#
#         pk = FilesetPrivateKey(name)
#         update_fileset(source_file, pk, target_dir)
from ksf._80_dir import Dir

ref_content = [
    ('one', bytes([11, 22, 33])),
    ('empty', bytes([])),
    ('five', bytes([5, 4, 3, 2, 1]))
]

refs_dir = Path(__file__).parent / "data_refs"


def generate_references():
    if not input(f"Really replace {refs_dir}? (y/n) ").lower().startswith('y'):
        print("Canceled")
        return
    if refs_dir.exists():
        assert "_refs" in refs_dir.name
        shutil.rmtree(str(refs_dir))

    refs_dir.mkdir(parents=True)

    d = Dir(refs_dir)

    for name, data in ref_content:
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            source_file.write_bytes(data)
            d.set_from_file(name, source_file)


class TestRefs(unittest.TestCase):
    def test(self):
        d = Dir(refs_dir)
        for name, data in ref_content:
            self.assertEqual(d.get(name).data, data)


if __name__ == "__main__":
    unittest.main()
    # generate_references()