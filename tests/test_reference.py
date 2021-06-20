# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import time
import unittest
from io import BytesIO
from pathlib import Path

from dmk._vault_file import DmkFile
from dmk.a_base import CodenameKey

ref_content = [
    ('one', bytes([11, 22, 33])),
    ('empty', bytes([])),
    ('192k large', bytes([1, 2, 3] * (1024 * 64)))
]

refs_file = Path(__file__).parent / "data" / "ref_vault.dmk"


def generate_references():
    assert CodenameKey.is_standard_params()

    if not input(f"Really replace {refs_file} (y/N)? ").lower().startswith('y'):
        print("Canceled")
        return
    if refs_file.exists():
        assert "ref_" in refs_file.name
        refs_file.unlink()

    d = DmkFile(refs_file)

    for name, data in ref_content:
        t = time.monotonic()
        with BytesIO(data) as input_io:
            d.set_from_io(name, input_io)
        print(f"Written in {time.monotonic() - t}")

#@unittest.skip('tmp')
class TestRefs(unittest.TestCase):
    def test(self):
        assert CodenameKey.is_standard_params()
        d = DmkFile(refs_file)
        print("References salt", tuple(d.salt))
        for name, data in ref_content:
            self.assertEqual(d.get_bytes(name), data)


if __name__ == "__main__":
    # unittest.main()
    generate_references()
    TestRefs().test()
    print("OK")
