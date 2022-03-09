# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


from pathlib import Path

from dmk.a_utils.randoms import get_noncrypt_random_bytes


# todo remove this module?

def shred(file: Path, cycles=2):
    size = file.stat().st_size
    for _ in range(cycles):
        data = get_noncrypt_random_bytes(size)
        with file.open('wb') as f:
            f.write(data)
    file.unlink()
