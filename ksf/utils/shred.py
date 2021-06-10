from pathlib import Path

from ksf.utils.randoms import get_noncrypt_random_bytes


def shred(file: Path, cycles=2):
    size = file.stat().st_size
    for _ in range(cycles):
        data = get_noncrypt_random_bytes(size)
        with file.open('wb') as f:
            f.write(data)
    file.unlink()
