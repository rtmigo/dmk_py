from typing import BinaryIO


def read_or_fail(f: BinaryIO, n: int) -> bytes:
    result = f.read(n)
    if len(result) != n:
        raise InsufficientData
    return result


class InsufficientData(Exception):
    pass