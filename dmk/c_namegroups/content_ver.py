import random
from typing import Collection

MAX_UINT48 = 0xFFFFFFFFFFFF
MAX_CONTENT_VERSION = MAX_UINT48 - 1
MAX_CONTENT_VERSION_DELTA = 1000


def initial_version() -> int:
    # initial content version number averaged 4 billion. It varies both ways.
    # There is no clear upper bound.

    result = round(random.gauss(2 ** 32, 2 ** 24))
    result = max(result, 0)
    assert 0 <= result
    return result


def increased_data_version(prev_versions: Collection[int]) -> int:
    # todo when we somehow reached upper limit, remove all blocks from
    # the namegroup, start again

    if len(prev_versions) <= 0:
        return initial_version()

    previously_max = max(prev_versions)

    assert previously_max >= 1
    result = previously_max + random.randint(1, MAX_CONTENT_VERSION_DELTA)
    if result > MAX_CONTENT_VERSION:
        # ((2**48)-99999) / 100 = 2 814 749 766 106.57 (two trillions)
        # this will never happen
        raise ValueError(f"new_data_version={result} "
                         f"cannot be saved as UINT48")
    assert result > previously_max
    return result
