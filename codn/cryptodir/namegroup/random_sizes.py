# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random
from typing import Iterable, Optional

from codn._common import MIN_DATA_FILE_SIZE


def _not_too_small(size: int) -> int:
    if size < MIN_DATA_FILE_SIZE:
        return MIN_DATA_FILE_SIZE + random.randint(0, 1024)
    return size


def random_size_like_others_in_dir(file_sizes: Iterable[int]) -> Optional[int]:
    sizes = list(set(file_sizes))
    if len(sizes) < 2:
        return None

    sizes.sort()
    idx = random.randint(1, len(sizes) - 1)
    a, b = sizes[idx - 1], sizes[idx]
    assert a < b

    middle = int((a + b) / 2)

    assert middle >= a
    assert middle <= b

    radius = (b - a)

    assert radius > 0

    delta = random.randint(-radius, radius)

    result = middle + delta
    assert result >= middle - radius
    assert result <= middle + radius

    return _not_too_small(result)


def random_size_like_file(ref_size: int) -> int:
    radius = round(ref_size / 2)
    delta = random.randint(-radius, radius)
    result = ref_size + delta
    return _not_too_small(result)


def random_size_like_file_greater(ref_size: int) -> int:
    # todo remove
    for _ in range(999999):
        result = random_size_like_file(ref_size)
        if result >= ref_size:
            return result
    raise RuntimeError("Dead loop prevented")
