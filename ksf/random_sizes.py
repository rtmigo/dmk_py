# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import random
from typing import Iterable, Optional

_MIN_SIZE = 1024


def _not_too_small(size: int) -> int:
    if size < _MIN_SIZE:
        return _MIN_SIZE + random.randint(0, 1024)
    return size


def random_size_like_others_in_dir(file_sizes: Iterable[int]) -> Optional[int]:
    # todo test
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

    return _not_too_small(result)  # todo test


def random_size_like_file(reference_size: int) -> int:
    # must be used when creating both surrogates and real files
    radius = round(reference_size / 2)
    delta = random.randint(-radius, radius)
    result = reference_size + delta
    return _not_too_small(result)  # todo test
