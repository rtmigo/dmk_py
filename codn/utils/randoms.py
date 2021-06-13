# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random


def get_noncrypt_random_bytes(n: int):
    return bytes(random.getrandbits(8) for _ in range(n))
