# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

from Crypto.Random import get_random_bytes

from codn._common import CLUSTER_SIZE
from codn.a_base import CodenameKey, Imprint


def create_fake_bytes(fpk: CodenameKey) -> bytes:
    result = Imprint(fpk).as_bytes + get_random_bytes(
        CLUSTER_SIZE - Imprint.FULL_LEN)
    assert len(result) == CLUSTER_SIZE
    return result
