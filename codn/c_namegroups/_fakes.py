# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random

from Crypto.Random import get_random_bytes

from codn.a_base import CodenameKey, Imprint
from codn._common import MAX_BLOB_SIZE




def create_fake_bytes(fpk: CodenameKey) -> bytes:
    """Creates a fake file.

    WRONG DOC (NEEDS REWRITE)

    The file name of the will be the correct imprint from the [fpk]. But the
    file content is random, so the file header is not a correct imprint
    from [fpk].

    Knowing the name we can easily find all the fakes and real files
    for the name. We can differentiate the real file from the surrogate
    by the header (only for real files it contains the imprint).

    ref_size: The size of the real file. The surrogate file will have
    similar size but randomized.
    """

    # todo test instead "create file"

    target_size = random.randint(0, MAX_BLOB_SIZE)

    return Imprint(fpk).as_bytes + get_random_bytes(
        target_size - Imprint.FULL_LEN)
