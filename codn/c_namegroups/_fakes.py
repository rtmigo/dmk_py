# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import io

from codn._common import CLUSTER_SIZE
from codn.a_base import CodenameKey
from codn.b_cryptoblobs._20_encdec_part import Encrypt


def create_fake_bytes(pk: CodenameKey) -> bytes:
    with io.BytesIO() as temp_io:
        Encrypt(cnk=pk).io_to_io(
            None,  # fake!
            temp_io)
        temp_io.seek(0, io.SEEK_SET)
        result = temp_io.read()
        #
        # result = Imprint(fpk).as_bytes + get_random_bytes(
        #     CLUSTER_SIZE - Imprint.FULL_LEN)
        assert len(result) == CLUSTER_SIZE
        return result
