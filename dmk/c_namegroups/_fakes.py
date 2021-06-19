# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io

from dmk._common import CLUSTER_SIZE
from dmk.a_base import CodenameKey
from dmk.b_cryptoblobs._20_encdec_part import Encrypt


def create_fake_bytes(pk: CodenameKey) -> bytes:
    with io.BytesIO() as temp_io:
        Encrypt(cnk=pk).io_to_io(
            None,  # fake!
            temp_io)
        temp_io.seek(0, io.SEEK_SET)
        result = temp_io.read()
        assert len(result) == CLUSTER_SIZE
        return result
