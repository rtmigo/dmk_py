# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


from Crypto.Random import get_random_bytes

from dmk._common import CODENAME_LENGTH_BYTES


class CodenameAscii:

    # todo remove?

    @classmethod
    def to_padded_ascii(cls, codename: str) -> bytes:
        result = cls.to_ascii(codename)
        length = len(result)
        if length > CODENAME_LENGTH_BYTES:
            raise ValueError(f"Too long: {length}>{CODENAME_LENGTH_BYTES}")
        elif length < CODENAME_LENGTH_BYTES:
            padding = get_random_bytes(CODENAME_LENGTH_BYTES - length - 1)
            result = padding + b'\0' + result
        assert len(result) == CODENAME_LENGTH_BYTES
        return result

    @classmethod
    def unpadded(cls, codename_data: bytes) -> bytes:
        return codename_data.rpartition(b'\0')[2]

    @classmethod
    def to_ascii(cls, codename: str) -> bytes:
        if '\0' in codename:
            raise ValueError("Zero character in codename")
        result = codename.encode('ascii')
        if len(result) > CODENAME_LENGTH_BYTES:
            raise ValueError(f"Too long: {len(result)}>{CODENAME_LENGTH_BYTES}")
        return result

    @classmethod
    def padded_to_str(cls, data: bytes) -> str:
        return cls.unpadded(data).decode('ascii')
