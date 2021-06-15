# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import struct


def double_to_bytes(x: float) -> bytes:
    return struct.pack('>d', x)


def bytes_to_double(b: bytes) -> float:
    result = struct.unpack('>d', b)
    # print(result)
    return result[0]


def bytes_to_uint32(data: bytes) -> int:
    if len(data) != 4:
        raise ValueError
    return int.from_bytes(data, byteorder='big', signed=False)


def bytes_to_uint16(data: bytes) -> int:
    if len(data) != 2:
        raise ValueError
    return int.from_bytes(data, byteorder='big', signed=False)


def bytes_to_uint24(data: bytes) -> int:
    if len(data) != 3:
        raise ValueError
    return int.from_bytes(data, byteorder='big', signed=False)


def bytes_to_int64(data: bytes) -> int:
    if len(data) != 8:
        raise ValueError
    return int.from_bytes(data, byteorder='big', signed=True)


def uint8_to_bytes(x: int) -> bytes:
    if not 0 <= x <= 0xFF:
        raise OverflowError
    return bytes((x,))


def bytes_to_uint8(data: bytes) -> int:
    if len(data) != 1:
        raise ValueError
    return data[0]


def uint16_to_bytes(x: int) -> bytes:
    return x.to_bytes(2, byteorder='big', signed=False)


def uint24_to_bytes(x: int) -> bytes:
    return x.to_bytes(3, byteorder='big', signed=False)


def uint32_to_bytes(x: int) -> bytes:
    return x.to_bytes(4, byteorder='big', signed=False)


def int64_to_bytes(x: int) -> bytes:
    return x.to_bytes(8, byteorder='big', signed=True)
