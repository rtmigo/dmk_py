# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import random
from pathlib import Path
from typing import BinaryIO, List, Set

from codn.a_base._10_kdf import CodenameKey
from codn.a_utils.randoms import set_random_last_modified
from codn.b_cryptoblobs._20_encdec_part import get_stream_size, \
    Encrypt, \
    DecryptedIO
from codn._common import unique_filename, MAX_BLOB_SIZE, MAX_PART_CONTENT_SIZE


def split_random_sizes(full_size: int) -> List[int]:
    if full_size < 0:
        raise ValueError

    if full_size == 0:
        return [0]

    truncated_last_part = False  # just for asserts

    sum_sizes = 0
    part_sizes = list()
    while sum_sizes < full_size:
        assert not truncated_last_part

        # up to 64 kb, even if we do not have so much data
        next_part_size = random.randint(1, MAX_PART_CONTENT_SIZE)
        # adjusting the last part size
        limit = min(MAX_PART_CONTENT_SIZE, full_size - sum_sizes)
        assert limit > 0
        if next_part_size > limit:
            next_part_size = limit
            truncated_last_part = True

        # updating sizes list and sum
        sum_sizes += next_part_size
        part_sizes.append(next_part_size)

    assert sum(part_sizes) == full_size, f"{sum(part_sizes)} {full_size}"
    assert all(1 <= p <= MAX_PART_CONTENT_SIZE for p in part_sizes)
    return part_sizes


class MultipartEncryptor:
    def __init__(self,
                 fpk: CodenameKey,
                 source_io: BinaryIO,
                 content_version: int):
        self.fpk = fpk
        self.source_io = source_io
        self.content_version = content_version

        full_size = get_stream_size(source_io)
        self.part_sizes = split_random_sizes(full_size)
        assert sum(self.part_sizes) == full_size

        self.encrypted_indices: Set[int] = set()

    def encrypt(self, part_idx: int, target_io: BinaryIO):
        if part_idx in self.encrypted_indices:
            raise ValueError(f"The part {part_idx} is already encrypted.")

        src_pos = sum(self.part_sizes[:part_idx])
        self.source_io.seek(src_pos, io.SEEK_SET)

        Encrypt(self.fpk,
                parts_len=len(self.part_sizes),
                part_idx=part_idx,
                part_size=self.part_sizes[part_idx],
                data_version=self.content_version
                ).io_to_io(self.source_io, target_io)
        assert target_io.seek(0, io.SEEK_END) <= MAX_BLOB_SIZE

        self.encrypted_indices.add(part_idx)

    def encrypt_all_to_list(self) -> List[bytes]:
        result: List[bytes] = []
        for part_idx in range(len(self.part_sizes)):
            with io.BytesIO() as outio:
                self.encrypt(part_idx, outio)
                outio.seek(0, io.SEEK_SET)
                result.append(outio.read())
        assert self.all_encrypted
        return result

    @property
    def all_encrypted(self) -> bool:
        return len(self.encrypted_indices) == len(self.part_sizes)


def encrypt_to_files(fpk: CodenameKey,
                     source_io: BinaryIO,
                     target_dir: Path,
                     content_version: int) -> List[Path]:
    # todo remove this method
    # it is outdated and it does not use WTF
    # is is kept temporarily for transition period
    me = MultipartEncryptor(fpk, source_io, content_version)

    files: List[Path] = []

    for i in range(len(me.part_sizes)):
        target_file = unique_filename(target_dir)
        files.append(target_file)
        with target_file.open('wb') as f:
            me.encrypt(i, f)
        set_random_last_modified(target_file)

    assert len(files) == len(me.part_sizes)
    return files
    #
    #
    #
    # full_size = get_stream_size(source_io)
    # part_sizes = split_random_sizes(full_size)
    # assert sum(part_sizes) == full_size
    #
    #
    #
    # for part_idx, part_size in enumerate(part_sizes):
    #     target_file = unique_filename(target_dir)
    #     files.append(target_file)
    #     Encrypt(fpk,
    #             parts_len=len(part_sizes),
    #             part_idx=part_idx,
    #             part_size=part_size,
    #             data_version=content_version
    #             ).io_to_file(source_io, target_file)
    #
    # assert len(files) == len(part_sizes)
    # return files


def encrypt_to_files_old(fpk: CodenameKey,
                         source_io: BinaryIO,
                         target_dir: Path,
                         content_version: int) -> List[Path]:
    full_size = get_stream_size(source_io)
    part_sizes = split_random_sizes(full_size)
    assert sum(part_sizes) == full_size

    files: List[Path] = []

    for part_idx, part_size in enumerate(part_sizes):
        target_file = unique_filename(target_dir)
        files.append(target_file)
        Encrypt(fpk,
                parts_len=len(part_sizes),
                part_idx=part_idx,
                part_size=part_size,
                data_version=content_version
                ).io_to_file(source_io, target_file)

    assert len(files) == len(part_sizes)
    return files


class BadFilesetError(Exception):
    pass


def decrypt_from_dios(files: List[DecryptedIO],
                      target_io: BinaryIO):
    if not files:
        raise ValueError("Zero files passed")

    pos = target_io.seek(0, io.SEEK_CUR)
    if pos != 0:
        raise ValueError(f"Unexpected initial stream position: {pos}")

    files = files.copy()

    first = files[0]
    for f in files[1:]:
        if f.header.parts_len != first.header.parts_len:
            raise BadFilesetError("parts_len mismatch")
        if f.header.data_size != first.header.data_size:
            raise BadFilesetError("data_size mismatch")
        if f.header.data_version != first.header.data_version:
            raise BadFilesetError("data_version mismatch")
    if len(files) != first.header.parts_len:
        raise BadFilesetError(f"Expected {first.header.parts_len} files, "
                              f"but got {len(files)}.")
    if len(set(f.header.part_idx for f in files)) != len(files):
        raise BadFilesetError("some part indexes are not unique")

    files.sort(key=lambda fl: fl.header.part_idx)

    for f in files:
        # maximum data size is 64k, so no need for chunks
        target_io.write(f.read_data())

    pos = target_io.seek(0, io.SEEK_CUR)
    if pos != first.header.data_size:
        raise ValueError(f"Unexpected final stream position: {pos}. "
                         f"Full original data size must be "
                         f"{first.header.data_size}.")
