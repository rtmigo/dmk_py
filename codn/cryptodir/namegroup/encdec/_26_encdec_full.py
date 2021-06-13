import io
import random
from pathlib import Path
from typing import BinaryIO, List

from codn._common import unique_filename
from codn.cryptodir._10_kdf import FilesetPrivateKey
from codn.cryptodir.namegroup.encdec._25_encdec_part import get_stream_size, Encrypt, \
    DecryptedIO


def split_random_sizes(full_size: int) -> List[int]:
    MAX_PART_SIZE = 0xFFFF

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
        next_part_size = random.randint(1, MAX_PART_SIZE)
        # adjusting the last part size
        limit = min(MAX_PART_SIZE, full_size - sum_sizes)
        assert limit > 0
        if next_part_size > limit:
            next_part_size = limit
            truncated_last_part = True

        # updating sizes list and sum
        sum_sizes += next_part_size
        part_sizes.append(next_part_size)

    assert sum(part_sizes) == full_size, f"{sum(part_sizes)} {full_size}"
    assert all(1 <= p <= MAX_PART_SIZE for p in part_sizes)
    return part_sizes


def encrypt_to_files(fpk: FilesetPrivateKey,
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


def decrypt_from_files(files: List[DecryptedIO],
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
