# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import zlib
from pathlib import Path
from typing import BinaryIO, List, Set

from dmk._common import MAX_CLUSTER_CONTENT_SIZE, CLUSTER_SIZE
from dmk.a_base._10_kdf import CodenameKey
from dmk.a_utils.randoms import set_random_last_modified, unique_filename
from dmk.b_cryptoblobs._20_encdec_part import get_stream_size, \
    Encrypt, \
    DecryptedIO


def split_cluster_sizes(full_size: int) -> List[int]:
    if full_size < 0:
        raise ValueError
    if full_size == 0:
        return [0]
    result: List[int] = []
    s = full_size
    while s > 0:
        result.append(min(s, MAX_CLUSTER_CONTENT_SIZE))
        s -= MAX_CLUSTER_CONTENT_SIZE
    assert sum(result) == full_size
    return result


class MultipartEncryptor:
    def __init__(self,
                 fpk: CodenameKey,
                 source_io: BinaryIO,
                 content_version: int):
        self.fpk = fpk
        self.content_version = content_version

        self._source_bytesio = source_io

        # todo cache source io in bytes io?

        full_size = get_stream_size(source_io)
        self.part_sizes = split_cluster_sizes(full_size)
        assert sum(self.part_sizes) == full_size

        assert self._source_bytesio.tell() == 0
        self.source_crc = zlib.crc32(self._source_bytesio.read())
        self._source_bytesio.seek(0, io.SEEK_SET)

        self.encrypted_indices: Set[int] = set()

    def encrypt(self, part_idx: int, target_io: BinaryIO):
        if part_idx in self.encrypted_indices:
            raise ValueError(f"The part {part_idx} is already encrypted.")

        src_pos = sum(self.part_sizes[:part_idx])
        self._source_bytesio.seek(src_pos, io.SEEK_SET)

        Encrypt(self.fpk,
                parts_len=len(self.part_sizes),
                part_idx=part_idx,
                part_size=self.part_sizes[part_idx],
                data_version=self.content_version
                ).io_to_io(self._source_bytesio, target_io)
        assert target_io.seek(0, io.SEEK_END) == CLUSTER_SIZE

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

    max_part_idx = max(f.header.part_idx for f in files)
    if max_part_idx != len(files) - 1:
        raise BadFilesetError(
            f"max_part_idx={max_part_idx}, but len(files)={len(files)}")

    if set(f.header.part_idx for f in files) != set(range(len(files))):
        raise BadFilesetError(
            f"Some parts are missing")

    first = files[0]
    for f in files[1:]:
        if f.header.data_version != first.header.data_version:
            raise BadFilesetError("data_version mismatch")

    if len(set(f.header.part_idx for f in files)) != len(files):
        raise BadFilesetError("some part indexes are not unique")

    files.sort(key=lambda fl: fl.header.part_idx)

    for f in files:
        # maximum data size is 64k, so no need for chunks
        target_io.write(f.read_data())

    pos = target_io.seek(0, io.SEEK_CUR)
    if pos != sum(f.header.part_size for f in files):
        raise ValueError(f"Unexpected final stream position: {pos}.")
