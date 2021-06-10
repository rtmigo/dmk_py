# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import os
import random
from pathlib import Path
from typing import List, Optional

from ksf._20_key_derivation import FilesetPrivateKey
from ksf._40_imprint import pk_matches_codename
from ksf._50_sur import create_fake
from ksf._61_encryption import pk_matches_header, encrypt_to_dir, \
    DecryptedFile
from ksf.random_sizes import random_size_like_others_in_dir, \
    random_size_like_file


def _get_newest_file(files: List[Path], pk: FilesetPrivateKey) -> Path:
    # we are reading not the file last-modified timestamp, but a timestamp
    # stored inside the encrypted file content
    times_and_files = [
        (DecryptedFile(fp, pk, decrypt_body=False).data_version, fp)
        for fp in files]

    latest_timestamp = max(ts for ts, _ in times_and_files)
    latest_files = [fp for ts, fp in times_and_files if ts == latest_timestamp]

    if len(latest_files) != 1:
        raise RuntimeError("Unexpected count of files with the same maximum"
                           f"last-modified: {len(latest_files)}")
    return latest_files[0]


class Fileset:
    def __init__(self, parent: Path, fpk: FilesetPrivateKey):
        self.parent = parent
        self.fpk = fpk

        self.real_file: Optional[Path] = None

        # `files` are all files related to the current item,
        # the real one and the surrogates
        self.all_files = [p for p in self.parent.glob('*')
                          if pk_matches_codename(self.fpk, p.name)]

        reals = [p for p in self.all_files
                 if pk_matches_header(self.fpk, p)]

        if len(reals) == 1:
            self.real_file = reals[0]
        elif len(reals) > 1:
            # it tested indirectly when we write and rewrite fileset
            # multiple times. Without correctly incrementing version,
            # we will not be able to read the latest data
            self.real_file = _get_newest_file(reals, fpk)
        else:
            assert len(reals) == 0
            self.real_file = None

        self.surrogates = [f for f in self.all_files if f != self.real_file]


class Task:
    pass


class WriteFakeTask(Task):
    def __init__(self, size: int):
        self.size = size


class DeleteTask(Task):
    def __init__(self, path: Path, is_real: bool):
        self.file = path
        self.is_real = is_real


class WriteRealTask(Task):
    pass


def _shuffle_so_creating_before_deleting(tasks: List[Task]):
    """We shuffle tasks in random order, while making sure that a new real
    file is created first, and only then the old one is deleted"""
    while True:
        random.shuffle(tasks)
        index_of_delete = next(
            (idx for idx, task in enumerate(tasks)
             if isinstance(task, DeleteTask) and task.is_real),
            None)
        if index_of_delete is None:
            break
        index_of_create = next(idx for idx, task in enumerate(tasks)
                               if isinstance(task, WriteRealTask))
        assert index_of_create != index_of_delete
        if index_of_create < index_of_delete:
            break


def dir_to_file_sizes(d: Path) -> List[int]:
    return [f.stat().st_size for f in d.glob('*') if f.is_file]


MAX_UINT32 = (2 ** 32) - 1


def update_fileset(source_file: Path, fpk: FilesetPrivateKey, target_dir: Path):
    # we will remove and add some surrogates, and also remove old real file
    # add new real file. We will do this in random order, so as not to give
    # out which files are real and which are surrogates

    source_file_size = source_file.stat().st_size
    all_file_sizes = dir_to_file_sizes(target_dir)

    def fake_size():
        result = random_size_like_others_in_dir(all_file_sizes)
        if result is None:
            result = random_size_like_file(source_file_size)
        return result

    tasks: List[Task] = list()

    fileset = Fileset(target_dir, fpk)

    new_data_version: Optional[int] = None

    if fileset.real_file:
        df = DecryptedFile(fileset.real_file, fpk, decrypt_body=False)
        new_data_version = df.data_version + random.randint(1, 999)
        if new_data_version > MAX_UINT32:
            raise ValueError(f"new_data_version={new_data_version} "
                             f"cannot be saved as UINT32")

    max_to_delete = 4
    max_to_fake = max_to_delete - 1  # +1 real file will be written

    # we will remove random number of files
    if len(fileset.all_files) > 0:
        max_to_delete = min(max_to_delete, len(fileset.all_files))
        num_to_delete = random.randint(1, max_to_delete)
        files_to_delete = random.sample(fileset.all_files, num_to_delete)
        for f in files_to_delete:
            tasks.append(DeleteTask(
                path=f,
                is_real=(f == fileset.real_file)))

    for _ in range(random.randint(1, max_to_fake)):
        tasks.append(WriteFakeTask(fake_size()))
    tasks.append(WriteRealTask())

    _shuffle_so_creating_before_deleting(tasks)

    real_written = False

    for task in tasks:
        if isinstance(task, WriteRealTask):
            encrypt_to_dir(source_file, fpk, target_dir, new_data_version)
            real_written = True
        elif isinstance(task, WriteFakeTask):
            create_fake(fpk,
                        target_dir=target_dir,
                        target_size=task.size)
        elif isinstance(task, DeleteTask):
            assert real_written or not task.is_real
            os.remove(str(task.file))
        else:
            raise TypeError
