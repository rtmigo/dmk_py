# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import os
import random
from pathlib import Path
from typing import List, Optional

from ksf._40_imprint import name_matches_encoded
from ksf._50_sur import create_surrogate
from ksf._61_encryption import name_matches_header, encrypt_to_dir, \
    DecryptedFile


def _get_newest_file(files: List[Path], name: str) -> Path:
    # we are reading not the file last-modified timestamp, but a timestamp
    # stored inside the encrypted file content
    times_and_files = [
        (DecryptedFile(fp, name, decrypt_body=False).timestamp, fp)
        for fp in files]

    latest_timestamp = max(ts for ts, _ in times_and_files)
    latest_files = [fp for ts, fp in times_and_files if ts == latest_timestamp]

    if len(latest_files) != 1:
        raise RuntimeError("Unexpected count of files with the same maximum"
                           f"last-modified: {len(latest_files)}")
    return latest_files[0]


class FileAndSurrogates:
    def __init__(self, parent: Path, name: str):
        self.parent = parent
        self.name = name

        self.real_file: Optional[Path] = None

        # `files` are all files related to the current item, the real one
        # and the surrogates
        self.all_files = [p for p in self.parent.glob('*')
                          if name_matches_encoded(self.name, p.name)]

        reals = [p for p in self.all_files
                 if name_matches_header(self.name, p)]

        if len(reals) == 1:
            self.real_file = reals[0]
        elif len(reals) > 1:
            # todo test
            self.real_file = _get_newest_file(reals, name)
        else:
            assert len(reals) == 0
            self.real_file = None

        self.surrogates = [f for f in self.all_files if f != self.real_file]


# class Timing(IntEnum):
#    anytime = auto()
#    earlier = auto()
#    later = auto()


# class Task(NamedTuple):
#    timing: Timing
#    func: Callable

class Task:
    pass


class CreateSurrogateTask(Task):
    pass


class DeleteFileTask(Task):
    def __init__(self, path: Path, is_real: bool):
        self.file = path
        self.is_real = is_real


class EncryptRealFileTask(Task):
    pass


def _shuffle_so_creating_before_deleting(tasks: List[Task]):
    """We shuffle tasks in random order, while making sure that a new real
    file is created first, and only then the old one is deleted"""
    while True:
        random.shuffle(tasks)
        index_of_delete = next(
            (idx for idx, task in enumerate(tasks)
             if isinstance(task, DeleteFileTask) and task.is_real),
            None)
        if index_of_delete is None:
            break
        index_of_create = next(idx for idx, task in enumerate(tasks)
                               if isinstance(task, EncryptRealFileTask))
        assert index_of_create != index_of_delete
        if index_of_create < index_of_delete:
            break


def write_with_surrogates(source_file: Path, name: str, target_dir: Path):
    # we will remove and add some surrogates, and also remove old real file
    # add new real file. We will do this in random order, so as not to give
    # out which files are real and which are surrogates

    tasks: List[Task] = list()

    source_file_size = source_file.stat().st_size

    old_files = FileAndSurrogates(target_dir, name)

    # we will remove random number of files

    if len(old_files.all_files) > 0:
        n = random.randint(1, len(old_files.all_files))
        files_to_delete = random.sample(old_files.all_files, n)
        for f in files_to_delete:
            is_the_real = (f == old_files.real_file)
            tasks.append(DeleteFileTask(f, is_the_real))

    for _ in range(random.randint(1, 3)):
        tasks.append(CreateSurrogateTask())
    tasks.append(EncryptRealFileTask())

    _shuffle_so_creating_before_deleting(tasks)

    for task in tasks:
        if isinstance(task, DeleteFileTask):
            os.remove(str(task.file))
        elif isinstance(task, CreateSurrogateTask):
            create_surrogate(name=name,
                             target_dir=target_dir,
                             ref_size=source_file_size)
        elif isinstance(task, EncryptRealFileTask):
            encrypt_to_dir(source_file, name, target_dir)
        else:
            raise TypeError