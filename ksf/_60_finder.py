# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import os
import random
from pathlib import Path
from typing import List, Optional, Tuple, Callable

from ksf._40_imprint import name_matches_encoded
from ksf._50_sur import create_surrogate
from ksf._51_encryption import name_matches_header, encrypt_to_dir, \
    DecryptedFile


def _get_newest_file_naive(files: List[Path]) -> Path:
    times_and_files = [(f.stat().st_mtime, f) for f in files]
    max_mod_time = max(t for t, _ in times_and_files)
    files_modified_at_max = [f for t, f in times_and_files if t == max_mod_time]
    if len(files_modified_at_max) != 1:
        raise RuntimeError("Unexpected count of files with the same maximum"
                           f"last-modified: {len(files_modified_at_max)}")
    return files_modified_at_max[0]


def _get_newest_file(files: List[Path], name: str) -> Path:
    # we are reading not the file last-modified timestamp, but a timestamp
    # stored inside the encrypted file content
    times_and_files = [(DecryptedFile(fp, name).mtime, fp) for fp in files]

    # todo maybe we can read the decrypted header without decrypting
    # the contents?

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

        self.file: Optional[Path] = None

        # `files` are all files related to the current item, the real one
        # and the surrogates
        self.all_files = [p for p in self.parent.glob('*')
                          if name_matches_encoded(self.name, p.name)]

        reals = [p for p in self.all_files
                 if name_matches_header(self.name, p)]

        if len(reals) == 1:
            self.file = reals[0]
        elif len(reals) > 1:
            # usually only one file is real, the rest are surrogates. But it
            # may happen that the program was interrupted when it had already
            # created a new real file, but did not delete the old one.
            # In this rare case, we will have to decrypt both real files
            # to compare their last modified dates

            # todo test
            self.file = _get_newest_file(reals, name)
        else:
            assert len(reals) == 0
            self.file = None

        self.surrogates = [f for f in self.all_files if f != self.file]


def write_with_surrogates(source_file: Path, name: str, target_dir: Path):
    # we will remove and add some surrogates, and also remove old real file
    # add new real file. We will do this in random order, so as not to give
    # out which files are real and which are surrogates

    ANYTIME = 0
    EARLIER = 1
    LATER = 2

    tasks: List[Tuple[int, Callable]] = list()

    old_files = FileAndSurrogates(target_dir, name)

    # we will remove random count of surrogates
    if len(old_files.surrogates) >= 3:
        for surrogate in random.sample(old_files.surrogates,
                                       random.randint(1, 3)):
            tasks.append((ANYTIME, lambda: os.remove(str(surrogate))))

    # and add random count of surrogates
    src_size = source_file.stat().st_size
    for _ in range(random.randint(1, 3)):
        tasks.append((ANYTIME, lambda: create_surrogate(name=name,
                                                        target_dir=target_dir,
                                                        ref_size=src_size)))

    # add the new real file
    tasks.append(
        (EARLIER, lambda: encrypt_to_dir(source_file, name, target_dir)))
    # todo set last modified newer than old?

    # remove the old real file
    if old_files.file is not None:
        tasks.append((LATER, lambda: os.remove(str(old_files.file))))

    ##############

    def index_of(x: int):
        # todo test
        return next(idx for idx, tpl in enumerate(tasks) if tpl[0] == x)

    while True:
        random.shuffle(tasks)
        if index_of(LATER) > index_of(EARLIER):
            break

    for _, func in tasks:
        func()
