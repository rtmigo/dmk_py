# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import random
from pathlib import Path
from typing import List

from Crypto.Random import get_random_bytes

from ksf._10_imprint import name_matches_encoded, Imprint, HashCollision, \
    name_matches_hash, set_file_last_modified, random_datetime
from ksf._20_encryption import name_matches_header


def _file_with_last_mod_time(files: List[Path]) -> Path:
    times_and_files = [(f.stat().st_mtime, f) for f in files]
    max_mod_time = max(t for t, _ in times_and_files)
    files_modified_at_max = [f for t, f in times_and_files if t == max_mod_time]
    if len(files_modified_at_max) != 1:
        raise RuntimeError("Unexpected count of files with the same maximum"
                           f"last-modified: {len(files_modified_at_max)}")
    return files_modified_at_max[0]


class FileAndFakes:
    def __init__(self, parent: Path, name: str):
        self.parent = parent
        self.name = name

        # `files` are all files related to the current item, the real one
        # and the fakes
        self.all_files = [p for p in self.parent.glob('*')
                          if name_matches_encoded(self.name, p.name)]

        reals = [p for p in self.all_files
                 if name_matches_header(self.name, p)]

        if len(reals) == 1:
            self.file = reals[0]
        elif len(reals) > 1:
            self.file = _file_with_last_mod_time(reals)
        else:
            assert len(reals) == 0
            raise RuntimeError("Real file not found")


def create_fake(name: str, ref_size: int, target_dir: Path):
    """Creates a fake file. The encoded name of fake file will match `name`,
    but the content is random, so the header does not match.
    """
    target_file = target_dir / Imprint(name).as_str
    if target_file.exists():
        raise HashCollision
    size = ref_size + random.randint(int(-ref_size * 0.75),
                                     int(ref_size * 0.75))
    non_matching_header = get_random_bytes(Imprint.HEADER_LEN)
    if name_matches_hash(name, non_matching_header):
        raise HashCollision

    target_file.write_bytes(get_random_bytes(size))  # todo chunks?

    set_file_last_modified(target_file, random_datetime())

    # target_file.s