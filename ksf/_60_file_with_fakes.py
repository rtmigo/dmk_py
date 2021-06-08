# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

from pathlib import Path
from typing import List, Optional

from ksf._40_imprint import name_matches_encoded
from ksf._51_encryption import name_matches_header


def _get_newest_file(files: List[Path]) -> Path:
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

        self.file: Optional[Path] = None

        # `files` are all files related to the current item, the real one
        # and the fakes
        self.all_files = [p for p in self.parent.glob('*')
                          if name_matches_encoded(self.name, p.name)]

        reals = [p for p in self.all_files
                 if name_matches_header(self.name, p)]

        if len(reals) == 1:
            self.file = reals[0]
        elif len(reals) > 1:
            # todo test
            self.file = _get_newest_file(reals)
        else:
            assert len(reals) == 0
            self.file = None

# def encrypt_with_fakes(source_file: Path, target_dir: Path):

# encrypt_to_dir
