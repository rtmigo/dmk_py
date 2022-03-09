# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import os
import shutil
from pathlib import Path
from typing import Optional

from dmk.a_utils.shred import shred


class WritingToTempFile:
    """We will write data to a temporary file first, and when it's
    ready, we rename the file.

    We must use the same function for real files and fakes, so they
    look the same in logs.
    """

    def __init__(self, file: Path):
        self.final = file
        self.dirty = file.parent / (file.name + ".tmp")

    def __enter__(self):
        return self

    def commit(self):
        # instead of atomically replacing `final` with `dirty`,
        # we will copy `final` to a .bak file, rename `dirty` to `final`,
        # and securely remove the `.bak`. This way we'll be sure, the old
        # file content is not kept in the file system

        bak: Optional[Path] = None
        if self.final.exists():
            bak = self.final.parent / f"{self.final.name}.bak"
            shutil.copy2(self.final, bak)

        os.replace(self.dirty, self.final)

        if bak is not None:
            shred(bak)

        self.dirty = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.dirty is not None and self.dirty.exists():
            try:
                shred(self.dirty)
            except FileNotFoundError:
                pass
