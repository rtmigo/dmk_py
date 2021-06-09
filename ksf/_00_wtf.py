# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import os
from pathlib import Path


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

    def replace(self):
        os.replace(self.dirty, self.final)
        self.dirty = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.dirty is not None:
            try:
                os.remove(self.dirty)
            except FileNotFoundError:
                pass
