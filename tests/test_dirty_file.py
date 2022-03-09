# SPDX-FileCopyrightText: (c) 2022 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from dmk.a_utils.dirty_file import WritingToTempFile


class TestDirtyFiles(unittest.TestCase):
    def test_writing_new_and_committing(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            def files_count():
                return len(list(td.rglob("*")))

            self.assertEqual(files_count(), 0)

            target = td / "file.txt"

            with WritingToTempFile(target) as wttf:
                self.assertEqual(files_count(), 0)
                wttf.dirty.write_text("content!")
                self.assertEqual(files_count(), 1)
                wttf.commit()

            self.assertEqual(files_count(), 1)
            self.assertEqual(target.read_text(), "content!")

    def test_writing_new_and_not_committing(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            def files_count():
                return len(list(td.rglob("*")))

            self.assertEqual(files_count(), 0)

            target = td / "file.txt"

            class StubError(Exception):
                pass

            try:
                with WritingToTempFile(target) as wttf:
                    self.assertEqual(files_count(), 0)
                    wttf.dirty.write_text("content!")
                    self.assertEqual(files_count(), 1)
                    raise StubError
            except StubError:
                pass

            # we removed the temporary file and did not write to the target

            self.assertEqual(files_count(), 0)

    def test_writing_new_committing_then_error(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            def files_count():
                return len(list(td.rglob("*")))

            self.assertEqual(files_count(), 0)

            target = td / "file.txt"

            class StubError(Exception):
                pass

            try:
                with WritingToTempFile(target) as wttf:
                    self.assertEqual(files_count(), 0)
                    wttf.dirty.write_text("content!")
                    self.assertEqual(files_count(), 1)
                    wttf.commit()  # !!!
                    raise StubError
            except StubError:
                pass

            # we removed the temporary file, but kept the written data
            self.assertEqual(files_count(), 1)
            self.assertEqual(target.read_text(), "content!")

    def test_replacing_committing(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            def files_count():
                return len(list(td.rglob("*")))

            self.assertEqual(files_count(), 0)

            target = td / "file.txt"
            target.write_text("old content")

            class StubError(Exception):
                pass

            try:
                with WritingToTempFile(target) as wttf:
                    self.assertEqual(files_count(), 1)
                    wttf.dirty.write_text("new content")
                    self.assertEqual(files_count(), 2)
                    wttf.commit()
                    raise StubError
            except StubError:
                pass

            # we removed the temporary file, but kept the written data
            self.assertEqual(files_count(), 1)
            self.assertEqual(target.read_text(), "new content")

    def test_replacing_not_committing(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            def files_count():
                return len(list(td.rglob("*")))

            self.assertEqual(files_count(), 0)

            target = td / "file.txt"
            target.write_text("old content")

            class StubError(Exception):
                pass

            try:
                with WritingToTempFile(target) as wttf:
                    self.assertEqual(files_count(), 1)
                    wttf.dirty.write_text("new content")
                    self.assertEqual(files_count(), 2)
                    # wttf.replace() # not applying!
                    raise StubError
            except StubError:
                pass

            # nothing changed
            self.assertEqual(files_count(), 1)
            self.assertEqual(target.read_text(), "old content")
