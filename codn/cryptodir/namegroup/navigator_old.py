# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

"""

NAMEGROUP is all files related to a particular name. A group consists of:
- FILESET: files containing encrypted parts of the latest version of the data
- fakes: some files with random content
- obsolete: files with encrypted parts of older versions

Only the fileset can be decrypted. Obsolete files are deleted randomly, and
their sets may not be complete.

Fakes for different names look the same on the outside. However, they must be
associated with a specific name. This is the only way we can identify them as
fakes, knowing the secret key (derived from the name).

"""

import io
import os
import random
from pathlib import Path
from typing import List, BinaryIO, Optional

from codn._common import MIN_DATA_FILE_SIZE
from codn.cryptodir._10_kdf import CodenameKey
from codn.cryptodir.namegroup.fakes import create_fake
from codn.cryptodir.namegroup.encdec._25_encdec_part import DecryptedIO
from codn.cryptodir.namegroup.encdec._26_encdec_full import encrypt_to_files
from codn.cryptodir.namegroup.random_sizes import random_size_like_others_in_dir, \
    random_size_like_file


# def _get_newest_file(files: List[Path], pk: FilesetPrivateKey) -> Path:
#     # we are reading not the file last-modified timestamp, but a timestamp
#     # stored inside the encrypted file content
#     times_and_files = [
#         (_DecryptedFile(fp, pk, decrypt_body=False).data_version, fp)
#         for fp in files]
#
#     latest_timestamp = max(ts for ts, _ in times_and_files)
#     latest_files = [fp for ts, fp in times_and_files if ts == latest_timestamp]
#
#     if len(latest_files) != 1:
#         raise RuntimeError("Unexpected count of files with the same maximum"
#                            f"last-modified: {len(latest_files)}")
#     return latest_files[0]


class NameGroupFile:
    def __init__(self, path: Path, dio: DecryptedIO):
        self.path = path
        self.dio = dio
        self.is_fresh_data = False
        self.is_fake = False


class NewNameGroup:
    def __init__(self, parent: Path, fpk: CodenameKey):
        self.parent = parent
        self.fpk = fpk
        self._streams: List[BinaryIO] = []

        self._fresh_content_dios: Optional[List[DecryptedIO]] = None

    def __enter__(self):
        self.files: List[NameGroupFile] = []

        for path in self.parent.glob('*'):
            input_io = path.open('rb')  # todo test if not a file
            self._streams.append(input_io)

            dio = DecryptedIO(self.fpk, input_io)

            if not dio.belongs_to_namegroup:
                dio.source.close()
                continue

            assert dio.belongs_to_namegroup
            gf = NameGroupFile(path, dio)
            self.files.append(gf)

        # marking fakes
        for f in self.files:
            if not f.dio.contains_data:
                f.is_fake = True
                f.dio.source.close()
            else:
                assert not f.is_fake

        # finding the latest full version

        # It could happen that we started saving a new version of the content,
        # but something prevented it from completing. So the fileset does not
        # have all the needed parts. We are not interested in such incomplete
        # filesets. Therefore, we are looking for the maximum version value
        # only among the content that has all the parts.

        all_content_files = [gf for gf in self.files if gf.dio.contains_data]
        self.all_content_versions = set(gf.dio.header.data_version
                                        for gf in all_content_files)

        # trying version for maximum to minimum
        for ver in sorted(self.all_content_versions, reverse=True):
            files_by_ver = [gf for gf in all_content_files
                            if gf.dio.header.data_version == ver]
            if files_by_ver[0].dio.header.parts_len == len(files_by_ver):
                # okay, this is the fresh content with all parts
                for gf in files_by_ver:
                    gf.is_fresh_data = True
                break

        # we don't need other files opened
        for gf in all_content_files:
            if not gf.is_fresh_data:
                gf.dio.source.close()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for stream in self._streams:
            stream.close()
        self._streams = None

    @property
    def fresh_content_files(self) -> List[DecryptedIO]:
        if self._fresh_content_dios is None:
            self._fresh_content_dios = [gf.dio for gf in self.files
                                        if gf.is_fresh_data]
        return self._fresh_content_dios





# class NameGroup:
#     def __init__(self, parent: Path, fpk: FilesetPrivateKey):
#         self.parent = parent
#         self.fpk = fpk
#
#         self.real_file: Optional[Path] = None
#
#         # `files` are all files related to the current item,
#         # the real one and the surrogates
#         self.all_files = [p for p in self.parent.glob('*')
#                           if
#                           p.is_file() and is_file_from_namegroup(self.fpk, p)]
#
#         reals = [p for p in self.all_files
#                  if is_file_with_data(self.fpk, p)]
#
#         if len(reals) == 1:
#             self.real_file = reals[0]
#         elif len(reals) > 1:
#             # it tested indirectly when we write and rewrite fileset
#             # multiple times. Without correctly incrementing version,
#             # we will not be able to read the latest data
#             self.real_file = _get_newest_file(reals, fpk)
#         else:
#             assert len(reals) == 0
#             self.real_file = None
#
#         self.surrogates = [f for f in self.all_files if f != self.real_file]


class Task:
    def __init__(self, sorting: int):
        self.sorting = sorting


class WriteFakeTask(Task):
    def __init__(self, size: int):
        super().__init__(0)  # default sorting
        self.size = size


class DeleteTask(Task):
    def __init__(self, path: Path, was_the_content: bool):
        super().__init__(1 if was_the_content else 0)  # later or default
        self.file = path
        self.was_the_content = was_the_content


class WriteRealTask(Task):
    def __init__(self):
        super().__init__(-1)


# def _shuffle_so_creating_before_deleting(tasks: List[Task]):
#     """We shuffle tasks in random order, while making sure that a new real
#     file is created first, and only then the old one is deleted"""
#
#     random.shuffle(tasks)
#     tasks.sort(key=lambda t: t.sorting)


def dir_to_file_sizes(d: Path) -> List[int]:
    return [f.stat().st_size for f in d.glob('*') if f.is_file]


# def increased_data_version(fileset: NameGroup) -> int:
#     MAX_INT64 = 0x7FFFFFFFFFFFFFFF
#     if fileset.real_file:
#         df = _DecryptedFile(fileset.real_file, fileset.fpk, decrypt_body=False)
#         assert df.data_version >= 1
#         ver = df.data_version + random.randint(1, 999)
#         if ver > MAX_INT64:
#             # this will never happen
#             raise ValueError(f"new_data_version={ver} "
#                              f"cannot be saved as INT64")
#         assert ver > df.data_version
#         return ver
#     # this is the first time we are saving this item. We assign it
#     # a random version value.
#     return random.randint(1, 999999)


def increased_data_version_old(fileset: NewNameGroup) -> int:
    MAX_INT64 = 0x7FFFFFFFFFFFFFFF
    if len(fileset.all_content_versions) <= 0:
        return random.randint(1, 999999)

    previously_max = max(fileset.all_content_versions)

    assert previously_max >= 1
    result = previously_max + random.randint(1, 999)
    if result > MAX_INT64:
        # this will never happen
        raise ValueError(f"new_data_version={result} "
                         f"cannot be saved as INT64")
    assert result > previously_max
    return result


# def update_fileset(source_io: BinaryIO,
#                    fpk: FilesetPrivateKey,
#                    target_dir: Path):
#     # we will remove and add some surrogates, and also remove old real file
#     # add new real file. We will do this in random order, so as not to give
#     # out which files are real and which are surrogates
#
#     source_file_size = source_io.seek(0, io.SEEK_END)
#     source_io.seek(0, io.SEEK_SET)
#
#     all_file_sizes = dir_to_file_sizes(target_dir)
#
#     def fake_size():
#         result = random_size_like_others_in_dir(all_file_sizes)
#         if result is None:
#             result = random_size_like_file(source_file_size)
#         assert result >= MIN_DATA_FILE_SIZE
#         return result
#
#     tasks: List[Task] = list()
#
#     fileset = NameGroup(target_dir, fpk)
#
#     new_data_version = increased_data_version(fileset)
#
#     max_to_delete = 4
#     max_to_fake = max_to_delete - 1  # +1 real file will be written
#
#     # we will remove random number of files
#     if len(fileset.all_files) > 0:
#         max_to_delete = min(max_to_delete, len(fileset.all_files))
#         num_to_delete = random.randint(1, max_to_delete)
#         files_to_delete = random.sample(fileset.all_files, num_to_delete)
#         for f in files_to_delete:
#             tasks.append(DeleteTask(
#                 path=f,
#                 is_real=(f == fileset.real_file)))
#
#     for _ in range(random.randint(1, max_to_fake)):
#         tasks.append(WriteFakeTask(fake_size()))
#     tasks.append(WriteRealTask())
#
#     _shuffle_so_creating_before_deleting(tasks)
#
#     real_written = False
#
#     for task in tasks:
#         if isinstance(task, WriteRealTask):
#             encrypt_io_to_dir(source_io, fpk, target_dir, new_data_version)
#             real_written = True
#         elif isinstance(task, WriteFakeTask):
#             create_fake(fpk,
#                         target_dir=target_dir,
#                         target_size=task.size)
#         elif isinstance(task, DeleteTask):
#             assert real_written or not task.was_fresh_data
#             os.remove(str(task.file))
#         else:
#             raise TypeError


def update_namegroup_old(source_io: BinaryIO,
                         fpk: CodenameKey,
                         target_dir: Path):
    # we will remove and add some surrogates, and also remove old real file
    # add new real file. We will do this in random order, so as not to give
    # out which files are real and which are surrogates

    source_file_size = source_io.seek(0, io.SEEK_END)
    source_io.seek(0, io.SEEK_SET)

    all_file_sizes = dir_to_file_sizes(target_dir)

    def fake_size():
        result = random_size_like_others_in_dir(all_file_sizes)
        if result is None:
            result = random_size_like_file(source_file_size)
        assert result >= MIN_DATA_FILE_SIZE
        return result

    tasks: List[Task] = list()

    with NewNameGroup(target_dir, fpk) as name_group:

        new_data_version = increased_data_version_old(name_group)

        max_to_delete = 4
        max_to_fake = max_to_delete - 1  # +1 real file will be written

        # removable_files = name_group.fake_files + name_group.obsolete_files

        # we will remove random number of files
        if len(name_group.files) > 0:
            max_to_delete = min(max_to_delete, len(name_group.files))
            num_to_delete = random.randint(1, max_to_delete)
            files_to_delete = random.sample(name_group.files, num_to_delete)
            for f in files_to_delete:
                dt = DeleteTask(f.path, was_the_content=f.is_fresh_data)
                if f.is_fresh_data:
                    dt.sorting = 1  # later
                tasks.append(dt)

        for _ in range(random.randint(1, max_to_fake)):
            tasks.append(WriteFakeTask(fake_size()))

        wrt = WriteRealTask()
        wrt.sorting = -1  # earlier
        tasks.append(wrt)

    # closes the NameGroup and all the open-for-reading files.
    # Now we can delete any file without PermissionError

    random.shuffle(tasks)
    tasks.sort(key=lambda t: t.sorting)

    new_content_written = False

    for task in tasks:
        if isinstance(task, WriteRealTask):
            encrypt_to_files(fpk, source_io, target_dir, new_data_version)
            new_content_written = True
        elif isinstance(task, WriteFakeTask):
            create_fake(fpk,
                        target_dir=target_dir,
                        target_size=task.size)
        elif isinstance(task, DeleteTask):
            assert new_content_written or not task.was_the_content
            os.remove(str(task.file))
        else:
            raise TypeError

# def update_fileset_old(source_file: Path, fpk: FilesetPrivateKey,
#                        target_dir: Path):
#     # todo remove from code
#     with source_file.open('rb') as f:
#         update_fileset(f, fpk, target_dir)
