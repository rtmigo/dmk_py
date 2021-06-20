# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import os
from io import BytesIO
from math import ceil
from pathlib import Path

import click.exceptions

from dmk._common import CLUSTER_SIZE
from dmk._the_file import TheFile
from dmk.a_utils.randoms import random_codename_fullsize


def _confirm(txt: str):
    ans = input(f"{txt} (y/N) ")
    return ans and ans.upper().startswith('Y')


class ItemNotFoundExit(SystemExit):
    def __init__(self):
        super().__init__("Item not found.")

    pass


def parse_n_units(txt: str) -> int:
    if len(txt) <= 0:
        raise ValueError
    txt = txt
    if txt[-1].isdigit():
        return int(txt)
    if len(txt) <= 1:
        raise ValueError

    num = int(txt[:-1])
    suffix = txt[-1:].lower()

    if suffix == "k":
        return num * 1024
    elif suffix == "m":
        return num * 1024 * 1024
    else:
        raise ValueError(f"Unknown suffix: {suffix}")


class Main:
    def __init__(self, storage_file: Path):

        str_path = str(storage_file)
        str_path = os.path.expanduser(str_path)
        str_path = os.path.expandvars(str_path)

        self.file_path = Path(str_path)

    def fake(self, size_and_units: str):

        try:
            size_bytes = parse_n_units(size_and_units)
        except ValueError:
            raise click.exceptions.BadParameter(size_and_units)

        if size_bytes <= 0:
            raise click.exceptions.BadParameter(size_and_units)

        crd = TheFile(self.file_path)
        blocks_num = ceil(size_bytes / CLUSTER_SIZE)
        print(f"Adding {blocks_num} block(s) sized {CLUSTER_SIZE:,} B each")
        print(f"Old file size: {crd.path.stat().st_size:,} B")
        crd.add_fakes(random_codename_fullsize(), blocks_num)
        print(f"New file size: {crd.path.stat().st_size:,} B")

    def set_text(self, name: str, value: str):
        crd = TheFile(self.file_path)
        with BytesIO(value.encode('utf-8')) as source_io:
            crd.set_from_io(name, source_io)

    def set_file(self, name: str, file: str):
        crd = TheFile(self.file_path)
        with Path(file).open('rb') as  source_io:
            crd.set_from_io(name, source_io)

    def get_text(self, name: str):
        crd = TheFile(self.file_path)
        decrypted_bytes = crd.get_bytes(name)
        if decrypted_bytes is None:
            raise ItemNotFoundExit
        return decrypted_bytes.decode('utf-8')

    def get_file(self, name: str, file: str):
        crd = TheFile(self.file_path)
        fpath = Path(file)
        if fpath.exists():
            raise FileExistsError  # todo ask

        data = crd.get_bytes(name)  # todo get io, chunks?
        if data is None:
            raise Exception("No data!")  # todo

        with Path(file).open('wb') as outio_io:
            outio_io.write(data)

    def eval(self, name: str):
        # todo test
        crd = TheFile(self.file_path)
        decrypted_bytes = crd.get_bytes(name)
        if decrypted_bytes is None:
            raise ItemNotFoundExit
        cmd = decrypted_bytes.decode('utf-8')

        exit(os.system(cmd))
