# SPDX-FileCopyrightText: (c) 2021-2022 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import os
import subprocess
from math import ceil
from pathlib import Path
from tempfile import TemporaryDirectory

import click.exceptions

from dmk._common import CLUSTER_SIZE
from dmk._vault_file import DmkFile
from dmk._vault_file_ops import set_text, get_text, set_file, get_file, \
    DmkKeyError
from dmk.a_utils.randoms import random_codename_fullsize, random_basename


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

        crd = DmkFile(self.file_path)
        blocks_num = ceil(size_bytes / CLUSTER_SIZE)
        print(f"Adding {blocks_num} block(s) sized {CLUSTER_SIZE:,} B each")
        print(f"Old file size: {crd.path.stat().st_size:,} B")
        crd.add_fakes(random_codename_fullsize(), blocks_num)
        print(f"New file size: {crd.path.stat().st_size:,} B")

    def set_text(self, name: str, value: str):
        set_text(DmkFile(self.file_path), name, value)

    def set_file(self, name: str, file: str):
        set_file(dmk_file=DmkFile(self.file_path),
                 codename=name,
                 source_file=Path(file))

    def get_text(self, name: str):
        try:
            return get_text(
                dmk_file=DmkFile(self.file_path),
                codename=name)
        except DmkKeyError:
            raise ItemNotFoundExit

    def get_file(self, name: str, file: str):
        try:
            get_file(
                dmk_file=DmkFile(self.file_path),
                codename=name,
                target_file=Path(file))
        except DmkKeyError:
            raise ItemNotFoundExit

    def eval(self, name: str) -> int:
        # todo test
        crd = DmkFile(self.file_path)
        decrypted_bytes = crd.get_bytes(name)
        if decrypted_bytes is None:
            raise ItemNotFoundExit
        cmd = decrypted_bytes.decode('utf-8')
        return os.system(cmd)

    def open(self, codename: str):
        # todo how to unit test?!..
        crd = DmkFile(self.file_path)
        decrypted_bytes = crd.get_bytes(codename)
        if decrypted_bytes is None:
            raise ItemNotFoundExit
        with TemporaryDirectory() as td:
            fn = Path(td) / random_basename()
            fn.write_bytes(decrypted_bytes)
            args = ['open', '-W', str(fn)]
            lmd = fn.stat().st_mtime
            # print(args)
            print("Running the 'open' and waiting for app to close")
            result = subprocess.run(args, shell=False)
            if result.returncode == 0:
                if fn.stat().st_mtime == lmd:
                    print("The file was not changed")
                else:
                    print("Updating the entry...")
                    with fn.open('rb') as updated_file:
                        crd.set_from_io(codename, updated_file)
                    print("Done!")
            else:
                click.echo("'open' returned non-zero exit code. "
                           "Entry not updated.")
