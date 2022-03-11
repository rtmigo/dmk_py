# SPDX-FileCopyrightText: (c) 2022 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

from io import BytesIO
from pathlib import Path

from dmk import DmkFile


def set_text(dmk_file: DmkFile,
             codename: str,
             source_text: str):
    with BytesIO(source_text.encode('utf-8')) as source_io:
        dmk_file.set_from_io(codename, source_io)


def get_text(dmk_file: DmkFile, codename: str) -> str:
    decrypted_bytes = dmk_file.get_bytes(codename)
    if decrypted_bytes is None:
        raise DmkKeyError
    return decrypted_bytes.decode('utf-8')


def set_file(dmk_file: DmkFile,
             codename: str,
             source_file: Path):
    with Path(source_file).open('rb') as source_io:
        dmk_file.set_from_io(codename, source_io)


def get_file(dmk_file: DmkFile,
             codename: str,
             target_file: Path):
    if target_file.exists():
        raise FileExistsError

    decrypted_bytes = dmk_file.get_bytes(codename)  # todo get io, chunks?
    if decrypted_bytes is None:
        raise DmkKeyError

    with Path(target_file).open('wb') as target_io:
        target_io.write(decrypted_bytes)


class DmkKeyError(KeyError):
    pass