# SPDX-FileCopyrightText: (c) 2022 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

from io import BytesIO
from pathlib import Path

from dmk import DmkFile
from dmk._main import DmkKeyError


def set_text(dmk_file: DmkFile,
             secret_key: str,
             source_text: str):
    # todo test
    with BytesIO(source_text.encode('utf-8')) as source_io:
        dmk_file.set_from_io(secret_key, source_io)


def get_text(dmk_file: DmkFile, secret_key: str) -> str:
    # todo test
    decrypted_bytes = dmk_file.get_bytes(secret_key)
    if decrypted_bytes is None:
        raise DmkKeyError
    return decrypted_bytes.decode('utf-8')


def set_file(dmk_file: DmkFile,
             secret_key: str,
             source_file: Path):
    # todo test
    with Path(source_file).open('rb') as source_io:
        dmk_file.set_from_io(secret_key, source_io)


def get_file(dmk_file: DmkFile,
             secret_key: str,
             target_file: Path):
    # todo test
    if target_file.exists():
        raise FileExistsError

    decrypted_bytes = dmk_file.get_bytes(secret_key)  # todo get io, chunks?
    if decrypted_bytes is None:
        raise DmkKeyError

    with Path(target_file).open('wb') as target_io:
        target_io.write(decrypted_bytes)