# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
from pathlib import Path

from Crypto.Random import get_random_bytes

from codn._common import MIN_DATA_FILE_SIZE, looks_like_random_basename, \
    unique_filename
from codn.cryptodir._10_kdf import FilesetPrivateKey
from codn.cryptodir.namegroup.imprint import Imprint
from codn.utils.dirty_file import WritingToTempFile
from codn.utils.randoms import MICROSECONDS_PER_DAY, set_random_last_modified

assert datetime.timedelta(microseconds=MICROSECONDS_PER_DAY) \
           .total_seconds() == 60 * 60 * 24


def create_fake(fpk: FilesetPrivateKey, target_size: int, target_dir: Path):
    """Creates a fake file.

    WRONG DOC (NEEDS REWRITE)

    The file name of the will be the correct imprint from the [fpk]. But the
    file content is random, so the file header is not a correct imprint
    from [fpk].

    Knowing the name we can easily find all the fakes and real files
    for the name. We can differentiate the real file from the surrogate
    by the header (only for real files it contains the imprint).

    ref_size: The size of the real file. The surrogate file will have
    similar size but randomized.
    """

    if target_size < MIN_DATA_FILE_SIZE:
        raise ValueError

    target_file = unique_filename(target_dir) #target_dir / Imprint(fpk).as_str  # todo random fn
    assert looks_like_random_basename(target_file.name)
    assert not target_file.exists()
    #if target_file.exists():
    #    raise HashCollision
    # size = randomized_size(target_size) # todo
    # non_matching_header = get_random_bytes(Imprint.FULL_LEN)
    # if pk_matches_imprint_bytes(fpk, non_matching_header):
    #     raise HashCollision


    with WritingToTempFile(target_file) as wtf:
        with wtf.dirty.open('wb') as outp:
            outp.write(Imprint(fpk).as_bytes)  # imprint_a
            outp.write(get_random_bytes(target_size-Imprint.FULL_LEN))  # todo chunks?
        set_random_last_modified(wtf.dirty)
        wtf.replace()

    return target_file
