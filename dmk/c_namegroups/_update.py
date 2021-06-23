# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import random
from typing import List, BinaryIO, Set, NamedTuple

from dmk.a_base import CodenameKey
from dmk.b_cryptoblobs import MultipartEncryptor
from dmk.b_storage_file import BlocksIndexedReader, BlocksSequentialWriter
from dmk.c_namegroups._fakes import create_fake_bytes
from dmk.c_namegroups._namegroup import NameGroup


def increased_data_version(namegroup: NameGroup) -> int:

    # todo when we somehow reached upper limit, remove all blocks from
    # the namegroup, start again

    # MAX_INT64 = 0x7FFFFFFFFFFFFFFF
    MAX_UINT48 = 0xFFFFFFFFFFFF
    if len(namegroup.all_content_versions) <= 0:
        return random.randint(1, 99999)

    previously_max = max(namegroup.all_content_versions)

    assert previously_max >= 1
    result = previously_max + random.randint(1, 100)
    if result > MAX_UINT48:
        # ((2**48)-99999) / 100 = 2 814 749 766 106.57 (two trillions)
        # this will never happen
        raise ValueError(f"new_data_version={result} "
                         f"cannot be saved as UINT48")
    assert result > previously_max
    return result


def get_stream_size(stream: BinaryIO) -> int:
    pos = stream.seek(0, io.SEEK_CUR)
    result = stream.seek(0, io.SEEK_END)
    stream.seek(pos, io.SEEK_SET)
    return result


def remove_random_items(source: Set[int],
                        min_to_delete=1,
                        max_to_delete=5) -> Set[int]:
    if len(source) < min_to_delete:
        raise ValueError("List is too small")

    max_to_delete = min(max_to_delete, len(source))
    num_to_delete = random.randint(min_to_delete, max_to_delete)
    indexes_to_delete = random.sample(list(source), num_to_delete)
    result = source - set(indexes_to_delete)
    assert len(result) < len(source) or min_to_delete == 0
    return result


class TaskKeep(NamedTuple):
    old_block_idx: int


class TaskFake:
    pass


class TaskEncrypt(NamedTuple):
    part_idx: int


def copy_block(old_blobs: BlocksIndexedReader,
               old_block_idx: int,
               new_blobs: BlocksSequentialWriter):
    old_buf = old_blobs.io(old_block_idx).read()
    # todo don't recompute crc32
    new_blobs.write_bytes(old_buf)


def add_fake(cdk: CodenameKey, new_blobs: BlocksSequentialWriter):
    new_blobs.write_bytes(create_fake_bytes(cdk))


def add_fakes(cdk: CodenameKey,
              old_blobs: BlocksIndexedReader,
              new_blobs: BlocksSequentialWriter,
              fakes_to_add_num: int):
    # todo test
    tasks: List[object] = list()
    for old_idx in range(len(old_blobs)):
        tasks.append(TaskKeep(old_idx))
    for _ in range(fakes_to_add_num):
        tasks.append(TaskFake())

    for task in tasks:
        if isinstance(task, TaskFake):
            add_fake(cdk, new_blobs)
        elif isinstance(task, TaskKeep):
            copy_block(old_blobs, task.old_block_idx, new_blobs)
        else:
            raise TypeError
    new_blobs.write_tail()  # todo test


class FakeDeltas:
    def __init__(self, old_blocks_num: int, adding_blocks: int):
        max_loss_percent = 0.05
        min_delta = 3

        self.max_loss = round(old_blocks_num * max_loss_percent)
        self.max_loss = max(self.max_loss, min_delta)
        self.max_loss = min(self.max_loss, old_blocks_num)
        #

        # было x0 блоков.
        # Если потеряем все блоки, станет x1 = x0-max_loss.
        # Чтобы восстановиться нужно будет вернуть в точности max_loss
        # блоков. Относительный прирост потребуется
        #   rel_recover = max_loss/x1 = max_loss/(x0-max_loss)
        # Мы не знаем, мы теряли в прошлый раз блоки или приобретали.
        # Просто нужно симметрично восстанавливающее значение max_recover.
        # Поэтому считаем его так, словно уже потеряли блоки в прошлый раз.

        divisor = (old_blocks_num - self.max_loss)
        if divisor >= 1:
            rel_recover = self.max_loss / divisor
            self.max_add = max(min_delta, round(old_blocks_num * rel_recover))
        else:
            self.max_add = min_delta

        self.max_loss = max(self.max_loss, adding_blocks)
        self.max_loss = min(self.max_loss, old_blocks_num)

        assert self.max_add >= 1
        assert self.max_loss >= 0
        assert self.max_loss <= old_blocks_num


def update_namegroup_b(cdk: CodenameKey,
                       new_content_io: BinaryIO,
                       old_blobs: BlocksIndexedReader,
                       new_blobs: BlocksSequentialWriter):
    name_group = NameGroup(old_blobs, cdk)

    encryptor = MultipartEncryptor(cdk, new_content_io,
                                   increased_data_version(name_group))

    all_blob_indexes = set(range(len(old_blobs)))
    our_old_blob_indexes = set(e.idx for e in name_group.items)
    assert all(idx in all_blob_indexes for idx in our_old_blob_indexes)

    # All our_blob_indexes refer to the current codename. But there is no
    # longer any valuable data among them. There are only fake or outdated
    # ones. Therefore, we can safely delete them.

    fake_deltas = FakeDeltas(
        old_blocks_num=len(old_blobs),
        adding_blocks=len(encryptor.part_sizes)
    )

    if len(our_old_blob_indexes) >= 1:
        our_new_blob_indexes = remove_random_items(
            our_old_blob_indexes,
            min_to_delete=1,
            max_to_delete=fake_deltas.max_loss)
    else:
        assert len(our_old_blob_indexes) == 0
        our_new_blob_indexes = set()

    tasks: List[object] = list()

    indexes_to_keep = set(all_blob_indexes)
    indexes_to_keep -= our_old_blob_indexes
    indexes_to_keep.update(our_new_blob_indexes)

    for idx in indexes_to_keep:
        tasks.append(TaskKeep(idx))

    for part_idx in range(len(encryptor.part_sizes)):
        tasks.append(TaskEncrypt(part_idx))

    for idx in range(random.randint(1, fake_deltas.max_add)):
        tasks.append(TaskFake())

    assert sum(1 for t in tasks if isinstance(t, TaskFake)) >= 1

    # in random order: copying old blocks, writing fake blocks,
    # adding new content
    random.shuffle(tasks)
    for task in tasks:
        if isinstance(task, TaskFake):
            add_fake(cdk, new_blobs)
        elif isinstance(task, TaskEncrypt):
            assert not encryptor.all_encrypted
            with io.BytesIO() as temp_io:
                encryptor.encrypt(part_idx=task.part_idx,
                                  target_io=temp_io)
                temp_io.seek(0, io.SEEK_SET)
                new_blobs.write_bytes(temp_io.read())
        elif isinstance(task, TaskKeep):
            copy_block(old_blobs, task.old_block_idx, new_blobs)
        else:
            raise TypeError
    new_blobs.write_tail()
    assert encryptor.all_encrypted
