import io
import random
from typing import List, BinaryIO, Set

from codn.container import BlobsIndexedReader, BlobsSequentialWriter
from codn.cryptodir._10_kdf import CodenameKey
from codn.cryptodir.namegroup.blob_navigator import NameGroup
from codn.cryptodir.namegroup.encdec import MultipartEncryptor
from codn.cryptodir.namegroup.fakes import create_fake_bytes
from codn.cryptodir.namegroup.random_sizes import \
    random_size_like_others_in_dir, random_size_like_file


def increased_data_version(namegroup: NameGroup) -> int:
    MAX_INT64 = 0x7FFFFFFFFFFFFFFF
    if len(namegroup.all_content_versions) <= 0:
        return random.randint(1, 999999)

    previously_max = max(namegroup.all_content_versions)

    assert previously_max >= 1
    result = previously_max + random.randint(1, 999)
    if result > MAX_INT64:
        # this will never happen
        raise ValueError(f"new_data_version={result} "
                         f"cannot be saved as INT64")
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
    indexes_to_delete = random.sample(source, num_to_delete)
    result = source - set(indexes_to_delete)
    assert len(result) < len(source) or min_to_delete == 0
    return result


def update_namegroup_b(cdk: CodenameKey,
                       new_content_io: BinaryIO,
                       old_blobs: BlobsIndexedReader,
                       new_blobs: BlobsSequentialWriter):
    # we will remove and add some surrogates, and also remove old real file
    # add new real file. We will do this in random order, so as not to give
    # out which files are real and which are surrogates

    #old_file_sizes = [frio.length for frio in iter(old_blobs)]

    # def fake_size():
    #     result = random_size_like_others_in_dir(old_file_sizes)
    #     if result is None:
    #         result = random_size_like_file(get_stream_size(new_content_io))
    #     return result

    name_group = NameGroup(old_blobs, cdk)

    all_blob_indexes = set(range(len(old_blobs)))
    our_old_blob_indexes = set(e.idx for e in name_group.items)
    # other_blob_indexes = all_blob_indexes-our_blob_indexes
    assert all(idx in all_blob_indexes for idx in our_old_blob_indexes)

    # All our_blob_indexes refer to the current codename. But there is no
    # longer any valuable data among them. There are only fake or outdated
    # ones. Therefore, we can safely delete them.

    MAX_TO_DELETE = MAX_TO_FAKE = 5  # todo avoid constants

    if len(our_old_blob_indexes) >= 1:
        our_new_blob_indexes = remove_random_items(
            our_old_blob_indexes,
            min_to_delete=1,
            max_to_delete=MAX_TO_DELETE)
    else:
        assert len(our_old_blob_indexes) == 0
        our_new_blob_indexes = set()

    indexes_to_keep = set(all_blob_indexes)
    indexes_to_keep -= our_old_blob_indexes
    indexes_to_keep.update(our_new_blob_indexes)

    # First of all, we write to the new file the blobs that we decided to
    # keep. We write them in the most predictable order, making it easier for
    # services like Dropbox to synchronize unchanged data. Placing previously
    # existing blobs in a new random order would add nothing to the privacy.

    for idx in sorted(indexes_to_keep):
        old_buf = old_blobs.io(idx).read()
        # todo don't recompute crc32
        new_blobs.write_bytes(old_buf)

    # In this list, non-negative values correspond to parts of the new content,
    # and negative values correspond to fakes.
    tasks: List[int] = list()

    FAKE_TASK = -1

    me = MultipartEncryptor(cdk, new_content_io, increased_data_version(name_group))
    for part_idx in range(len(me.part_sizes)):
        assert part_idx != FAKE_TASK
        tasks.append(part_idx)

    for idx in range(random.randint(1, MAX_TO_FAKE)):
        tasks.append(FAKE_TASK)

    assert sum(1 for t in tasks if t == FAKE_TASK) >= 1

    # writing fakes and new content in random order
    random.shuffle(tasks)
    for task in tasks:
        if task == FAKE_TASK:
            new_blobs.write_bytes(create_fake_bytes(cdk))
        else:
            assert task != FAKE_TASK
            assert not me.all_encrypted
            with io.BytesIO() as temp_io:
                me.encrypt(part_idx=task,
                           target_io=temp_io)
                temp_io.seek(0, io.SEEK_SET)
                new_blobs.write_bytes(temp_io.read())
    assert me.all_encrypted
