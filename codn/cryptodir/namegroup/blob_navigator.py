from typing import List, BinaryIO, Optional

from codn.container import BlobsIndexedReader
from codn.cryptodir._10_kdf import FilesetPrivateKey
from codn.cryptodir.namegroup.encdec._25_encdec_part import DecryptedIO


class NameGroupBlob:
    def __init__(self, idx: int, dio: DecryptedIO):
        self.idx = idx
        self.dio = dio
        self.is_fresh_data = False
        self.is_fake = False


class BlobNameGroup:
    def __init__(self, blobs: BlobsIndexedReader, fpk: FilesetPrivateKey):
        self.blobs = blobs
        self.fpk = fpk
        self._streams: List[BinaryIO] = []

        self._fresh_content_dios: Optional[List[DecryptedIO]] = None

    def __enter__(self):
        self.files: List[NameGroupBlob] = []

        for idx in range(len(self.blobs)):
            input_io = self.blobs.io(idx)
            dio = DecryptedIO(self.fpk, input_io)
            if not dio.belongs_to_namegroup:
                continue
            assert dio.belongs_to_namegroup
            gf = NameGroupBlob(idx, dio)
            self.files.append(gf)

        # marking fakes
        for f in self.files:
            if not f.dio.contains_data:
                f.is_fake = True
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
        # for gf in all_content_files:
        #     if not gf.is_fresh_data:
        #         gf.dio.source.close()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # for stream in self._streams:
        #     stream.close()
        self._streams = None

    @property
    def fresh_content_files(self) -> List[DecryptedIO]:
        if self._fresh_content_dios is None:
            self._fresh_content_dios = [gf.dio for gf in self.files
                                        if gf.is_fresh_data]
        return self._fresh_content_dios
