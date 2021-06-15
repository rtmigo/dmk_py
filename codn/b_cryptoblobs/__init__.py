# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

"""
This package contains code that encrypts and decrypts blobs. This code doesn't
know where these blobs come from or where they are stored.
"""

from ._20_encdec_part import DecryptedIO
from ._30_encdec_multipart import MultipartEncryptor, decrypt_from_dios
