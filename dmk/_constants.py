# SPDX-FileCopyrightText: (c) 2021-2023 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import sys

__version__ = "0.7.1"
__copyright__ = "2021-2023 Artёm iG <github.com/rtmigo>"

__build_timestamp__ = "2023-09-14 20:32:58"

# replacing unicode chars with ASCII for non-unicode interpreters
# (such as Windows PowerShell)
try:
    __copyright__.encode(sys.stdout.encoding)
except UnicodeEncodeError:
    __copyright__ = __copyright__.replace("ё", "e")
