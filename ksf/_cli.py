# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import time

import click

from ksf._common import PK_SALT_SIZE
from ksf.utils.randoms import get_noncrypt_random_bytes
from ksf.cryptodir._10_kdf import FilesetPrivateKey


@click.command()
def bench():
    """Measures the KDF speed: the private key computation time."""
    a = []
    random_salt = get_noncrypt_random_bytes(PK_SALT_SIZE)
    for i in range(4):
        t = time.monotonic()
        FilesetPrivateKey(str(i), random_salt)
        d = time.monotonic() - t
        a.append(d)
        print(f'{i + 1} {d:.3f} sec')
    print(f'Mean {sum(a) / len(a):.3f} sec')


@click.group()
def cli():
    pass


cli.add_command(bench)

if __name__ == '__main__':
    # config = Config()
    cli()
