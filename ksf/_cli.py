import time

import click

from ksf._00_common import PK_SALT_SIZE
from ksf._00_randoms import get_noncrypt_random_bytes
from ksf._10_kdf import FilesetPrivateKey


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
