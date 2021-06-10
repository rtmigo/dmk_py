# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import time

import click

from ksf._common import PK_SALT_SIZE
from ksf._main import Main
from ksf.cryptodir._10_kdf import FilesetPrivateKey
from ksf.utils.randoms import get_noncrypt_random_bytes


@click.command(hidden=True)
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


@click.command()
def config():
    """Opens config file in nano for editing."""
    Main().edit_config()


@click.command(name='set')
@click.option('-n',
              '--name',
              prompt='Secret name of the item',
              hide_input=True,
              confirmation_prompt=True)
@click.option('-v', '--value', prompt='The value')
def set_cmd(name: str, value: str):
    """Adds or replaces item as a string."""
    Main().set(name, value)


@click.command()
@click.option('-n', '--name',
              prompt='Secret name of the item',
              hide_input=True)
def get(name: str):
    """Gets item data as string prints value to stdout."""
    s = Main().get(name)
    print(s)


@click.command()
@click.option('-n', '--name',
              prompt='Secret name of the item',
              hide_input=True)
def eval(name: str):
    """Gets item data as string and executes it as shell command."""
    Main().eval(name)


@click.command()
def clear():
    """Deletes the data directory with all items."""
    if click.confirm(f'Are you sure want to delete {Main().config.data_dir}?'):
        Main().clear()
        print("Cleared")
    else:
        print("Canceled")


@click.group()
def cli():
    pass


cli.add_command(bench)
cli.add_command(config)
cli.add_command(set_cmd)
cli.add_command(get)
cli.add_command(eval)
cli.add_command(clear)

if __name__ == '__main__':
    # config = Config()
    cli()
