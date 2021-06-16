# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import time

import click

from codn._common import KEY_SALT_SIZE
from codn._main import Main
from codn.a_base._10_kdf import CodenameKey
from codn.a_utils.randoms import get_noncrypt_random_bytes


@click.command(hidden=True)
def bench():
    """Measures the KDF speed: the private key computation time."""
    a = []
    random_salt = get_noncrypt_random_bytes(KEY_SALT_SIZE)
    for i in range(4):
        t = time.monotonic()
        CodenameKey(str(i), random_salt)
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
              prompt='Name',
              hide_input=True,
              confirmation_prompt="Repeat")
@click.option('-v', '--value', prompt='Entry value')
def set_cmd(name: str, value: str):
    """Adds or replaces item as a string."""
    Main().set(name, value)


@click.command()
@click.option('-n', '--name',
              prompt='Codename',
              hide_input=True)
def get(name: str):
    """Gets item data as string prints value to stdout."""
    s = Main().get(name)
    print(s)


@click.command()
@click.option('-n', '--name',
              prompt='Codename',
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


from ._constants import __version__, __copyright__


@click.group()
@click.version_option(message=f'%(prog)s {__version__}\n(c) {__copyright__}')
def codn_cli():
    """
    See https://github.com/rtmigo/ksf_py#readme
    """
    pass


codn_cli.add_command(bench)
codn_cli.add_command(config)
codn_cli.add_command(set_cmd)
codn_cli.add_command(get)
codn_cli.add_command(eval)
codn_cli.add_command(clear)

if __name__ == '__main__':
    # config = Config()
    codn_cli()
