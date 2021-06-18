# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import time
from pathlib import Path
from typing import List

import click

from dmk._common import KEY_SALT_SIZE
from dmk._main import Main
from dmk.a_base._10_kdf import CodenameKey
from dmk.a_utils.randoms import get_noncrypt_random_bytes

CODN_FILE_ENVNAME = 'DMK_VAULT_FILE'
DEFAULT_STORAGE_FILE = "~/vault.dmk"


def validate_filename(ctx, param, value):
    if value is None or not value.strip():
        raise click.BadParameter("Storage filename must be specified")

    # value = os.path.expandvars(value)
    # value = os.path.expanduser(value)

    return value
    # if isinstance(value, tuple):
    #     return value
    #
    # try:
    #     rolls, _, dice = value.partition("d")
    #     return int(dice), int(rolls)
    # except ValueError:
    #     raise click.BadParameter("format must be 'NdM'")


# def env_get_file() -> str:
#    return os.environ.get('CODN_STORAGE_FILE')


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


@click.command(name='set')
@click.option('-v', '--vault',
              envvar=CODN_FILE_ENVNAME,
              default=DEFAULT_STORAGE_FILE,
              callback=validate_filename)
@click.option('-e',
              '--entry',
              'codename',
              prompt='Entry secret name',
              hide_input=True,
              confirmation_prompt="Repeat")
@click.option('-t', '--text', default=None)
@click.argument('file', nargs=-1, type=Path)
def set_cmd(vault: str, codename: str, text: str, file: List[Path]):
    """Sets entry content."""

    if len(file) >= 1:
        if len(file) >= 2:
            raise click.BadParameter("Exactly one file expected")
        Main(vault).set_file(codename, str(file[0]))  # todo not str
    else:
        if text is None:
            text = click.prompt('Text')
        Main(vault).set_text(codename, text)


# @click.command(name='print')
# @click.option('-v', '--vault', envvar=CODN_FILE_ENVNAME,
#               callback=validate_filename)
# @click.option('-e',
#               '--entry',
#               'codename',
#               prompt='Codename',
#               hide_input=True)
# def print_cmd(storage: str, codename: str):
#     """Prints entry content to stdout."""
#     s = Main(storage).get_text(codename)
#     print(s)


@click.command(name='get')
@click.option('-v', '--vault',
              envvar=CODN_FILE_ENVNAME,
              default=DEFAULT_STORAGE_FILE,
              callback=validate_filename)
@click.option('-e',
              '--entry',
              'codename',
              prompt='Name',
              hide_input=True)
@click.argument('file', nargs=-1, type=Path)
def getf_cmd(vault: str, codename: str, file: List[Path]):
    """Writes entry content to a binary file."""
    if len(file)>0:
        Main(vault).get_file(codename, str(file[0]))
    else:
        s = Main(vault).get_text(codename)
        print(s)


@click.command()
@click.option('-v', '--vault',
              envvar=CODN_FILE_ENVNAME,
              callback=validate_filename)
@click.option('-e',
              '--entry',
              'codename',
              prompt='Codename',
              hide_input=True)
def eval(storage: str, codename: str):
    """Gets item data as text and executes it as shell command."""
    Main(storage).eval(codename)


from ._constants import __version__, __copyright__


@click.group()
@click.version_option(message=f'%(prog)s {__version__}\n(c) {__copyright__}')
def dmk_cli():
    """
    See https://github.com/rtmigo/dmk_py#readme
    """
    pass

# todo file command


dmk_cli.add_command(bench)

#dmk_cli.add_command(print_cmd)

dmk_cli.add_command(getf_cmd)
dmk_cli.add_command(eval)
dmk_cli.add_command(set_cmd)

if __name__ == '__main__':
    # config = Config()
    dmk_cli()