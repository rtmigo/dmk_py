# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import time
from pathlib import Path
from typing import List, Optional

import click

from dmk._common import KEY_SALT_SIZE
from dmk._main import Main
from dmk.a_base._10_kdf import CodenameKey
from dmk.a_utils.randoms import get_noncrypt_random_bytes
from ._constants import __version__

VAULT_FILE_ENVNAME = 'DMK_VAULT_FILE'
DEFAULT_STORAGE_FILE = "~/vault.dmk"

CODENAME_SHORT_ARG = "-e"
CODENAME_LONG_ARG = "--entry"
CODENAME_PROMT = "Secret name"
CODENAME_PROMT_CONFIRMATION = "Secret name (again)"

VAULT_ARG_SHORT = "-v"
VAULT_ARG_LONG = "--vault"


# def validate_filename(ctx, param, value):
#     if value is None or not value.strip():
#         raise click.BadParameter("Storage filename must be specified")
#     return value


class Globals:
    main: Optional[Main]

    @classmethod
    def the_main(cls) -> Main:
        # for mypy
        if cls.main is None:
            raise TypeError
        return cls.main
    # vault_arg: Optional[str] = None


@click.group(invoke_without_command=True)
@click.option(VAULT_ARG_SHORT, VAULT_ARG_LONG,
              envvar=VAULT_FILE_ENVNAME,
              default=DEFAULT_STORAGE_FILE,
              type=Path)
@click.pass_context
def dmk_cli(ctx, vault: Path):
    Globals.main = Main(vault)  # todo
    if not ctx.invoked_subcommand:
        click.echo(f"DMK: Dark Matter Keeper v{__version__} (c) 2021 Artem IG")
        click.echo()
        click.echo("See https://github.com/rtmigo/dmk_py#readme")
        click.echo()
        click.echo(ctx.get_help())
        ctx.exit(2)


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


codename_read_option = click.option(CODENAME_SHORT_ARG, CODENAME_LONG_ARG,
                                    'codename',
                                    prompt=CODENAME_PROMT,
                                    hide_input=True)

codename_confirm_option = click.option(CODENAME_SHORT_ARG, CODENAME_LONG_ARG,
                                       'codename',
                                       prompt=CODENAME_PROMT,
                                       hide_input=True,
                                       confirmation_prompt=CODENAME_PROMT_CONFIRMATION)


@dmk_cli.command(name='set')
# @vault_option
@codename_confirm_option
@click.option('-t', '--text', default=None)
@click.argument('file', nargs=-1, type=Path)
def set_cmd(codename: str, text: str, file: List[Path]):
    """Encrypts text or file to an entry."""

    if len(file) >= 1:
        if len(file) >= 2:
            raise click.BadParameter("Exactly one file expected")
        Globals.the_main().set_file(codename, str(file[0]))  # todo not str
    else:
        if text is None:
            text = click.prompt('Text')
        Globals.the_main().set_text(codename, text)


@dmk_cli.command(name='get')
# @vault_option
@codename_read_option
@click.argument('file', nargs=-1, type=Path)
def getf_cmd(codename: str, file: List[Path]):
    """Decrypts an entry and prints as text, or writes to file."""
    if len(file) > 0:
        Globals.the_main().get_file(codename, str(file[0]))
    else:
        s = Globals.the_main().get_text(codename)
        print(s)


@dmk_cli.command(name='open',
                 hidden=True  # not unit-tested
                 )
@codename_read_option
def open_cmd(codename: str):
    """Saves decrypted entry to file, opens it with 'open', then encrypts
    again."""
    Globals.the_main().open(codename)


@dmk_cli.command(name='dummy')
@click.argument('size', type=str)
def fake_cmd(size: str):
    """Adds dummy data to the vault."""
    Globals.the_main().fake(size)


@dmk_cli.command()
# @vault_option
@codename_read_option
def eval(codename: str,
         hidden=True  # not unit-tested
         ):
    """Gets item data as text and executes it as shell command."""
    Globals.the_main().eval(codename)


@dmk_cli.command(name='vault')
def vault_cmd():
    """Prints the location of the vault file."""
    click.echo(Globals.the_main().file_path)
    # click.echo(f'Original: {Globals.main.}')
    # click.echo(f'Resolved: {Main(Globals.vault_arg).file_path}')

# if __name__ == '__main__':
#    dmk_cli(None)
