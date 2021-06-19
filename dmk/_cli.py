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
from ._constants import __version__, __copyright__

CODN_FILE_ENVNAME = 'DMK_VAULT_FILE'
DEFAULT_STORAGE_FILE = "~/vault.dmk"


def validate_filename(ctx, param, value):
    if value is None or not value.strip():
        raise click.BadParameter("Storage filename must be specified")
    return value


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
    """Encrypts text or file to an entry."""

    if len(file) >= 1:
        if len(file) >= 2:
            raise click.BadParameter("Exactly one file expected")
        Main(vault).set_file(codename, str(file[0]))  # todo not str
    else:
        if text is None:
            text = click.prompt('Text')
        Main(vault).set_text(codename, text)


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
    """Decrypts an entry and prints as text, or writes to file."""
    if len(file) > 0:
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


@click.group(
    invoke_without_command=True,

    #callback = lambda: print('zzz'),


    )
#@click.version_option(message=f'%(prog)s {__version__}\n(c) {__copyright__}')
@click.pass_context
def dmk_cli(ctx):
    if not ctx.invoked_subcommand:
        click.echo(f"DMK: Dark Matter Keeper v{__version__}")
        click.echo('(c) 2021 Artёm IG <ortemeo@gmail.com>')
        click.echo()
        click.echo("See https://github.com/rtmigo/dmk_py#readme")
        click.echo()
        click.echo(ctx.get_help())
        ctx.exit(2)
        #click.e
        #print('main stuff')
#    print("haha")
 #   exit()


    # todo fix windows --version problem
    pass

# @click.command()
# @click.option('--option')
# @click.pass_context
#
# def run(ctx, option):
#     if not option:
#         print("zzz")
#         click.echo(ctx.get_help())
#         ctx.exit()

dmk_cli.add_command(bench)
dmk_cli.add_command(getf_cmd)
dmk_cli.add_command(eval)
dmk_cli.add_command(set_cmd)
#dmk_cli.add_command(run)

if __name__ == '__main__':
    dmk_cli(None)
