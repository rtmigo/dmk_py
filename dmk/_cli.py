# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import time

import click

from dmk._common import KEY_SALT_SIZE
from dmk._main import Main
from dmk.a_base._10_kdf import CodenameKey
from dmk.a_utils.randoms import get_noncrypt_random_bytes

CODN_FILE_ENVNAME = 'CODN_STORAGE_FILE'


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


@click.command(name='sett')
@click.option('-s', '--storage', envvar=CODN_FILE_ENVNAME,
              callback=validate_filename)
@click.option('-e',
              '--entry',
              'codename',
              prompt='Name',
              hide_input=True,
              confirmation_prompt="Repeat")
@click.option('-t', '--text', prompt='Text')
def set_cmd(storage: str, codename: str, text: str):
    """Sets entry content from text."""
    Main(storage).set_text(codename, text)



@click.command()
@click.option('-s', '--storage', envvar=CODN_FILE_ENVNAME,
              callback=validate_filename)
@click.option('-e',
              '--entry',
              'codename',
              prompt='Codename',
              hide_input=True)
def gett(storage: str, codename: str):
    """Prints entry content."""
    s = Main(storage).get_text(codename)
    print(s)

@click.command(name='setf')
@click.option('-s', '--storage', envvar=CODN_FILE_ENVNAME,
              callback=validate_filename)
@click.option('-e',
              '--entry',
              'codename',
              prompt='Name',
              hide_input=True,
              confirmation_prompt="Repeat")
@click.argument('filename')
def setf_cmd(storage: str, codename: str, filename: str):
    """Sets entry content from data read from binary file."""
    Main(storage).set_file(codename, filename)

@click.command(name='getf')
@click.option('-s', '--storage', envvar=CODN_FILE_ENVNAME,
              callback=validate_filename)
@click.option('-e',
              '--entry',
              'codename',
              prompt='Name',
              hide_input=True)
@click.argument('filename')
def getf_cmd(storage: str, codename: str, filename: str):
    """Writes entry content to a binary file."""
    Main(storage).get_file(codename, filename)


@click.command()
@click.option('-s', '--storage', envvar=CODN_FILE_ENVNAME,
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


dmk_cli.add_command(bench)
dmk_cli.add_command(set_cmd)
dmk_cli.add_command(gett)
dmk_cli.add_command(setf_cmd)
dmk_cli.add_command(getf_cmd)
dmk_cli.add_command(eval)

if __name__ == '__main__':
    # config = Config()
    dmk_cli()
