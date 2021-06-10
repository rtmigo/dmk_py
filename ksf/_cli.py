import time

import click

from ksf._20_key_derivation import FilesetPrivateKey

@click.command()
def bench():
    """Measures the KDF speed: the private key computation time."""
    a = []
    for i in range(4):
        t = time.monotonic()
        FilesetPrivateKey(str(i))
        d = time.monotonic()-t
        a.append(d)
        print(f'{i+1} {d:.3f} sec')
    print(f'Mean {sum(a)/len(a):.3f} sec')


@click.group()
def cli():
    pass


cli.add_command(bench)

if __name__ == '__main__':
    # config = Config()
    cli()
