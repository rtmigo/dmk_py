import datetime
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import PyInstaller.__main__ as compile
import click
import neatest
from chkpkg import Package


@click.group()
def app():
    pass


@app.command()
def test():
    _test()


def _test():
    neatest.run(warnings=neatest.Warnings.fail)


@app.command()
def test_pkg():
    with Package() as pkg:
        pkg.run_shell_code('dmk --version')
    print("\nPackage is OK!")


@app.command()
def run():
    subprocess.call([sys.executable, "_run.py"])


@app.command()
def lint():
    _lint()


def _lint():
    print("Running mypy...")
    if subprocess.call(['mypy', 'dmk',
                        '--ignore-missing-imports']) != 0:
        exit(1)


# def _get_git_commit():
#     return subprocess.check_output("git log --pretty=format:'%h' -n 1".split())


def _replace_build_date(fn: Path):
    now = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
    text = fn.read_text()
    new_text = re.sub(
        r'__build_timestamp__.+',
        f'__build_timestamp__ = "{now}"',
        text)
    print(new_text)
    assert new_text != text, "timestamp not changed"
    fn.write_text(new_text)


# def _replace_git_commit(fn: Path):
#     now = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
#     text = fn.read_text()
#     text = re.sub(
#         r'__prev_commit__.+$',
#         f'__prev_prev_commit__ = "{now}"',
#         text)
#     print(text)
#     fn.write_text(text)


@app.command()
def install():
    """Build PyInstaller executable and copy it to ~/.local/bin"""
    name = "dmk"
    project_dir = Path(__file__).parent

    _test()
    _lint()

    _replace_build_date(Path("dmk/_constants.py"))
    # exit()

    compile.run([
        "--clean", "--onefile", "-y",
        "--collect-all", "dmk",
        "--name", name, "_run.py"
    ])

    exe = project_dir / "dist" / name
    print(f"Exe size: {exe.stat().st_size / 1024 / 1024:.0f} MiB")

    os.remove(project_dir / "dmk.spec")
    shutil.rmtree(project_dir / "build")
    target = Path(os.path.expanduser("~/.local/bin")) / name
    if target.parent.exists():
        print(f"Copying to {target}")
        shutil.move(exe, target)
    else:
        print(f"{target.parent} does not exist")


if __name__ == "__main__":
    app()
