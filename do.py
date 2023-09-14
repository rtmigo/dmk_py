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
        # pkg.run_shell_code('dmk --version')
        pkg.run_shell_code('dmk --help')
        # pkg.run_shell_code('dmk', expected_return_code=2)
        pkg.run_shell_code('dmk --version')
        # todo problem with unicode: is it chkpkg or dmk problem?
        pkg.run_python_code("from dmk import DmkFile, get_text, set_text, "
                            "get_file, set_file")
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


def _build_exe() -> Path:
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
    print(f"Built {exe}")
    print(f"Exe size: {exe.stat().st_size / 1024 / 1024:.0f} MiB")

    return exe


@app.command()
def build():
    """Build PyInstaller executable"""
    _build_exe()


@app.command()
def install():
    """Build PyInstaller executable and copy it to ~/.local/bin"""
    exe = _build_exe()
    project_dir = Path(__file__).parent
    target = Path(os.path.expanduser("~/.local/bin")) / "dmk"
    if target.parent.exists():
        print(f"Copying to {target}")
        shutil.move(exe, target)
    else:
        print(f"{target.parent} does not exist")
    os.remove(project_dir / "dmk.spec")
    shutil.rmtree(project_dir / "build")


if __name__ == "__main__":
    app()
