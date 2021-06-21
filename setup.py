from pathlib import Path

from setuptools import setup, find_packages


def load_module_dict(filename: str) -> dict:
    import importlib.util as ilu
    filename = Path(__file__).parent / filename
    spec = ilu.spec_from_file_location('', filename)
    module = ilu.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.__dict__


name = "dmk"
constants = load_module_dict(f'{name}/_constants.py')

readme = (Path(__file__).parent / 'README.md').read_text(encoding="utf-8")
readme = "# " + readme.partition("\n#")[-1]

setup(
    name=name,
    version=constants['__version__'],

    author="Artëm IG",
    author_email="ortemeo@gmail.com",
    url='https://github.com/rtmigo/dmk_py',

    packages=find_packages(include='dmk/*'),
    python_requires='>=3.7',
    install_requires=['pycryptodome', 'click', 'argon2-cffi'],

    description="Experimental storage with entries encrypted independently.",

    long_description=readme,
    long_description_content_type='text/markdown',

    license="MIT",

    entry_points={
        'console_scripts': [
            'dmk = dmk:dmk_cli',
        ]},

    keywords="encryption password keeper storage vault keychain file"
             "privacy deniable data security "
             "chacha20 argon2 "
             "".split(),

    classifiers=[
        #"Development Status :: 4 - Beta",
        #"Intended Audience :: Developers",
        'Development Status :: 2 - Pre-Alpha',
        'License :: OSI Approved :: BSD License',
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        'Topic :: Security :: Cryptography',
        "Environment :: Console",
        "Typing :: Typed",
        #"Topic :: Software Development :: Build Tools",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows"
    ],

    test_suite="test_unit.suite"
)
