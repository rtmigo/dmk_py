[![Generic badge](https://img.shields.io/badge/Status-Experimental-red.svg)](#)
[![Generic badge](https://img.shields.io/badge/Python-3.7+-blue.svg)](#)
[![Generic badge](https://img.shields.io/badge/OS-Linux%20|%20macOS%20|%20Windows-blue.svg)](#)

`ksf` encrypts individual data entries. Entries can be added, updated and
removed.

Entries are identified with **secret names**. Knowing the secret name of an
entry, you can access the data of that particular entry.

There is no way to decrypt the entire storage or even find out its contents.
There is no master password and no list of entries. Each entry is independent
and encrypted with a separate key.

# Install

``` bash
$ pip install git+https://github.com/rtmigo/ksf_py#egg=ksf
```

## The files

`ksf` stores encrypted data in a directory.

The directory can contain any number of entries. Including zero entries.

The directory structure does not give any information about the content. It is
not even possible to determine that the directory was created by the `ksf`.

The file content is indistinguishable from a random data: there are no
recognizable identifiers or structures. Literally not a single predictable byte,
until you have an encryption key.

- The file names are random

- The file modification dates are random

- The file sizes are random. Large entries are split into small file parts.
  Small entries are supplemented with random padding

- The number of files is random: some files are fakes that do not contain real
  data

