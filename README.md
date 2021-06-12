[![Generic badge](https://img.shields.io/badge/Status-Experimental-red.svg)](#)
[![Generic badge](https://img.shields.io/badge/Python-3.7+-blue.svg)](#)
[![Generic badge](https://img.shields.io/badge/OS-Linux%20|%20macOS%20|%20Windows-blue.svg)](#)

Experimental data encryption app.

# Install

``` bash
$ pip install git+https://github.com/rtmigo/ksf_py#egg=ksf
```

# Details

`ksf` stores encrypted data in a directory.

The directory can contain any number of entries. Including zero entries.





## How it looks from the outside

The directory structure does not give any information about the content.
It is not even possible to determine that the directory was created by 
the `ksf`.


- The file names are random

- The file modification dates are random

- The file sizes are random. Large entries are split into small file parts. Small
entries are supplemented with random padding

- The number of files is random: some of them are fakes that do not contain real data

Each file is indistinguishable from a random one: there are no recognizable
identifiers or structures. Literally not a single predictable byte.

## How does it look inside 

All records are independent: each is encrypted with its own key.

There is no master password to show the list of entries. Because there is no
list of entries and no master password.

The only thing that can be done is to get individual entries by their 
secret keys.
