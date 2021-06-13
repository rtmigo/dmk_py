[![Generic badge](https://img.shields.io/badge/Status-Experimental-red.svg)](#)
[![Generic badge](https://img.shields.io/badge/Python-3.7+-blue.svg)](#)
[![Generic badge](https://img.shields.io/badge/OS-Linux%20|%20macOS%20|%20Windows-blue.svg)](#)

**This is experimental code. It is not ready to use. This description is also a
draft.**

# [codn](https://github.com/rtmigo/ksf_py)

---

`codn` encrypts data entries. Entries can be added, updated and removed. Entries
are files or strings.

You need to know the **codename** of the entry to access the data of the entry.
Without the codename, it is impossible even to find out if the entry exists.

There is **no way to decrypt the entire storage**, since there is **no master
password**. There is **no table of contents**. The **codenames are not stored** even in
  encrypted form. The **files reveal nothing** about the storage contents. The file names,
  sizes, dates and even the number of files are randomly obfuscated.  Each file content is indistinguishable from random.

# Install

``` bash
$ pip install git+https://github.com/rtmigo/ksf_py#egg=ksf
```

# Codenames

The codename serves as both the identifier of the entry and the password that
decrypts it. It is a secret. And it must be unique.

For example, information about a bitcoin wallet can be stored under codename
`"b1TC01n"` or `"bitcoin_secret123"`.

# Under the hood

## Encryption

1) **URandom** creates 256-bit **salt** when we initialize the directory. The
   salt is saved openly in one of the files. This salt never changes. It is
   required for any other actions on the directory.

2) **Scrypt** (CPU/Memory cost = 2^17) computes 256-bit **private key** from
   salted (1) codename.

3) **Blake2b** computes 192-bit **hashes** from the private key (2) combined
   with a 192-bit **nonce**. These hash+nonce pairs are openly saved to files
   that contain encrypted entries.

   Having the private key (2) and the nonce (3), we can recompute the same
   hash (3) and check if the file contains it. If yes, then the file belongs to
   the given codename.

4) **ChaCha20** encrypts the entry data using the private key (2) and a newly
   generated 64-bit nonce.

5) **CRC-32** checksums (encrypted by ChaCha20) verify the integrity of the
   decoded data.

## Obfuscation

`ksf` stores encrypted data in a directory.

The directory can contain any number of entries. Or contain none at all.

The directory content is obfuscated. It is not even possible to determine that
the directory was created by the `ksf`.

```
Size  | Timestamp    | Filename
------|--------------|--------------------
 1897 | Mar  5  2019 | 2r6wsjiktoply4eiwe
55043 | May 26  2017 | 4ba7ucpwnnzq
 1681 | Oct  9  2016 | d3vh7ifow4
58041 | Dec 25  2016 | e47grv7dkx4q
 1775 | Oct 16  2012 | f34q
 1901 | Mar  6  2020 | f445pmidvzok2
 1842 | Sep 15  2020 | fswxug7rse
 1946 | Jul 23  2018 | g335bk657nbtleinea
45491 | Apr 28  2012 | jbzbww3hyihdn3i
  389 | Feb 13  2015 | mgamw25dv3dsbji
19376 | Jul  7  2019 | n4w5soq
 1886 | Jun  5  2012 | npqlqxkendgyl3qz4gea
   94 | Jan 28  2014 | pm5hk7sm
  587 | May 16  2019 | rjsgposhcx6a
 1481 | Feb 11  2016 | to4q5gn7uu
52400 | Mar 18  2012 | v7uq
  450 | Jun 20  2019 | von5d4lo6xfytfep
```

Content of each file is indistinguishable from a random data: there are no
recognizable identifiers or structures. Literally not a single predictable byte,
until you have the decryption key.

- The file names are random

- The file modification dates are random

- The file sizes are random. Large entries are split into small file parts.
  Small entries are supplemented with random padding

- The number of files is random: some files are fakes that do not contain real
  data

