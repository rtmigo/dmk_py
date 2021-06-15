[![Generic badge](https://img.shields.io/badge/Status-Experimental-red.svg)](#)
[![Generic badge](https://img.shields.io/badge/Python-3.7+-blue.svg)](#)
[![Generic badge](https://img.shields.io/badge/OS-Linux%20|%20macOS%20|%20Windows-blue.svg)](#)

**This is experimental code. It is not ready to use. This description is also a
draft.**

# [codn](https://github.com/rtmigo/codn_py)

---

`codn` encrypts data entries. Entries can be added, updated, and removed. Entries
are files or strings.

Each entry is independent and opens with a unique **codename**.

Knowing one codename reveals nothing about other entries. Neither the user nor
the utility has that information. It's tightly encrypted.

By design, `codn` reveals very little besides the particular entry.
Number and size of entries are obfuscated.
There is no table of contents and no master decryption keys. 

# Install

``` bash
$ pip install git+https://github.com/rtmigo/codn_py#egg=codn
```

# Codenames

The codename serves as both the identifier of the entry and the password that
decrypts it. It is a secret. And it must be unique.

For example, information about a bitcoin wallet can be stored under codename
`"b1TC01n"` or `"bitcoin_secret123"`.

# Storage location

Encrypted files are stored in a directory on the file system.

If the `-d` argument is given, it specifies the directory.

``` bash
$ codn get -d /path/to/storage -n codename123  
```

If `-d` is not specified, the path is read from `$CODN_DIR` environment
variable.

``` bash
$ export CODN_DIR=/path/to/storage
$ codn get -n codename123  
```

Keep in mind that mixing storage files with other files is not desirable.
Therefore, you should not save other files to the directory. This can lead to
data not being correctly encrypted or decrypted.

# Save and read text

In one line:

``` 
$ codn set -n topsecret123 -v "My lover's jokes are not that funny"
```

``` 
$ codn get -n 'topsecret123'

My lover's jokes are not that funny
```

Interactively:

``` 
$ codn set

Codename: topsecret123
Repeat: topsecret123 
Entry value: My lover's jokes are not that funny
```

``` 
$ codn get

Codename: topsecret123
 
My lover's jokes are not that funny
```

# Under the hood

## Obfuscation

`codn` stores encrypted entries inside blobs. The number and size of blobs is no
secret. Their contents are secret.

- Which blobs refer to the same codename is unknown and cryptographically hidden

- The blob sizes are random. They are unrelated to the size of the entries.
  Large entries are broken into parts, and small ones are padded

- Many blobs are fake. They are indistinguishable from real data, but do not
  contain anything meaningful

- Random actions are taken every time the vault is updated: some fake blobs are
  added, and some are removed

The file itself, at first glance, does not have format-identifying information,
and does not have any evident structure.

## Encryption

1) **URandom** creates 256-bit **salt** when we initialize the vault file. The
   salt is saved openly in the file header. This salt never changes. It is
   required for any other actions on the vault.

2) **Scrypt** (CPU/Memory cost = 2^17) computes 256-bit **private key** from
   salted (1) codename.

3) **Blake2b** computes 192-bit **hashes** from the private key (2) combined
   with a 192-bit **nonce**. These hash+nonce pairs are openly saved to blobs
   that contain encrypted entries.

   Having the private key (2) and the nonce (3), we can recompute the same
   hash (3) and check if the blob contains it. If yes, then the blob belongs to
   the given codename.

4) **ChaCha20** encrypts the blob data using the private key (2) and a newly
   generated 64-bit nonce.

5) **CRC-32** checksums (encrypted by ChaCha20) verify the integrity of the
   decoded data.