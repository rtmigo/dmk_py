[![Generic badge](https://img.shields.io/badge/Status-Experimental-red.svg)](#)
[![Generic badge](https://img.shields.io/badge/Python-3.7+-blue.svg)](#)
[![Generic badge](https://img.shields.io/badge/OS-Linux%20|%20macOS%20|%20Windows-blue.svg)](#)

**This is experimental code. It is not ready to use. This description is also a
draft.**

# [codn](https://github.com/rtmigo/codn_py)

---

`codn` encrypts data entries. Entries can be added, updated, and removed.
Entries are files or strings.

Each entry is independent and protected with a unique **codename**. The codename
serves as a name and password at the same time.

Codename allows access to one entry. It reveals nothing about other entries,
even whether they exist. The
vault is cryptographically secure and overly obfuscated. There is no table of
contents and no master decryption keys.

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

- Entries are encrypted really well
- Number of entries cannot be determined
- It is impossible to identify the file format without knowing a codename

## Entries obfuscation

The vault file stores all data within multiple fixed-size blocks.

Small entries are padded so they become block-sized. Large entries are split and
padded to fit into multiple blocks. In the end, they are all just a lot of
blocks.

A block gives absolutely no information for someone who does not own the
codename. All non-random data is either hashed or encrypted. The size of 
padding is unknown.

The number of blocks is no secret. Their contents are secret.

- The number of blocks is random. Many blocks are fake. They are
  indistinguishable from real data, but do not contain anything meaningful

- The information about which entry the block belongs to is cryptographically
  protected. It is impossible to even figure out if the blocks refer to the same
  entry

- Random actions are taken every time the vault is updated: some fake blocks are
  added, and some are removed

Thus, **number and size of entries cannot be determined** by the size of the
vault file or number of blocks.

The payload is smaller than the vault size. Only this is known for certain.

## File obfuscation

The vault file format is virtually **indistinguishable from random data**.

The file has no header, no constant bytes (or even bits), no block boundaries. File size will not give clues: the file is randomly padded with a
size that is not a multiple of a block.

The only predictable part of the file is the format version number encoded in
the first two bytes. However, even the first two bytes are not constant.
Similar "version number" can be found literally in every fourth file, even if it
contains random rubbish.

## Encryption

1) **URandom** creates 192-bit **salt** when we initialize the vault file. The
   salt is saved openly in the file. This salt never changes. It is
   required for any other actions on the vault.

2) **Scrypt** (CPU/Memory cost = 2^17) computes 256-bit **private key** from
   salted (1) codename.

3) **Blake2b** computes 256-bit **hashes** from the private key (2) combined
   with a 256-bit **nonce**. These hash+nonce pairs are openly saved to blocks
   that contain encrypted entries.

   Having the private key (2) and the nonce (3), we can recompute the same
   hash (3) and check if the block contains it. If yes, then the block belongs 
   to the given codename.

4) **ChaCha20** encrypts the blob data using the private key (2) and a newly
   generated 64-bit nonce.

5) **CRC-32** checksums (encrypted by ChaCha20) verify the integrity of the
   decoded data.