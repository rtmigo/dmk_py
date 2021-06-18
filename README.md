[![Generic badge](https://img.shields.io/badge/Status-Experimental-red.svg)](#)
[![Generic badge](https://img.shields.io/badge/Python-3.7+-blue.svg)](#)
[![Generic badge](https://img.shields.io/badge/OS-Linux%20|%20macOS%20|%20Windows-blue.svg)](#)

**This is experimental code. It is not ready to use. This description is also a
draft.**

# [dmk: dark matter keeper](https://github.com/rtmigo/dmk_py)

`dmk` keeps data entries in a file. Entries can be added, updated, and removed.
Entries can be binary (files) or text (passwords, etc).

Each entry is independent and protected unique **codename**. The codename
serves as a name and password at the same time.

Codename allows access to one entry. It reveals nothing about other
entries, even whether they exist.

The `dmk` storage file does not have master password or table of contents.

The file consists mostly of unidentifiable data. The data may contain encrypted
information, or be just random. Codename helps to identify only data fragments
associated with particular entry and decrypt it. The rest of the data will
remain dark matter.

# Install

``` bash
$ pip install git+https://github.com/rtmigo/dmk_py#egg=dmk
```

# Codenames

The codename serves as both the identifier of the entry and the password that
decrypts it. It is a secret. And it must be unique.

For example, information about a bitcoin wallet can be stored under codename
`"b1TC01n"` or `"bitcoin_secret123"`.

# Storage location

Entries will be stored in a file.

If the `-s` argument is given, it specifies the file.

``` bash
$ dmk gett -s /path/to/storage.file ...  
```

If `-s` is not specified, the path is read from `$dmk_STORAGE_FILE` environment
variable.

``` bash
$ export dmk_STORAGE_FILE=/path/to/storage.file
$ dmk gett ...  
```

The following examples assume that the variable `$dmk_STORAGE_FILE` is set and
therefore the `-s` argument is not required.

# Save and read text

``` 
$ dmk sett -e secRet007 -t "My darling's jokes are not so funny"
```

``` 
$ dmk gett -e secRet007

My darling's jokes are not so funny
```

The `-e` and `-t` parameters are optional. If they are not specified, their
values will be prompted for interactive input.

``` 
$ dmk sett

Codename: secRet007
Repeat: secRet007 
Text: My darling's jokes are not so funny
```

``` 
$ dmk gett

Codename: secRet007
 
My darling's jokes are not so funny
```

# Save and read file

Read data from a `source.docx` and save it as encrypted entry `secRet007`

``` 
$ dmk setf -e secRet007 /my/docs/source.docx
```

Decrypt the entry `secRet007` and write the result to `target.docx`

``` 
$ dmk getf -e secRet007 /my/docs/target.docx
```

The `-e` parameter is optional. If it is not specified, the value will be
prompted for interactive input.

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
codename. All non-random data is either hashed or encrypted. The size of padding
is unknown.

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

The file has no header, no constant bytes (or even bits), no block boundaries.
File size will not give clues: the file is randomly padded with a size that is
not a multiple of a block.

The only predictable part of the file is the format version number encoded in
the first two bytes. However, even the first two bytes are not constant.
Similar "version number" can be found literally in every fourth file, even if it
contains random rubbish.

## Block encryption

1) **URandom** creates 192-bit **salt** when we initialize the vault file. The
   salt is saved openly in the file. This salt never changes. It is required for
   any other actions on the vault.

2) **Scrypt** (CPU/Memory cost = 2^17) derives 256-bit **private key** from
   salted (1) codename.

3) Еach block receives a 352-bit **fingerprint** consisting of 96-bit **nonce**
   and 256-bit **Blake2s** **hash**, derived from nonce (3) + private key (2).
   We use a new nonce for each block.

   This fingerprint is saved openly to the block. Fingerprint allows us to
   identify blocks associated with a specific codename. With the private key (2)
   available, we can recreate the same fingerprint (3) using the known nonce
   (3). Without the private key, we have no idea what the hash (3) was derived
   from.

4) **ChaCha20** encrypts the block data using the private key (2) and 96-bit
   nonce (3).

5) The block header is located at the very beginning of the encrypted data. The
   header is followed by the **header checksum**, which is a 128-bit
   **Blake2s** hash. This hash (5) helps ensure that the private key is correct
   without decrypting the rest of the data.

   Thus, the block's belonging to the code name is checked twice: with 256-bit
   (3) and 128-bit (5) hashes.

   We also made sure that the data decryption is proceeding correctly.

6) **CRC-32** checksum verifies the entry data decrypted from the block.

   This verification occurs when we have already double-checked the correctness
   of the private key (3) (5). Therefore, it is really only a self-test to see
   if the data is decoded as expected.

   This checksum is saved inside the encrypted stream. If the data in the blocks
   is the same, it will not be noticeable from the outside due to different
   nonce (3) values.





