[![Generic badge](https://img.shields.io/badge/Status-Pre_Alpha-red.svg)](#)
[![Generic badge](https://img.shields.io/badge/Python-3.7+-blue.svg)](#)
[![Generic badge](https://img.shields.io/badge/OS-Linux%20|%20macOS%20|%20Windows-blue.svg)](#)

**This is experimental code. The file format may change.**

# [dmk: dark matter keeper](https://github.com/rtmigo/dmk_py#readme)

`dmk` keeps encrypted data entries in a file. Entries can be added, updated, and removed.
Entries can be binary (files) or text (passwords, etc).

Besides encrypting entries `dmk` makes uncertain the very fact of their
existence. The vault file consists of "dark matter":
unidentifiable data, most of which is just random bytes. There is no master
password and no way the see the table of contents.

Each entry is independent and encrypted with unique **secret name**. The secret 
name serves as a name and password at the same time.

Secret name makes possible to identify data
fragments associated with particular entry and decrypt it. It reveals nothing
about other entries, even whether they exist. The rest of the data is always a
dark matter.


# Install

``` 
$ pip install git+https://github.com/rtmigo/dmk_py#egg=dmk
```

# Secret names

The secret name serves as both the identifier of the entry and the password that
decrypts it. It is a secret. And it must be unique.

For example, information about a bitcoin wallet can be stored under name
`"b1TC01n"` or `"bitcoin_secret123"`.

# Save and read text

When called without parameters, the `get` and `set` commands query for all 
values interactively:

``` 
$ dmk set

Secret name: secRet007
Repeat secret name: secRet007 
Text: My darling's jokes are not so funny
```

``` 
$ dmk get

Secret name: secRet007
 
My darling's jokes are not so funny
```

Interactive input is optional. You can get by with one line:

``` 
$ dmk set -e secRet007 -t "My darling's jokes are not so funny"
```

``` 
$ dmk get -e secRet007

My darling's jokes are not so funny
```



# Save and read file

Read data from a `source.docx` and save it as encrypted entry `secRet007`

```  
$ dmk set -e secRet007 /my/docs/source.docx
```

Decrypt the entry `secRet007` and write the result to `target.docx`

``` bash
$ dmk get -e secRet007 /my/docs/target.docx
```

The `-e` parameter is optional. If it is not specified, the value will be
prompted for interactive input.

Vault location
==============

Entries will be stored in a file.

You can check the current vault file location with `vault` command:

```
$ dmk vault
```
Output:
```
/home/username/vault.dmk
```

By default, it is `vault.dmk` in the current user's `$HOME` directory.

--------------------------------------------------------------------------------

The `-v` parameter overrides the location for a single run.

```
$ dmk -v /path/to/myfile.data vault
```

Output:
```
/path/to/myfile.data
```

The parameter can be used with any commands:

```
$ dmk -v /path/to/myfile.data set 
$ dmk -v /path/to/myfile.data get 
```

--------------------------------------------------------------------------------

The `$DMK_VAULT_FILE` environment variable overrides the default location:

``` 
$ export DMK_VAULT_FILE=/path/to/myfile.data
$ dmk vault  
```
Output:
```
/path/to/myfile.data
```

While `$DMK_VAULT_FILE` is set all the command will use `myfile.data`:

```
$ dmk set   # set to myfile.data 
$ dmk get   # get from myfile.data
```

# Under the hood

- Entries are encrypted 
- Number of entries cannot be determined
- File format is unidentifiable

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

1) **URandom** creates 38-bytes **salt** when we initialize the vault file. The
   salt is saved openly in the file. This salt never changes. It is required for
   any other actions on the vault.

2) **Argon2id** (memory 128 MiB, iterations 4, parallelism 8) derives 
   256-bit **private key** from salted (1) secret name.

3) **ChaCha20** encrypts the block data using the 256-bit private key (2) and 
   newly generated 96-bit urandom **block nonce**.

4) The encrypted data of the block starts with a 40-byte header. This header
   contains the secret key in plain text, and some other information.
   The header is followed by the **header checksum**, which is a 160-bit 
   **Blake2s** hash. The checksum itself is also in the encrypted stream.
   
   When decrypting, we are directly or indirectly checking that all components 
   match each other:
   - 32-byte (256-bit) private key (1) - it decrypts the data
   - 20-byte (160-bit) header checksum (4)
   - decrypted secret name (4) up to 28 bytes long
   - the secret name provided by user
   
   If everything matches everything, it is at least a 53 bytes match. We also 
   verified that this is not a private key collision or a checksum collision. 
   Still not deterministic, but more likely than any conceivable coincidence. 
   This is indeed a block related to the given secret name.
   
   We also made sure that the data decryption is proceeding correctly.

5) **CRC-32** checksum verifies the entry data decrypted from the block.

   This verification occurs when we have already checked (4) the correctness
   of the private key (2). Therefore, it is really only a self-test to see
   if the data is decoded as expected.

   This checksum is saved inside the encrypted stream. If the data in the 
   blocks is the same, it will not be noticeable from the outside due to 
   different nonce (3) values.





