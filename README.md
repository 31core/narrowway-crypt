# NarrowWay Cryptor

A NarrowWay-based archive encryption/decryption utility.

## Usage

Encrypt a file with NarrowWay-192 and ECB block mode:

```shell
narrowway-crypt -a 192 -b ecb -k <Your Key Here> <Input Path> <Output Path> encrypt
```

Decrypt a file with specified key file:

```shell
narrowway-crypt -f <Key File> <Your Key Here> <Input Path> <Output Path> decrypt
```

## Bugs & Reports

You can report a bug or share your ideas by email `31core@tutanota.com`.
