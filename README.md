# dlink-decrypt
This is the PoC code for my [blogpost series](https://0x00sec.org/t/breaking-the-d-link-dir3060-firmware-encryption-recon-part-1/21943) about breaking encrypted D-Link firmware samples for further analysis:

* [part 1](https://0x00sec.org/t/breaking-the-d-link-dir3060-firmware-encryption-recon-part-1/21943)
* [part 2](https://0x00sec.org/t/breaking-the-d-link-dir3060-firmware-encryption-static-analysis-of-the-decryption-routine-part-2-1/22099)
* [part 3](https://0x00sec.org/t/breaking-the-d-link-dir3060-firmware-encryption-static-analysis-of-the-decryption-routine-part-2-2/22260/)

## Repo Contents

* src --> My re-constructed C code from the `imgdecrypt` disassembly
* bin --> Has compiled x64 versions of the `imgdecrypt` binary
* DIR_3060 --> Contains `public.pem` and the `imgdecrypt` binary from their root fs
* DIR_882 --> Analogous to *DIR_3060*
* test --> some test binaries for un-/packing

# Usage

For the basic decryption of a sample you can just invoke the python script as follows:
``` 
$ ./dlink-dec.py
Usage: python3 ./dlink-dec.py -i <in> -o <out>
```

I've also rapidly prototypted a D-Link like encryption that mimics the original one. You can test it by adding a mode flag to the invocation:
```
$ ./dlink-dec.py
Usage: python3 ./dlink-dec.py -i <in> -o <out> -m enc
```

## Alternative way:
As always there is also an alternative way using `openssl`:

```bash
dd if=enc.bin skip=1756 iflag=skip_bytes|openssl aes-128-cbc -d -p -nopad -nosalt -K "c05fbf1936c99429ce2a0781f08d6ad8" -iv "67c6697351ff4aec29cdbaabf2fbe346" --nosalt -in /dev/stdin -out dec.bin
```
