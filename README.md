# fs-fuzzer
My Material for the HITB 2020 Lockdown edition presentation in April.
This repo contains the presentation slides as well as all used scripts that were used to demonstrate the demos.

 ### Update May 2020
 
**[FULL FUZZING FRAMEWORK HERE](https://github.com/0xricksanchez/fisy-fuzz)**

## fs_generator.py

This standalone script can be used to generate different file systems across the different support host systems:

```
SUPPORTED_FILE_SYSTEMS = {
    "freebsd": ["ufs1", "ufs2", "zfs", "ext2", "ext3", "ext4"],
    "netbsd": ["4.3bsd", "ufs1", "ufs2", "ext2"],
    "openbsd": ["4.3bsd", "ufs1", "ufs2", "ext2"],
    "linux": ["uf1", "ufs2", "ext2", "ext3", "ext4", "zfs"],
    "darwin": ["apfs"],
}
```

Depending on the supplied flags to `fs_generator.py` the generated file system is either empty or contains a randomly generated file system hierarchy.
The files will be directories, symbolic as well as hard links and binary files.

### Example:

```
$ sudo python3 fs_generator.py -fs ext4 -s 15 -n "ubuntu_ext4_15mb" -o /home/dev/HITB/scripts/create_fs -p 10 -ps 1024
```

This creates a *ext4* disk image of size *15 MB* on a Ubuntu host system.
It will contain *10* files of which the maximum file size for each will be at most *1024 bytes*.
Finally, it will be saved at */home/dev/HITB/scripts/create_fs/*:

```bash
$ ls /home/dev/HITB/scripts/create_fs/ubuntu_ext4_15mb
/home/dev/HITB/scripts/create_fs/ubuntu_ext4_15mb
```


## fs_mutator.py

Is a standalone mutation script that supports mutation via *radamsa*, *targeted mutation* of specific metadata fields as well as less targeted variant
where you can write *n bytes* of *0x00*/*0xff*/*random* to either the *superblock*, *cylinder groups* or *data section*.

### Examples

```
$ ./fs_mutator.py -f HITB_ufs -o HITB_ufs_rad --radamsa --determinism --restore
```

Takes the HITB_ufs file system and applies a seeded full binary radamsa mutation to it.
Afterwards the magic bytes are restored.
The output is saved in a file called *HITB_ufs_rad*.


```
$ ./fs_mutator.py -f HITB_ufs -t sb 0 fs_magic 'AAAA' -o HITB_ufs_fsmagic
```
This overwrites the 4 byte magic sequence in the 0th ufs superblock with *'AAAA'*.

```
$ ./fs_mutator.py -f HITB_ufs -t sb all fs_fsmnt 'Hello World @ HITB 2020 Lockdown' -o HITB_ufs_fsmnt
```
This overwrites all superblock fields that correspond to the *fs_fsmnt* name with the provided *Hello World...* string.


## fs_fuzzer.py

This is a minimal working demo fuzzer, which includes 5 PoCs. 
You can read the code and understand the concept behind accessing and playing with remote machines.

## fs_util.py, ext-/ufs-superblock_parser.py

Provide some helper scripts to parse metadata fields and so forth.
