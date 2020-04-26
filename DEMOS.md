## Test case generator

1. sudo ./fs_generator.py -fs ufs2 -s 10 -n 'HITB_ufs' -o $(pwd)
2. sudo ./fs_generator.py -fs ext2 -s 10 -n 'HITB_ext2' -o $(pwd)
3. sudo ./fs_generator.py -fs zfs -s 64 -n 'HITB_zfs' -o $(pwd)
4. sudo ./fs_generator.py -fs ext2 -s 15 -n 'HITB_ext2_p' -o $(pwd) -p 10 ps 1024

## Mutation

1. file HITB_ufs
1.1 /fs_mutator.py -f HITB_ufs -t sb all fs_fsmnt 'Hello world @ HITB 2020 Lockdown Edition :)!' -o HITB_ufs_fsmnt
1.2 file HITB_ufs_fsmnt
1.3 ./fs_fuzzer.py -2


2. ./fs_mutator.py -f HITB_ufs -t sb 0 fs_magic 'AAAA' -o HITB_ufs_fsmagic
2.1 file HITB_ufs_fsmagic
2.2 ./ufs_superblock_parser.py -f HITB_ufs_fsmagic -ps 0
2.3 ./fs_fuzzer.py -3
2.4 Change to sb1 if time.. 

3. ./fs_mutator.py -f HITB_ufs --prototype sb byte_flip ff 0 -o HITB_ufs_sb0_bf_ff
4. ./fs_mutator.py -f HITB_ufs --prototype cg byte_flip rnd all -o HITB_ufs_cgall_bf_rnd
5. ./fs_mutator.py -f HITB_ufs --prototype data block rnd '' -o HITB_ufs_data_block_rnd
6. ./fs_mutator.py -f HITB_ufs -o HITB_ufs_rad --radamsa --determinism
6.1 binwalk -W HITB_ufs HITB_ufs_rad
7. ./fs_mutator.py -f HITB_ufs -o HITB_ufs_rad --radamsa --determinisn --restore
7.1 file HITB_ufs_rad

## User Emul:

1. ./fs_fuzzer.py -4    ; Mount no user emul
2. ./fs_fuzzer.py -5    ; some user emul

## Monitoring

1. less default.txt
1.1 ./extract_core_features.py default.txt
2. less verbose.txt
2.1 ./extract_core_features.py verbose.txt
