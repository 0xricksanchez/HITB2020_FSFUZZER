#!/usr/bin/env sh

mkdir /mnt/radamsa_fs_fuzz1_ufs_15MB
mdconfig -a -t vnode -f radamsa_fs_fuzz1_ufs_15MB
echo "[!] Mounting..."
mount -t ufs /dev/md0 /mnt/radamsa_fs_fuzz1_ufs_15MB

