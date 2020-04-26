#!/usr/bin/env python3

import argparse
import os
import pathlib
import pprint as pp
import re
from collections import OrderedDict
from ctypes import *

from fs_util import UFS_MAGIC, CG_MAGIC, get_int, UFS_CG, UFS_SB, SBLOCK_UFS1, SBLOCK_UFS2


class UFS(Structure):

    def __init__(self, fs, fst):
        super(Structure).__init__()
        self.sb = OrderedDict()
        self.cg = OrderedDict()
        self.sb_expected_len = 1376
        self.cg_expected_len = 169
        self.fs = fs
        self.fst = fst
        if fst == 'ufs2':
            self.sbo = SBLOCK_UFS2
        else:
            self.sbo = SBLOCK_UFS1
        self.sb_locs = []
        self._fields_sb = UFS_SB
        self.cg_locs = []
        self._fields_cg = UFS_CG
        self._sanity_check()

    def _sanity_check(self):
        res_sb = 0
        res_cg = 0
        for _, v in self._fields_sb:
            res_sb += sizeof(v)
        for _, v in self._fields_cg:
            res_cg += sizeof(v)
        assert res_sb == self.sb_expected_len
        assert res_cg == self.cg_expected_len

    def get_superblock(self, n=0):
        self.find_all_superblocks()
        self._read_superblock_in_dict(self.sb_locs[n])
        return self.sb

    def get_cylinder_group(self, n=0):
        self.find_all_cylinder_groups()
        self._read_cylinder_group_in_dict(self.cg_locs[n])
        return self.cg

    def _read_superblock_in_dict(self, loc=SBLOCK_UFS2):

        with open(self.fs, 'rb') as f:
            f.seek(loc)
            for field in self._fields_sb:
                self.sb[field[0]] = f.read(sizeof(field[1]))

    def _read_cylinder_group_in_dict(self, loc=None):
        with open(self.fs, 'rb') as f:
            f.seek(loc)
            for field in self._fields_cg:
                self.cg[field[0]] = f.read(sizeof(field[1]))

    def find_all_superblocks(self):
        with open(self.fs, 'rb') as f:
            data = f.read()
            matches = re.finditer(UFS_MAGIC, data)
            for m in matches:
                sb = m.span()[0] - (self.sb_expected_len - 4)
                self.sb_locs.append(sb)
        self.sb_locs = self.sb_locs[1:]
        if (not self.sb_locs or SBLOCK_UFS2 not in self.sb_locs) and self.fst == 'ufs2':
            self.sb_locs = [SBLOCK_UFS2] + self.sb_locs
        elif (not self.sb_locs or SBLOCK_UFS1 not in self.sb_locs) and self.fst =='ufs1':
            self.sb_locs = [SBLOCK_UFS1] + self.sb_locs
        return self.sb_locs

    def find_all_cylinder_groups(self):
        with open(self.fs, 'rb') as f:
            data = f.read()
            matches = re.finditer(CG_MAGIC, data)
            for m in matches:
                cg = m.span()[0] - 4
                self.cg_locs.append(cg)
        return self.cg_locs

    def print_superblock(self):
        tmp = OrderedDict()
        for key, value in self.sb.items():
            if key in ['fs_maxfilesize', 'fs_metackhash', 'fs_ckhash', 'fs_avgfpdir', 'fs_avgfilesize', 'fs_snapinum',
                       'fs_pendinginodes', '*fs_active', 'fs_swuid', 'fs_ipg', 'fs_inopb', 'fs_ncg']:
                tmp[key] = hex(get_int(value, signed=False))
            else:
                tmp[key] = hex(get_int(value))
        pp.pprint(tmp)

    def print_cylinder_group(self):
        tmp = OrderedDict()
        for key, value in self.cg.items():
            if key in ['cg_firstfield', 'cg_magic', 'cg_old_time', 'cg_old_ncyl', 'cg_old_niblk', 'cg_old_btotoff',
                       'cg_old_boff', 'cg_sparecon32', 'cg_time', 'cg_sparecon64', 'cg_cs__cs_ndir', 'cg_cs__cs_nbfree',
                       'cg_cs__cs_nifree', 'cg_cs__cs_nffree']:
                tmp[key] = hex(get_int(value, signed=True))
            else:
                tmp[key] = hex(get_int(value))
        pp.pprint(tmp)

    def dump_superblock(self, n=0):
        if not self.sb_locs:
            self.find_all_superblocks()
        self._read_superblock_in_dict(loc=self.sb_locs[n])
        p = str(pathlib.Path(self.fs).parent)
        c = str(pathlib.Path(self.fs).name)
        fp = os.path.join(p, f'superblock_{hex(n)}_' + c + '.dump')
        with open(fp, 'wb') as f:
            for _, value in self.sb.items():
                f.write(value)
        print(f'[+] Dumped {fp}')

    def dump_all_superblocks(self):
        self.find_all_superblocks()
        for i, _ in enumerate(self.sb_locs):
            self.dump_superblock(n=i)


# The UFS2 superblock is located at the beginning of the disk slice, and is replicated in each cylinder group.

def main():
    parser = argparse.ArgumentParser(description='UFS file system parser')
    parser.add_argument('--dump', '-d', action='store_true', default=False,
                        dest='dump', help='Dumps the first superblock to disk')
    parser.add_argument('--dump_all', '-da', action='store_true', default=False,
                        dest='dump_all', help='Dumps all superblocks to disk')
    parser.add_argument('--print_superblock', '-ps', type=int, default=-1, dest='print_sb',
                        help='Print the n-th superblock to stdout. Default: %(default)s')
    parser.add_argument('--print_cylinder_groups', '-pcg', type=int,
                        help='Print the n-th cylinder group to stdout. Default: %(default)s',
                        default=-1, dest='print_cg')
    parser.add_argument('--find_all', '-fa', action='store_true', default=False, dest='find_all',
                        help='Finds all superblock locations and prints them to stdout. Default: %(default)s')
    parser.add_argument('--file_system', '-f', required=True, type=pathlib.Path, help='UFS Filesystem')
    parser.add_argument('--file_system_type', '-ft', type=str, default='ufs2', dest='fst',
                        help='[ufs1, ufs2]. Default: %(default)s')

    args = parser.parse_args()

    ufs = UFS(args.file_system, args.fst)
    if args.dump:
        ufs.dump_superblock()
    if args.dump_all:
        ufs.dump_all_superblocks()
    if args.find_all:
        ufs.find_all_superblocks()
        ufs.find_all_cylinder_groups()
        res = ', '.join(hex(e) for e in ufs.sb_locs)
        print(f'[+] Found superblock offsets: {res}')
        res = ', '.join(hex(e) for e in ufs.cg_locs)
        print(f'[+] Found cylinder group offsets: {res}')
    if args.print_sb >= 0:
        ufs.find_all_superblocks()
        if not ufs.sb_locs and args.fst == 'ufs2':
            ufs.sb_locs.append(SBLOCK_UFS2)
        elif not ufs.sb_locs and args.fst == 'ufs1':
            ufs.sb_locs.append(SBLOCK_UFS1)
        ufs._read_superblock_in_dict(ufs.sb_locs[args.print_sb])
        ufs.print_superblock()
    if args.print_cg >= 0:
        ufs.find_all_cylinder_groups()
        ufs._read_cylinder_group_in_dict(ufs.cg_locs[args.print_cg])
        ufs.print_cylinder_group()


if __name__ == '__main__':
    main()
