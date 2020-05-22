#!/usr/bin/env python3

import argparse
import os
import pathlib
import pprint as pp
import re
import sys
from collections import OrderedDict
from ctypes import *

from fs_util import get_int, EXT_SB, EXT_MAGIC, SBLOCK_EXT2, MAGIC_BYTES_OFF


class EXT(Structure):
    def __init__(self, fs, fst):
        super(Structure).__init__()
        self.sb = OrderedDict()
        self.sb_expected_len = 960
        self.fs = fs
        self.fst = fst
        self.sb_locs = []
        self.sb_locs = []
        self._fields_sb = EXT_SB

    def _sanity_check(self):
        res_sb = 0
        for _, v in self._fields_sb:
            res_sb += sizeof(v)
        assert res_sb == self.sb_expected_len

    def read_superblock_in_dict(self, loc=SBLOCK_EXT2):
        with open(self.fs, "rb") as f:
            f.seek(loc)
            for field in self._fields_sb:
                self.sb[field[0]] = f.read(sizeof(field[1]))

    def find_all_superblocks(self):
        self.read_superblock_in_dict()
        with open(self.fs, "rb") as f:
            f.seek(0)
            data = f.read()
            # Using uuid because the EXT2 magic is too short to yield good results
            matches = re.finditer(self.sb["e2fs_uuid"], data)
            for m in matches:
                bytearr = bytearray()
                sb = m.span()[0] - 104
                bytearr.append(data[sb + MAGIC_BYTES_OFF])
                bytearr.append(data[sb + MAGIC_BYTES_OFF + 1])
                if bytearr == EXT_MAGIC:
                    self.sb_locs.append(sb)

    def find_all_cylinder_groups(self):
        self.cg_locs = []

    def print_superblock(self):
        tmp = OrderedDict()
        for key, value in self.sb.items():
            if key in ["e3fs_def_hash_version", "e3fs_jnl_backup_type", "e3fs_journal_uuid", "e2fs_fsmnt", "e2fs_vname"]:
                tmp[key] = hex(get_int(value, signed=False))
            else:
                tmp[key] = hex(get_int(value, signed=False))
        pp.pprint(tmp)

    def dump_superblock(self, n=SBLOCK_EXT2):
        self.read_superblock_in_dict(loc=n)
        p = str(pathlib.Path(self.fs).parent)
        c = str(pathlib.Path(self.fs).name)
        fp = os.path.join(p, f"superblock_{hex(n)}_" + c + ".dump")
        with open(fp, "wb") as f:
            for _, value in self.sb.items():
                f.write(value)
        print(f"[+] Dumped {fp}")

    def dump_all_superblocks(self):
        self.find_all_superblocks()
        for i in self.sb_locs:
            self.dump_superblock(n=i)


def main():
    parser = argparse.ArgumentParser(description="EXT file system parser")
    parser.add_argument(
        "--dump", "-d", action="store_true", default=False, dest="dump", help="Dumps the first superblock to disk"
    )
    parser.add_argument(
        "--dump_all", "-da", action="store_true", default=False, dest="dump_all", help="Dumps all superblocks to disk"
    )
    parser.add_argument(
        "--print_superblock",
        "-ps",
        type=int,
        default=-1,
        dest="print_sb",
        help="Print the n-th superblock to stdout. Default: %(default)s",
    )
    parser.add_argument(
        "--find_all",
        "-fa",
        action="store_true",
        default=False,
        dest="find_all",
        help="Finds all superblock locations and prints them to stdout",
    )
    parser.add_argument("--file_system", "-f", required=True, type=pathlib.Path, help="UFS Filesystem")

    args = parser.parse_args()

    ext = EXT(args.file_system, "ext")
    if args.dump:
        ext.dump_superblock()
    if args.dump_all:
        ext.dump_all_superblocks()
    if args.find_all:
        ext.find_all_superblocks()
        res = ", ".join(hex(e) for e in ext.sb_locs)
        print(f"[+] Found superblock offsets: {res}")
    if args.print_sb >= 0:
        ext.find_all_superblocks()
        ext.read_superblock_in_dict(ext.sb_locs[args.print_sb])
        ext.print_superblock()


if __name__ == "__main__":
    sys.exit(main())
