#!/usr/bin/env python3

import argparse
import pathlib
import secrets
import subprocess
import sys
from ctypes import sizeof

from ext_superblock_parser import EXT
from fs_util import get_magic_offsets, restore_magic_bytes, UFS_SB, EXT_SB, UFS_CG, SBLOCK_EXT2, MAGIC_BYTES_OFF
from ufs_superblock_parser import UFS


class Mutator:

    def __init__(self, fs, fst, mutation, out, radamsa=False, restore=False, deter=False, target=None):
        if target is None:
            target = []
        self.fs = fs
        self.fs_obj = fst
        # self.mutation = mutation
        if mutation:
            self.mutation_section = mutation[0]
            self.mutation_size = mutation[1]
            self.mutation_value = mutation[2]
            self.mutation_pos = mutation[3]
        self.outfile = out
        # self.mutation_type = mtype
        self.restore = restore
        self.determinism = deter
        self.radamsa = radamsa
        self.radamsa_seed = None
        self.target = target

    @staticmethod
    def _make_zero(size):
        return b'\x00' * size

    @staticmethod
    def _make_ff(size):
        return b'\xFF' * size

    @staticmethod
    def _rnd(size):
        return secrets.token_bytes(size)

    def _rnd_radamsa(self):
        if self.determinism:
            self.radamsa_seed = secrets.randbits(100)
            print(f'[+] Used radamsa seed: {self.radamsa_seed}.')
            cmd = f'radamsa {self.fs} -s {self.radamsa_seed} > {self.outfile}'
        else:
            cmd = f'radamsa {self.fs} > {self.outfile}'
        subprocess.check_output(cmd, shell=True)

    @staticmethod
    def _get_offset_in_sb(fn, mime='ufs'):
        off = 0
        for i, v in UFS_SB if mime == 'ufs' else EXT_SB:
            if i == fn:
                return off, sizeof(v)
            off += sizeof(v)
        return None, None

    @staticmethod
    def _get_offset_in_ufs_cg(fn):
        off = 0
        for i, v in UFS_CG:
            if i == fn:
                return off, sizeof(v)
            off += sizeof(v)
        return None, None

    def targeted_mutation(self):
        with open(self.fs, 'rb') as f:
            data = bytearray(f.read())
        if self.target[0].lower() == 'sb':
            block_offs = self.fs_obj.find_all_superblocks()
        elif self.target[0].lower() == 'cg':
            block_offs = self.fs_obj.find_all_cylinder_groups()
        else:
            print('[!] Unknown target.')
            sys.exit(-1)

        if self.target[1] != 'all':
            block_offs = [block_offs[int(self.target[1])]]

        if self.target[0].lower() == 'sb':
            offs, size = self._get_offset_in_sb(self.target[2])
        else:
            offs, size = self._get_offset_in_ufs_cg(self.target[2])
        if offs:
            inj = self.target[3][:size].encode()
            for b in block_offs:
                data[b + offs: b + offs + len(inj)] = inj
            self._write_outfile(data)
        else:
            print(f'[!] Could not determine offset for: {self.target[2]} in {self.target[0]}!')
            sys.exit(-1)

    def _write_outfile(self, data):
        with open(self.outfile, 'wb') as g:
            g.write(data)

    def _get_data_pos(self, non_data, border, r=0):
        pos = secrets.randbelow(border + 1)
        if pos in non_data or pos + r in non_data:
            self._get_data_pos(non_data, border, r)
        else:
            return pos

    def _get_meta_pos(self, mlen, r):
        pos = secrets.randbelow(mlen + 1)
        if pos < mlen and pos + r < mlen:
            return pos
        else:
            self._get_meta_pos(mlen, r)

    def _get_meta_offs(self, cgs, sbs):
        forbidden = []
        for sb in sbs:
            for i in range(self.fs_obj.sb_expected_len + 1):
                forbidden.append(sb + i)
        if cgs:
            for cg in cgs:
                for i in range(self.fs_obj.cg_expected_len + 1):
                    forbidden.append(cg + i)
        return forbidden

    def _get_size(self):
        if self.mutation_size == 'byte_flip':
            return 1
        elif self.mutation_size == 'block':
            if self.mutation_section == 'sb':
                return self.fs_obj.sb_expected_len
            elif self.mutation_section == 'cg':
                return self.fs_obj.cg_expected_len
            else:
                return 64

    def _apply_mutation(self, btype=None, fields=None):
        fake_block = b''
        msize = self._get_size()
        if self.mutation_value == 'zero':
            fake_block = self._make_zero(msize)
        elif self.mutation_value == 'ff':
            fake_block = self._make_ff(msize)
        elif self.mutation_value == 'rnd':
            fake_block = self._rnd(msize)

        with open(self.fs, 'rb') as f:
            data = bytearray(f.read())
            dlen = len(data)

        if btype in ['sb', 'cg']:
            pos = 0
            if btype == 'sb' and self.mutation_size == 'byte_flip':
                pos = self._get_meta_pos(self.fs_obj.sb_expected_len, msize)
            elif btype == 'cg' and self.mutation_size == 'byte_flip':
                pos = self._get_meta_pos(self.fs_obj.cg_expected_len, msize)

            if self.mutation_pos == 'all':
                for e in fields:
                    data[e + pos: e + pos + len(fake_block)] = fake_block
                    print(f'[*] Modified offset {hex(e + pos)} with {fake_block} of length {len(fake_block)}.')
            else:
                mpos = int(self.mutation_pos)
                data[fields[mpos] + pos: fields[mpos] + pos + len(fake_block)] = fake_block
                print(f'[*] Modified offset {hex(fields[mpos] + pos)} with {fake_block} of length {len(fake_block)}.')

        else:
            forbidden = self._get_meta_offs(self.fs_obj.cg_locs, self.fs_obj.sb_locs)
            pos = self._get_data_pos(forbidden, dlen, msize)
            data[pos: pos + len(fake_block)] = fake_block
            print(f'[*] Modified offset {hex(pos)} with {fake_block} of length {len(fake_block)}.')

        self._write_outfile(data)
        if self.restore:
            self._restore_magic_bytes()

    def _restore_magic_bytes(self):
        if 'ufs' in self.fs_obj.fst:
            moff = get_magic_offsets(self.fs, 'ufs')
            restore_magic_bytes(moff, self.outfile, 'ufs')
        else:
            restore_magic_bytes([SBLOCK_EXT2 + MAGIC_BYTES_OFF], self.outfile, 'ext')

    def mutate(self):
        try:
            if self.target:
                self.targeted_mutation()
            elif self.radamsa:
                self._rnd_radamsa()

            else:
                if self.mutation_section == 'sb':
                    offs = self.fs_obj.find_all_superblocks()
                    self._apply_mutation(btype='sb', fields=offs)
                elif self.mutation_section == 'cg':
                    offs = self.fs_obj.find_all_cylinder_groups()
                    self._apply_mutation(btype='cg', fields=offs)
                else:
                    self.fs_obj.find_all_superblocks()
                    self.fs_obj.find_all_cylinder_groups()
                    self._apply_mutation(btype='data')
            print(f'[+] Writing result to \'{self.outfile}\'.')
        except:
            print(f'[!] Failed to mutate')
        finally:
            if self.restore:
                self._restore_magic_bytes()


def get_bool(i):
    if i:
        return True
    else:
        return False


def main():
    parser = argparse.ArgumentParser(description='Simple file system mutator')
    parser.add_argument('--file_system', '-f', required=True, type=pathlib.Path, help='UFS Filesystem')
    parser.add_argument('--file_system_type', '-ft', type=str, default='ufs', dest='fst',
                        help='[ufs, ext]. Default: %(default)s')
    parser.add_argument('--out', '-o', required=True, type=pathlib.Path, help='Filename for new sample')
    parser.add_argument('--prototype', '-p', nargs=4, default=None,
                        help='msection: [sb, cg, data],'
                             'msize: [byte_flip, block],'
                             'mvalue: [zero, ff, rnd],'
                             'mpos: [n-th- sb,cg, all]')
    parser.add_argument('--radamsa', '-rd', action='store_true', help='Use radamsa for full binary mutation')

    parser.add_argument('--restore', '-r', action='store_true', help='Restore magic bytes in super block(s)')
    parser.add_argument('--determinism', '-d', action='store_true', help='Set and save seed for radamsa mutation')
    parser.add_argument('--targeted_mutation', '-t', nargs=4, default=None,
                        # ['sb', 'all', 'fs_fsmnt',  'Hello World @ HITB 2020 AMS Lockdown Con :)!']
                        type=str, dest='target',
                        help='Specify <sb/cg> n-th/all <sb/cg> a <field> and the <injected value>. Default: %(default)s')

    args = parser.parse_args()
    if sum([get_bool(args.prototype), get_bool(args.target), args.radamsa]) > 1:
        parser.error('Only specify one of the flags: radamsa, targeted, or mutation')
    if args.determinism and not args.radamsa:
        parser.error('Determinism flag requires radamsa flag to be set')
    if args.fst == 'ufs':
        fst = UFS(fs=args.file_system, fst='ufs2')
    else:
        fst = EXT(fs=args.file_system)

    Mutator(fs=args.file_system, fst=fst, mutation=args.prototype, out=args.out, radamsa=args.radamsa,
            restore=args.restore, deter=args.determinism, target=args.target).mutate()


if __name__ == '__main__':
    main()
