import re
import sys
from ctypes import *
from datetime import datetime


def get_int(n, signed=False):
    return int.from_bytes(n, byteorder='little', signed=signed)


def get_time(n):
    return datetime.fromtimestamp(n).strftime('%c')


def get_hstr(hex_str, inv=False):
    if len(hex_str[2:]) % 16 != 0:
        hex_str = '0' + hex_str[2:]
    else:
        hex_str = hex_str[2:]
    if inv:
        return bytes.fromhex(hex_str[::-1]).decode('ASCII')
    else:
        return bytes.fromhex(hex_str).decode('ASCII')


def get_magic_offsets(path_to_file_system, file_system_type=None):
    with open(path_to_file_system, 'rb') as f:
        data = f.read()
        magic_positions = []
        if file_system_type is 'ufs':
            magic_sequence = UFS_MAGIC
        elif file_system_type is 'zfs':
            magic_sequence = ZFS_MAGIC
        else:
            return False
        matches = re.finditer(magic_sequence, data)
        for m in matches:
            magic_positions.append(m.span()[0])
        return magic_positions


def restore_magic_bytes(magic_offsets, fs, mime=None):
    if mime == 'ext':
        magic_sequence = EXT_MAGIC
    elif mime == 'ufs':
        magic_sequence = UFS_MAGIC
    elif mime == 'zfs':
        magic_sequence = ZFS_MAGIC
    else:
        print('[!] Unknown mime type')
        sys.exit(1)
    with open(fs, 'rb+') as f:
        for m in magic_offsets:
            f.seek(m)
            f.write(magic_sequence)


def save_sb(fs, mime=None):
    if mime == 'ufs':
        off = SBLOCK_UFS2
    elif mime == 'ext':
        off = E
    elif mime == 'zfs':
        pass
    else:
        print('[!] Unknown mime type')
        sys.exit(1)


def restore_sb(self):
    if self.mime == 'ufs':
        superblock = ufs_superblock_parser.get_raw_superblock(self.path_to_file_system)
        offset = ufs_superblock_parser.UFS_SUPERBLOCK['magic']['offset']
    elif self.mime == 'ext':
        superblock = 0
        offset = 0
        pass
    elif self.mime == 'zfs':
        superblock = 0
        offset = 0
        pass
    else:
        logging.error('Could not detect file system type correctly')
        return 0
    with open(self.path_to_mutated_file_system, 'wb') as f:
        f.read(offset)
        f.write(superblock)
        f.close()

# xxd EXT_FS | 'ef53'
# at offset 1080
EXT_MAGIC = b'\x53\xef'

# xxd UFS_FS | grep '1954 0119'
# multiple offsets
UFS_MAGIC = b'\x19\x01\x54\x19'
CG_MAGIC = b'\x55\x02\x09'

# xxd ZFS_FS | grep '0cb1 ba00'
# multiple offsets
ZFS_MAGIC = b'\x0c\xb1\xba\x00\x00\x00\x00\x00'

SBLOCK_PIGGY = 262144
SBLOCKSIZE = 8192
MAXMNTLEN = 468
MAXVOLLEN = 32
FSMAXSNAP = 20
NOCSPTRS = int(128 / (sizeof(c_void_p)) - 4)
MAXFRAG = 8
SBLOCK_UFS1 = 8192
SBLOCK_UFS2 = 65536

ufs_time_t = c_int64
ufs2_daddr_t = c_int64

UFS_SB = [
    ('fs_firstfield', c_int32),
    ('fs_unused_1', c_int32),
    ('fs_sblkno', c_int32),
    ('fs_cblkno', c_int32),
    ('fs_iblkno', c_int32),
    ('fs_dblkno', c_int32),
    ('fs_old_cgoffset', c_int32),
    ('fs_old_cgmask', c_int32),
    ('fs_old_time', c_int32),
    ('fs_old_size', c_int32),
    ('fs_old_dsize', c_int32),
    ('fs_ncg', c_uint32),
    ('fs_bsize', c_int32),
    ('fs_fsize', c_int32),
    ('fs_frag', c_int32),
    ('fs_minfree', c_int32),
    ('fs_old_rotdelay', c_int32),
    ('fs_old_rps', c_int32),
    ('fs_bmask', c_int32),
    ('fs_fmask', c_int32),
    ('fs_bshift', c_int32),
    ('fs_fshift', c_int32),
    ('fs_maxcontig', c_int32),
    ('fs_maxbpg', c_int32),
    ('fs_fragshift', c_int32),
    ('fs_fsbtodb', c_int32),
    ('fs_sbsize', c_int32),
    ('fs_spare1', c_int32 * 2),  # arr[2]
    ('fs_nindir', c_int32),
    ('fs_inopb', c_uint32),
    ('fs_old_nspf', c_int32),
    ('fs_optim', c_int32),
    ('fs_old_npsect', c_int32),
    ('fs_old_interleave', c_int32),
    ('fs_old_trackskew', c_int32),
    ('fs_id', c_int32 * 2),  # arr[2]
    ('fs_old_csaddr', c_int32),
    ('fs_cssize', c_int32),
    ('fs_cgsize', c_int32),
    ('fs_spare2', c_int32),
    ('fs_old_nsect', c_int32),
    ('fs_old_spc', c_int32),
    ('fs_old_ncyl', c_int32),
    ('fs_old_cpg', c_int32),
    ('fs_ipg', c_uint32),
    ('fs_fpg', c_int32),
    ('fs_old_cstotal__cs_ndir', c_int32),
    ('fs_old_cstotal__cs_nbfree', c_int32),
    ('fs_old_cstotal__cs_nifree', c_int32),
    ('fs_old_cstotal__cs_nffree', c_int32),
    # ('fs_old_cstotal', c_int32 * 4),  # struct csum
    ('fs_fmod', c_int8),
    ('fs_clean', c_int8),
    ('fs_ronly', c_int8),
    ('fs_old_flags', c_int8),
    ('fs_fsmnt', c_char * MAXMNTLEN),
    ('fs_volname', c_char * MAXVOLLEN),
    ('fs_swuid', c_uint64),
    ('fs_pad', c_int32),
    ('fs_cgrotor', c_int32),
    ('*fs_ocsp', c_void_p * NOCSPTRS),  # void 	*fs_ocsp[NOCSPTRS]
    ('*fs_contigdirs', c_size_t),  # *fs_contigdirs
    ('*fs_csp', c_size_t),  # struct csum *fs_csp
    ('*fs_maxcluster', c_size_t),
    ('*fs_active', c_uint64),
    ('fs_old_cpc', c_int32),
    ('fs_maxbsize', c_int32),
    ('fs_unrefs', c_int64),
    ('fs_providersize', c_int64),
    ('fs_metaspace', c_int64),
    ('fs_sparecon64', c_int64 * 13),  # arr[13]
    ('fs_sblockactualloc', c_int64),
    ('fs_sblockloc', c_int64),
    ('fs_cstotal__cs_ndir', c_int64),
    ('fs_cstotal__cs_nbfree', c_int64),
    ('fs_cstotal__cs_nifree', c_int64),
    ('fs_cstotal__cs_nffree', c_int64),
    ('fs_cstotal__cs_numclusters', c_int64),
    ('fs_cstotal__cs_spare', c_int64 * 3),
    # ('fs_cstotal', c_size_t * 8),  # struct csum_total
    ('fs_time', ufs_time_t),
    ('fs_size', c_int64),
    ('fs_dsize', c_int64),
    ('fs_csaddr', ufs2_daddr_t),
    ('fs_pendingblocks', c_int64),
    ('fs_pendinginodes', c_uint32),
    ('fs_snapinum', c_uint32 * FSMAXSNAP),
    ('fs_avgfilesize', c_uint32),
    ('fs_avgfpdir', c_uint32),
    ('fs_save_cgsize', c_int32),
    ('fs_mtime', ufs_time_t),
    ('fs_sujfree', c_int32),
    ('fs_sparecon32', c_int32 * 21),  # arr[21]
    ('fs_ckhash', c_uint32),
    ('fs_metackhash', c_uint32),
    ('fs_flags', c_int32),
    ('fs_contigsumsize', c_int32),
    ('fs_maxsymlinklen', c_int32),
    ('fs_old_inodefmt', c_int32),
    ('fs_maxfilesize', c_uint64),
    ('fs_qbmask', c_int64),
    ('fs_qfmask', c_int64),
    ('fs_state', c_int32),
    ('fs_old_postblformat', c_int32),
    ('fs_old_nrpos', c_int32),
    ('fs_spare5', c_int32 * 2),  # arr[2]
    ('fs_magic', c_int32)]

UFS_CG = [
    ('cg_firstfield', c_int32),
    ('cg_magic', c_int32),
    ('cg_old_time', c_int32),
    ('cg_cgx', c_uint32),
    ('cg_old_nyl', c_int16),
    ('cg_old_niblk', c_int16),
    ('cg_ndblk', c_uint32),
    ('cg_cs__cs_ndir', c_int32),
    ('cg_cs__cs_nbfree', c_int32),
    ('cg_cs__cs_nifree', c_int32),
    ('cg_cs__cs_nffree', c_int32),
    ('cg_rotor', c_uint32),
    ('cg_frotor', c_uint32),
    ('cg_irotor', c_uint32),
    ('cg_frsum', c_uint32 * MAXFRAG),  # arr[MAXFRAG]
    ('cg_old_btotoff', c_int32),
    ('cg_old_boff', c_int32),
    ('cg_iusedoff', c_uint32),
    ('cg_freeoff', c_uint32),
    ('cg_nextfreeoff', c_uint32),
    ('cg_clustersumoff', c_uint32),
    ('cg_clusteroff', c_uint32),
    ('cg_nclusterblks', c_uint32),
    ('cg_niblk', c_uint32),
    ('cg_initediblk', c_uint32),
    ('cg_unrefs', c_uint32),
    ('cg_sparecon32', c_int32),
    ('cg_ckhash', c_uint32),
    ('cg_time', ufs_time_t),
    ('cg_sparecon64', c_uint64 * 3),  # arr[3]
    ('cg_space', c_uint8)]

SBLOCK_EXT2 = 1024  # First 1024 bytes are unused, block group 0 starts with a superblock @ offset 1024d
MAGIC_BYTES_OFF = 56

EXT_SB = [
    ('e2fs_icount', c_uint32),
    ('e2fs_bcount', c_uint32),
    ('e2fs_rbcount', c_uint32),
    ('e2fs_fbcount', c_uint32),
    ('e2fs_ficount', c_uint32),
    ('e2fs_first_dblock', c_uint32),
    ('e2fs_log_bsize', c_uint32),
    ('e2fs_log_fsize', c_uint32),
    ('e2fs_bpg', c_uint32),
    ('e2fs_fpg', c_uint32),
    ('e2fs_ipg', c_uint32),
    ('e2fs_mtime', c_uint32),
    ('e2fs_wtime', c_uint32),
    ('e2fs_mnt_count', c_uint16),
    ('e2fs_max_mnt_count', c_uint16),
    ('e2fs_magic', c_uint16),
    ('e2fs_state', c_uint16),
    ('e2fs_beh', c_uint16),
    ('e2fs_minrev', c_uint16),
    ('e2fs_lastfsck', c_uint32),
    ('e2fs_fsckintv', c_uint32),
    ('e2fs_creator', c_uint32),
    ('e2fs_rev', c_uint32),
    ('e2fs_ruid', c_uint16),
    ('e2fs_rgid', c_uint16),
    ('e2fs_first_ino', c_uint32),
    ('e2fs_inode_size', c_uint16),
    ('e2fs_block_group_nr', c_uint16),
    ('e2fs_features_compat', c_uint32),
    ('e2fs_features_incompat', c_uint32),
    ('e2fs_features_rocompat', c_uint32),
    ('e2fs_uuid', c_uint8 * 16),  # arr[16], at offset 104
    ('e2fs_vname', c_char * 16),  # arr[16]
    ('e2fs_fsmnt', c_char * 64),  # arr[64]
    ('e2fs_algo', c_uint32),
    ('e2fs_prealloc', c_uint8),
    ('e2fs_dir_prealloc', c_uint8),
    ('e2fs_reserved_ngdb', c_uint16),
    ('e3fs_journal_uuid', c_char * 16),  # arr[16]
    ('e3fs_journal_inum', c_uint32),
    ('e3fs_journal_dev', c_uint32),
    ('e3fs_last_orphan', c_uint32),
    ('e3fs_hash_seed', c_uint32 * 4),  # arr[4]
    ('e3fs_def_hash_version', c_char),
    ('e3fs_jnl_backup_type', c_char),
    ('e3fs_desc_size', c_uint16),
    ('e3fs_default_mount_opts', c_uint32),
    ('e3fs_first_meta_bg', c_uint32),
    ('e3fs_mkfs_time', c_uint32),
    ('e3fs_jnl_blks', c_uint32),
    ('e4fs_bcount_hi', c_uint32),
    ('e4fs_rbcount_hi', c_uint32),
    ('e4fs_fbcount_hi', c_uint32),
    ('e4fs_min_extra_isize', c_uint16),
    ('e4fs_want_extra_isize', c_uint16),
    ('e4fs_flags', c_uint32),
    ('e4fs_raid_stride', c_uint16),
    ('e4fs_mmpintv', c_uint16),
    ('e4fs_mmpblk', c_uint64),
    ('e4fs_raid_stripe_wid', c_uint32),
    ('e4fs_log_gpf', c_uint8),
    ('e4fs_chksum_type', c_uint8),
    ('e4fs_encrypt', c_uint8),
    ('e4fs_reserved_pad', c_uint8),
    ('e4fs_kbytes_written', c_uint64),
    ('e4fs_snapinum', c_uint32),
    ('e4fs_snapid', c_uint32),
    ('e4fs_snaprbcount', c_uint64),
    ('e4fs_snaplist', c_uint32),
    ('e4fs_errcount', c_uint32),
    ('e4fs_first_errtime', c_uint32),
    ('e4fs_first_errino', c_uint32),
    ('e4fs_first_errblk', c_uint64),
    ('e4fs_first_errfunc', c_uint8 * 32),  # arr[32]
    ('e4fs_first_errline', c_uint32),
    ('e4fs_last_errtime', c_uint32),
    ('e4fs_last_errino', c_uint32),
    ('e4fs_last_errline', c_uint32),
    ('e4fs_last_errblk', c_uint64),
    ('e4fs_last_errfunc', c_uint8 * 32),  # arr[32]
    ('e4fs_mount_opts', c_uint8 * 64),  # arr[64]
    ('e4fs_usrquota_inum', c_uint32),
    ('e4fs_grpquota_inum', c_uint32),
    ('e4fs_overhead_clusters', c_uint32),
    ('e4fs_backup_bgs', c_uint32 * 2),  # arr[2]
    ('e4fs_encrypt_algos', c_uint8 * 4),  # arr[4]
    ('e4fs_encrypt_pw_salt', c_uint8 * 16),  # arr[16]
    ('e4fs_lpf_ino', c_uint32),
    ('e4fs_proj_quota_inum', c_uint32),
    ('e4fs_chksum_seed', c_uint32),
    ('e4fs_reserved', c_uint32 * 98),  # arr[98]
    ('e4fs_sbchksum', c_uint32)]
