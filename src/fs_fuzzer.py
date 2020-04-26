#!/usr/bin/env python3

import argparse
import getpass
import logging
import os
import pathlib
import re
import socket
import sys

import colorama as clr
import paramiko as pm


class Fuzzer:

    def __init__(self, host, fn, ft, mntpt, user_sim, port=22):
        self.host = host
        self.port = port
        self.lfile = fn[0]
        self.rfile = fn[1]
        self.fs_type = ft
        self.rshell = None
        self.vm_user = self.vm_password = 'root'
        self.mount_at = mntpt
        self.user_sim = user_sim

    def __exit__(self):
        return 1

    def _get_basic_ssh_conn(self):
        self.get_vm_credentials()
        ssh_conn = pm.SSHClient()
        ssh_conn.set_missing_host_key_policy(pm.AutoAddPolicy())
        ssh_conn.connect(hostname=self.host, port=self.port, username=self.vm_user,
                         password=self.vm_password, look_for_keys=False, allow_agent=False,
                         timeout=15)
        return ssh_conn

    def get_vm_credentials(self):
        if self.vm_user is None or self.vm_password is None:
            self.vm_user = str(input('Username for "{}": '.format(self.host)))
            self.vm_password = getpass.getpass("Password: ")
        else:
            logging.debug('Reusing stored vm credentials.')

    def invoke_remote_ssh_shell(self):
        ssh_conn = self._get_basic_ssh_conn()
        ssh_conn.get_transport().set_keepalive(200)
        ssh_conn.get_transport().open_session()
        ssh_conn.invoke_shell()
        self.rshell = ssh_conn
        return ssh_conn

    def _exec(self, cmd, to=3):
        if not self.rshell:
            logging.debug(f'new rshell for ... {cmd}')
            self.invoke_remote_ssh_shell()
        try:
            # get_pty=True combines stdout/stderr
            _, stdout, _ = self.rshell.exec_command(cmd, get_pty=True, timeout=to)
            stdout_decoded = stdout.read().decode().strip()
            if stdout_decoded != '':
                return stdout_decoded
            else:
                return None
        except (pm.ssh_exception.SSHException, socket.timeout,
                pm.ssh_exception.NoValidConnectionsError) as e:
            logging.debug('_EXEC ERROR: {}'.format(e))
            return 2
        except UnicodeDecodeError:
            return 1

    def mkdir(self, rpath):
        return self.exec_get_return_code(f'/bin/mkdir -p {rpath}; echo $?')

    def rm_files(self, rpath):
        return self.exec_get_return_code(f'/bin/rm -rf {rpath}; echo $?')

    def vm_ls(self, rpath):
        return self._exec(f'/bin/ls -lah {rpath}')

    def exec_cmd_quiet(self, cmd):
        stdout = self._exec(cmd)
        return stdout

    def exec_cmd(self, cmd):
        stdout = self._exec(cmd)
        print('{}'.format(stdout))
        return stdout

    def exec_get_return_code(self, cmd):
        res = str(self.exec_cmd_quiet(cmd))
        if int(res[-1]) != 0:
            return False
        else:
            return True

    def interactive_shell(self):
        print(clr.Fore.RED + 'Exit remote shell via "bye"' + clr.Fore.RESET)
        while True:
            command = input('$> ')
            if command.strip().lower() == 'bye':
                sys.exit(0)
            else:
                self.exec_cmd(command)

    def cp_to_local(self, rp, lp):
        ftpc = self.rshell.open_sftp()
        ftpc.get(rp, lp)
        ftpc.close()

    def cp_to_remote(self, lp, rp):
        ftpc = self.rshell.open_sftp()
        ftpc.put(lp, rp)
        ftpc.close()

    def _mk_blk_dev(self):
        logging.debug('CREATING BLKDEV FOR: {}'.format(self.rfile))
        cmd = '/sbin/mdconfig -a -t vnode -f {}'.format(self.rfile)
        print(cmd)
        self.block_device = os.path.join('/dev', self.exec_cmd_quiet(cmd))

    def _mount(self):
        self._clean_mount_dir()
        self._determine_fs_type()
        self._mk_blk_dev()
        self._mount_ext_ufs()

    def _determine_fs_type(self):
        file_output = self.exec_cmd_quiet('/usr/bin/file {}'.format(self.rfile))
        match = re.search(r'ext[1-4] filesystem data', file_output)
        if match:
            self.fs_type = match.group(0).split()[0]
        elif 'Unix Fast File system' in file_output:
            self.fs_type = 'ufs'
        elif 'data' in file_output:
            self.fs_type = 'zfs'

    def _clean_mount_dir(self):
        self.rm_files(self.mount_at)
        self.mkdir(self.mount_at)

    def _get_mount_switch(self):
        if any(x == self.fs_type for x in ['ext2', 'ext3', 'ext4']):
            flag = 'ext2fs'
        elif self.fs_type == 'ufs':
            flag = 'ufs'
        else:
            print('Malformed file system')
            print('Trying mount -t "auto" ...')
            flag = 'auto'
        return flag

    def _mount_ext_ufs(self):
        cmd = '/sbin/mount -t "{}" {} {}'.format(self._get_mount_switch(), self.block_device, self.mount_at)
        print(cmd)
        if not self.exec_cmd_quiet(cmd):
            return 1  # Success
        else:
            logging.debug('Mounting of {} failed'.format(self.block_device))  # Failed
            return 0

    def _umk_blk_dev(self):
        cmd = '/sbin/mdconfig -d -u {}'.format(self.block_device)
        print(cmd)
        return self.exec_cmd_quiet(cmd)

    def _umount(self):
        return self._unmount_ext_ufs()

    def _unmount_ext_ufs(self):
        cmd_mount = '/sbin/umount -f {}'.format(self.mount_at)
        print(cmd_mount)
        if not self.exec_cmd_quiet(cmd_mount) and not self._umk_blk_dev():
            return 1  # Success
        else:
            logging.debug('Failed to properly umount {}'.format(self.mount_at))
            return 0

    def _is_alive(self):
        if self._exec(f'ping -c1 {self.host}', to=1) != 2:
            return 1
        else:
            return 0

    def fuzz(self):
        if self.lfile is not '' and pathlib.Path(self.lfile).exists():
            self.cp_to_remote(self.lfile, self.rfile)
        self._mount()
        if self._is_alive():
            if self.user_sim:
                self._user_interaction()
            else:
                self._umount()
        else:
            # gotta reset vm
            print('[!] Target is dead..')

    def _user_interaction(self):
        #self._exec('find /mnt/HITB/')
        #self._exec(
        #    'mkdir -p /mnt/HITB/qNVzrx8xrw7hJ0e9sNynpSbICS5olJQmKQWNcZpX6L3foywr21FaqOWe6z6LnVxWeYUsR3PlIurBjLK5gaIoogjGoKQLNkV1e1/a/b/c')
        #self._exec('cp /bin/ls /mnt/HITB/')
        self._exec('/usr/bin/dirname /mnt/')
        self._exec('bin/rm -rf /mnt/HITB/reFEk8zIzNNNdIHqWStDP2DXU4Em4xeIbujCvW3IoqkJFMc0VtHmZWAF3pjUGHGADqSGruv')

    def poc(self, shell=False, emul=False):
        if self.lfile is not '' and pathlib.Path(self.lfile).exists():
            self.cp_to_remote(self.lfile, self.rfile)
        self._mount()
        if self._is_alive():
            if shell:
                self.interactive_shell()
            elif emul:
                self._user_interaction()
            self._umount()
        else:
            return 1


def main():
    parser = argparse.ArgumentParser(description='Fuzzer.')
    parser.add_argument('--host', '-rh', type=str, help='Remote Host', default='192.168.122.232')
    parser.add_argument('--port', '-p', type=int, help='Remote Port', default=22)
    parser.add_argument('--file', '-f', default=[], nargs=2, help='File to copy to remote. Requires lpath and rpath')
    parser.add_argument('--file_type', '-ft', type=str, help='File system type')
    parser.add_argument('--remote_mount_point', '-rmp', type=str, help='Mount point on host')
    parser.add_argument('--user_interaction', '-ui', action='store_true',
                        help='Emulate a user interaction if mount is successful')
    parser.add_argument('--copy_from', '-cf', nargs=2, help='remote -> local. Requires lpath and rpath')
    parser.add_argument('--copy_to', '-ct', nargs=2, help='local -> remote. Requires lpath and rpath')
    parser.add_argument('--poc_1', '-1', action='store_true', help='DEMO 1 - Default')
    parser.add_argument('--poc_2', '-2', action='store_true', help='DEMO 2 - SB Injection 1')
    parser.add_argument('--poc_3', '-3', action='store_true', help='DEMO 3 - SB Injection 2')
    parser.add_argument('--poc_4', '-4', action='store_true', help='DEMO 4 - rad_ufs2_15')
    parser.add_argument('--poc_5', '-5', action='store_true', help='DEMO 5 - rad_ufs2_15')

    args = parser.parse_args()

    if args.poc_1:
        fuzzer = Fuzzer(host='192.168.122.232', port=22, fn=['', '/root/poc1_ufs2'], ft='ufs', mntpt='/mnt/HITB/',
                        user_sim=None)
        fuzzer.poc(shell=True)
    if args.poc_2:
        # inject into mnt path
        fuzzer = Fuzzer(host='192.168.122.232', port=22, fn=['', '/root/poc2_ufs2'], ft='ufs', mntpt='/mnt/HITB/',
                        user_sim=None)
        fuzzer.poc(shell=True)
    if args.poc_3:
        # inject into magic bytes
        fuzzer = Fuzzer(host='192.168.122.232', port=22, fn=['', '/root/poc3_sb0_ufs2'], ft='ufs', mntpt='/mnt/HITB/',
                        user_sim=None)
        fuzzer.poc(shell=True)
    if args.poc_4:
        # radamsa mutated mount crash
        Fuzzer(host='192.168.122.232', port=22, fn=['', '/root/poc4_ufs2'], ft='ufs', mntpt='/mnt/HITB/',
               user_sim=None).fuzz()
    if args.poc_5:
        # radamsa mutated UI crash with a whole lotta weirdness
        Fuzzer(host='192.168.122.232', port=22, fn=['', '/root/poc5_ufs'], ft='ufs', mntpt='/mnt/HITB/',
               user_sim=None).poc(emul=True)

    if args.copy_from:
        pass
    if args.copy_to:
        pass
    if all([args.host, args.port, args.file, args.file_type, args.remote_mount_point]):
        Fuzzer(host=args.host, port=args.port, fn=args.file, ft=args.file_type,
               mntpt=args.remote_mount_point, user_sim=args.user_interaction).fuzz()


if __name__ == '__main__':
    main()
