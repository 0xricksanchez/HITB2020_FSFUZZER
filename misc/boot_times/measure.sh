#!/bin/bash
set -e

measure() {
    sleep 1
    for ((i = 1; i <= $2; i++)); do
        echo -en "[+] Run $i"
        time ./timer_vm.sh $1 && sudo virsh reboot $1 2>/dev/null && sleep 1
    done
}


if [ $# -ne "3" ]; then
	echo "[!] Expected Arguments:"
	echo "  Arg 1: Name of vm"
	echo "  Arg 2: Action: start/reboot"
	echo "  Arg 3: Number of measurement runs"
else
	rv=$( virsh list | grep -c "$1" )
	if [ "$rv" -eq "1" ]; then
		case "$2" in
            start) sudo virsh $2 $1 2>/dev/null && measure $1 $3
				;;
            reboot) sudo virsh $2 $1 2>/dev/null && measure $1 $3
				;;
			*) echo -n "Bad argument: $2"
				;;
		esac
	else
		echo "VM $1 not found ..!"
		exit 1
	fi
fi
exit 0