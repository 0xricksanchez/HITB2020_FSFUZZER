#!/bin/bash

until nc -vzw 2 $(sudo virsh domifaddr $1 | tail -n 2 | cut -d" " -f21 | cut -d"/" -f1 | xargs) 22 2>/dev/null; do
	sleep 0.5
done
