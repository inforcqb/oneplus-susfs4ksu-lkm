#!/system/bin/sh
# Install each inline-hooked entry one at a time, with every other layer
# (LSM / DAC probes / getdents64 tracepoint) present, and check after each one
# that the box is still alive and that both the hidden path and a plain open
# still behave.
#
#   sh /data/local/tmp/t_ihAll.sh [first] [last] [no_extra]
N0=${1:-1}
N1=${2:-8}
NOE=${3:-0}
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
T=$D/f600
UP=/data/local/tmp/.up

up() { cat /proc/uptime | cut -d' ' -f1; }

for N in $(seq $N0 $N1); do
	echo
	echo "################ entry #$N  no_extra=$NOE ################"
	rmmod susfs_guard_lkm 2>/dev/null
	rm -rf $D
	mkdir -p $D
	printf 'secret\n' > $T
	chmod 755 $D
	chmod 600 $T
	up > $UP

	ksud insmod $K ih_only=$N ih_secs=12 no_extra=$NOE
	echo "insmod rc=$?  uptime $(up)"
	dmesg | grep -E 'susfs_ih|sus_path: (inline|hooks armed|hidden)' | tail -5

	$KT add_sus_path $T >/dev/null 2>&1
	echo "add rc=$?   uptime $(up)"
	dmesg | grep -E 'susfs_ih|sus_path: (inline|hooks armed|hidden)' | tail -5

	sleep 2
	echo "alive(2s): uptime $(up)  cpus=$(grep -c processor /proc/cpuinfo)"
	echo "app cat : $(su 10123 -c "cat $T" 2>&1)"
	echo "ptmx    : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
	echo "app ls  : $(su 10123 -c 'ls /system/bin >/dev/null 2>&1 && echo LS_OK || echo LS_FAIL' 2>&1)"
	echo "root cat: $(cat $T 2>&1)"

	sleep 11
	echo "alive(13s): uptime $(up)"
	dmesg | grep -E 'susfs_ih|no longer hooking' | tail -3
	echo "ptmx    : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"

	rmmod susfs_guard_lkm
	echo "rmmod rc=$?  uptime $(up)"
	echo "### entry #$N survived"
done

echo
echo "### all entries done"
