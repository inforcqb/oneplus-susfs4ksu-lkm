#!/system/bin/sh
# Interactive single-entry bisect.
#
#   sh /data/local/tmp/t_ihstep.sh [entry#]
#
# Every step prints what it did, then waits for you to type "y" + Enter, then
# dumps the kernel log SINCE THE LAST STEP (dmesg -c clears it, so nothing from
# an earlier step can mislead us).
#
# Entry numbers: 1 openat, 2 openat2, 3 newfstatat, 4 statx, 5 faccessat,
#                6 faccessat2, 7 readlinkat, 8 execve
K=/data/local/tmp/susfs.ko
D=/data/local/tmp/dac_probe
T=$D/f600
KT=/data/adb/ksu/bin/ksu_susfs
N=${1:-1}
NOE=${2:-0}

confirm() {
	printf '\n========================================\n%s\n' "$1"
	printf 'press y + Enter to run it: '
	read ans
	if [ "$ans" != "y" ]; then
		echo "stopped."
		exit 0
	fi
}

show() {
	echo "--- dmesg since last step ---"
	dmesg -c > /data/local/tmp/.d 2>/dev/null
	if [ -s /data/local/tmp/.d ]; then
		tail -40 /data/local/tmp/.d
	else
		dmesg | tail -40
	fi
	echo "--- end dmesg ---"
}

echo "entry #$N  no_extra=$NOE  (1 openat, 2 openat2, 3 newfstatat, 4 statx,"
echo "            5 faccessat, 6 faccessat2, 7 readlinkat, 8 execve)"

confirm "STEP 0 - clean slate: rmmod, recreate the test file"
rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T
ls -l $T
echo "ptmx right now: $(su 10123 -c 'exec 3<>/dev/ptmx && echo ok || echo FAILED' 2>&1)"
show

confirm "STEP 1 - insmod ih_only=$N ih_secs=20   (module only; no hook yet)"
ksud insmod $K ih_only=$N ih_secs=20 no_extra=$NOE
echo "insmod rc=$?"
lsmod | grep susfs
show

confirm "STEP 2 - add ONE rule   <<< the hook is installed at this moment"
$KT add_sus_path $T
echo "add rc=$?"
show

confirm "STEP 3 - app-side checks (ptmx is the symptom to watch for)"
echo "ptmx      : $(su 10123 -c 'exec 3<>/dev/ptmx && echo ok || echo FAILED' 2>&1)"
echo "app  cat  : $(su 10123 -c "cat $T" 2>&1)"
echo "root cat  : $(cat $T 2>&1)"
echo "app  other: $(su 10123 -c 'ls /system/bin | head -1' 2>&1)"
show

confirm "STEP 4 - hold 5 s with the hook armed, then check again"
sleep 5
echo "held 5 s without wedging"
echo "ptmx      : $(su 10123 -c 'exec 3<>/dev/ptmx && echo ok || echo FAILED' 2>&1)"
show

confirm "STEP 5 - wait out ih_secs=20 so the kernel restores the entry itself"
sleep 16
echo "ptmx after restore: $(su 10123 -c 'exec 3<>/dev/ptmx && echo ok || echo FAILED' 2>&1)"
show

confirm "STEP 6 - rmmod and confirm the device is back to normal"
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "ptmx      : $(su 10123 -c 'exec 3<>/dev/ptmx && echo ok || echo FAILED' 2>&1)"
echo "app  cat  : $(su 10123 -c "cat $T" 2>&1)   (expect Permission denied)"
show

echo
echo "### finished. change the entry number by rerunning:"
echo "###   sh /data/local/tmp/t_ihstep.sh 1   (or 2, 3, ... 8)"
