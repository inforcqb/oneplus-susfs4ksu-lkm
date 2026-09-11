#!/system/bin/sh
# Bisect the inline hooks: install one entry at a time, hold for 10 s, then rmmod.
# An entry that wedges the box has to be found by rebooting, but every good one
# cleans itself up, so the sweep only costs reboots for the broken ones.
exec > /data/local/tmp/ihbisect_out.txt 2>&1

K=/data/local/tmp/susfs.ko
D=/data/local/tmp/dac_probe
T=$D/f600
KT=/data/adb/ksu/bin/ksu_susfs

rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T

for n in 1 2 3 4 5 6 7 8; do
	rmmod susfs_guard_lkm 2>/dev/null
	echo "=== ih_only=$n ==="

	ksud insmod $K ih_only=$n
	echo "insmod rc=$?"
	sleep 2
	dmesg | tail -12 | grep -a "susfs_ih: trying" | tail -1

	# liveness + correctness probes while the entry is patched
	echo "alive $(date +%s)"
	echo "ptmx: $(su 10123 -c 'exec 3<>/dev/ptmx && echo ok || echo FAILED' 2>&1)"
	$KT add_sus_path $T >/dev/null 2>&1
	echo "hidden(app): $(su 10123 -c "cat $T" 2>&1)"
	echo "root       : $(cat $T 2>&1)"
	echo "other(app) : $(su 10123 -c 'ls /system/bin | head -1' 2>&1)"

	echo "holding 10s..."
	sleep 10
	echo "alive after hold $(date +%s)"

	rmmod susfs_guard_lkm
	echo "rmmod rc=$?"
	echo
done

echo "### sweep finished - no entry wedged the device"
