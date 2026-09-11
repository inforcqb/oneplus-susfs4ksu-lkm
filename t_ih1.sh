#!/system/bin/sh
# Single-entry bisect: install ONLY entry $1, arm it with a rule, watch, and let
# the kernel-side timer restore it.
exec > /data/local/tmp/ih1_out.txt 2>&1

K=/data/local/tmp/susfs.ko
D=/data/local/tmp/dac_probe
T=$D/f600
KT=/data/adb/ksu/bin/ksu_susfs
N=$1

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T

echo "### entry #$N"
ksud insmod $K ih_only=$N ih_secs=20
echo "insmod rc=$?"

echo "--- arming with a rule (this is what installs the hook) ---"
$KT add_sus_path $T
echo "add rc=$?"
dmesg | tail -25 | grep -a -e "susfs_ih: trying" -e "inline hooks armed" | tail -2

sleep 2
echo "app  cat (expect ENOENT if this is a syscall entry): $(su 10123 -c "cat $T" 2>&1)"
echo "root cat (expect secret): $(cat $T 2>&1)"
echo "ptmx: $(su 10123 -c 'exec 3<>/dev/ptmx && echo ok || echo FAILED' 2>&1)"
echo "other(app): $(su 10123 -c 'ls /system/bin | head -1' 2>&1)"

echo "--- holding 5s with the hook armed ---"
sleep 5
echo "still alive"

echo "--- waiting for the kernel-side restore (ih_secs=20) ---"
sleep 15
dmesg | tail -10 | grep -a -e "elapsed" -e "restored" | tail -2

rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "### done"
